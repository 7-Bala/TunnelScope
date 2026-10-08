"""The traffic classifier and Random Forest ATTACKER (EXP-05, EXP-15), run live on a capture.

What it is: a model of a passive eavesdropper that guesses what kind of traffic is inside an encrypted ESP tunnel from
packet sizes, timing and direction alone. Since DEC-054 (EXP-42/43) it is EXP-42's K4: v2 features (the 31 original
window features plus 15 rhythm/shape features), trained on EIGHT families of traffic, each family's generators different:
our seeded lab generator and our real lab applications (EXP-05/15/16/17), real OpenVPN tunnels (MIT VNAT), real
L2TP-IPsec tunnels (USBVPN2022), real people's WireGuard traffic (its unlabelled-video-as-"web" class excluded), two other
teams' public IPsec labs (ipsec-pcap-lab, ashwin02 SIH_2026; their authors' permission) and our lab C (EXP-41); every family
and every class inside a family carries equal weight, and each session enters twice more with its sizes shifted and its
pace scaled. Measured on lab D (EXP-43), a lab of tools and ciphers nobody trained on: macro-F1 0.83 (0.42 for the model
it replaced), 11 of 11 gated answers right; still wrong on interactive sessions there. On a whole family held out of
training (EXP-42) it averages 0.455: traffic unlike all eight families can still be misread, which is what the abstain
rule and the out-of-distribution check are for.
EXP-45 (DEC-057) tested it on a second unseen lab, lab F: macro-F1 0.60 ungated, and 4 of its 6 gated answers right (two bulk
transfers confidently read as video). So a gated answer is usually, not always, right on traffic from tools it never saw; a nine-family
candidate did better ungated (0.72) but answered too few sessions to replace it.

What it reports for a capture (DEC-027, superseding DEC-021's "never a label"):
  - attacker_exposure: how SURE and how CONSISTENT the attacker is, 0-100;
  - traffic_type: the predicted type of traffic inside the tunnel (PS c), with
    its calibrated confidence, ONLY when the prediction clears the abstain rule
    (confident, consistent across windows, in distribution); otherwise the
    finding is UNKNOWN "uncertain" and says why. EXP-05's failure (a confident
    single label on mixed traffic) is the case the abstain rule exists for, and
    EXP-15 measures how often it catches it.

Trust limits, reported with every result:
  - the attacker learned five lab traffic types; traffic unlike anything it saw
    is flagged "outside the training data" and its confidence is not used;
  - a capture needs enough ESP traffic for at least MIN_WINDOWS full windows.

No pickled model ships (pickles are version-fragile and a code-execution risk):
the training windows ship as a plain .npz (build/models/make_traffic_data.py)
and the forest is trained on first use, then cached. The fit runs in parallel
(n_jobs=-1): measured at 0.68 s on today's ~20,000 windows, versus 5.0 s single-threaded
(EXP-20) with numerically identical predictions (same random_state; the only
difference is floating-point summation order, ~2e-16).
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from functools import lru_cache

import numpy as np

CLASSES = ["voip", "web", "bulk", "interactive", "video", "email", "messaging", "icmp"]
# PS terms for display. These are traffic SHAPES from our generator, not the apps themselves.
LABEL = {"voip": "VoIP call", "web": "Web browsing", "bulk": "File transfer", "interactive": "Interactive shell (SSH-like)",
         "video": "Video streaming", "email": "E-mail (SMTP-like)", "messaging": "Messaging (WhatsApp-like)",
         "icmp": "ICMP (ping)"}
# Measured on EXP-15's mixed sessions (results/exp15_results.json): 20 of 28 were
# named after the dominant one of their two traffic types; video+interactive was
# read as web in 8 of 8. Stated with every prediction it affects.
KNOWN_CONFUSION = {"web": "video streaming mixed with an interactive session also reads as web browsing; the "
                          "mixed-traffic check (EXP-16) catches that case, but it is the known weak spot"}
# Numbers from EXP-16 Part D (experiments/exp16-real-apps-cross-impl/RESULT.md, P16-5), the same ones
# the dashboard shows. An earlier version said "96%", which no experiment produced.
MIXED_NOTE = ("a mixed-traffic check ran first and found one kind of traffic here (in testing it caught 92.9% "
              "of mixed sessions and wrongly flagged 8.3% of single ones)")
MIXED_NOT_RUN = ("the mixed-traffic check could not run here (it needs at least three in-distribution windows), "
                 "so two kinds of traffic sharing this tunnel are not ruled out")
# abstain rule (set from EXP-15's leave-one-repetition-out analysis; see RESULT.md)
TAU = 0.60              # minimum mean top-class probability
MIN_CONSISTENCY = 0.70  # minimum share of windows agreeing with the session's top class
WIN = 2.0                  # seconds per window (EXP-05)
MIN_PKTS = 3               # a window with fewer packets carries no usable signal
SIZE_EDGES = [0, 128, 256, 512, 1024, 1600]
MIN_WINDOWS = 3            # below this, too little traffic to say anything
DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "traffic_windows_v2.npz")
# The v1 file (31 features, lab + VNAT/USBVPN/WireGuard) stays for the frozen scoreboard and earlier experiments.
DATA_V1 = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "traffic_windows.npz")

# Measured on held-out repetitions: EXP-15 (synthetic shapes) and EXP-16 (real
# lab applications + Libreswan). The last number is the one to keep in mind: a
# model trained ONLY on synthetic shapes scored 0.46 on real applications, so
# training data that looks like the target traffic is what matters, not the tuning.
# EXP-19 (DEC-036) adds real public traffic (MIT VNAT, OpenVPN tunnels recorded by others): a lab-only
# model scored 0.47 on it, the shipped lab + real model 0.74 on capture files it never saw.
# EXP-20 (DEC-037) adds real IPsec traffic (USBVPN2022) and real people's WireGuard traffic: before
# that data, the model scored 0.174 on real IPsec and answered 0% of the time (always abstained);
# with it, 0.757 macro-F1 and answers 93.6% of the time at 99.8% accuracy when it does.
REFERENCE = {"f1_unpadded": 0.995, "f1_tfc_padded": 0.958, "f1_real_apps_loro": 0.995,
             "f1_cross_implementation": 1.0, "f1_synthetic_only_on_real_apps": 0.461,
             "f1_lab_only_on_real_public": 0.472, "f1_real_public_heldout": 0.741,
             "f1_before_real_ipsec": 0.174, "f1_with_real_ipsec_and_people": 0.757,
             # DEC-054: EXP-42 (a whole family held out, mean of eight) and EXP-43 (lab D, nobody trained on it)
             "f1_unseen_family_mean": 0.455, "f1_lab_d_unseen": 0.833, "f1_lab_d_previous_model": 0.417,
             "chance": round(1 / len(CLASSES), 3)}


def window_features(pkts: list[tuple[float, str, int]], complete_only: bool = True) -> list[list[float]]:
    """(t, 'out'|'in', ip_len) packets -> one feature vector per WIN-second window.
    Identical to experiments/exp05-metadata-leakage/analyze.py so the live
    attacker sees exactly what the evaluated one saw (tests/test_attacker.py)."""
    if not pkts:
        return []
    t0 = pkts[0][0]
    last_full = int((pkts[-1][0] - t0) // WIN) - 1 if complete_only else 10**9
    buckets = defaultdict(list)
    for t, d, n in pkts:
        buckets[int((t - t0) // WIN)].append((t, d, n))
    feats = []
    for idx, w in sorted(buckets.items()):
        if len(w) < MIN_PKTS or idx > last_full:
            continue
        v: list[float] = []
        for d in ("out", "in"):
            s = np.array([n for _, dd, n in w if dd == d], float)
            ts = np.array([t for t, dd, _ in w if dd == d], float)
            iat = np.diff(ts) if len(ts) > 1 else np.array([0.0])
            hist = np.histogram(s, bins=SIZE_EDGES)[0] / max(len(s), 1) if len(s) else np.zeros(len(SIZE_EDGES) - 1)
            v += [len(s), s.sum() if len(s) else 0,
                  s.mean() if len(s) else 0, s.std() if len(s) else 0,
                  s.min() if len(s) else 0, s.max() if len(s) else 0,
                  np.log10(iat.mean() + 1e-6), np.log10(iat.std() + 1e-6), np.log10(np.median(iat) + 1e-6),
                  float((iat < 0.001).mean())]
            v += list(hist)
        v += [sum(1 for _, d, _ in w if d == "out") / len(w)]
        feats.append(v)
    return feats


V2_NEW = ["pps", "bps", "up_share", "dir_switch", "out_near_max", "in_near_max", "out_iat_cv", "in_iat_cv", "size_entropy",
          "rhythm_peak", "rhythm_lag", "fast_share", "ctx_pps", "ctx_bps", "ctx_up_share"]


def _rhythm(ts):
    if len(ts) < 4:
        return 0.0, 0.0
    c = np.bincount(((ts - ts[0]) / 0.01).astype(int), minlength=200)[:200].astype(float)
    c -= c.mean()
    den = float((c * c).sum())
    if den <= 0:
        return 0.0, 0.0
    ac = np.array([float((c[:-k] * c[k:]).sum()) / den for k in range(1, 21)])
    k = int(ac.argmax())
    return float(ac[k]), (k + 1) * 0.01


def _v2_extra(pkts):
    """The 15 rhythm/shape columns of EXP-42's v2 (build/models/features_v2.py, frozen); same windows as window_features."""
    if not pkts:
        return []
    t = np.array([p[0] for p in pkts], float)
    out = np.array([p[1] == "out" for p in pkts], bool)
    size = np.array([p[2] for p in pkts], float)
    idx = ((t - t[0]) // WIN).astype(int)
    last_full = int((t[-1] - t[0]) // WIN) - 1
    smax_out = size[out].max() if out.any() else 0.0
    smax_in = size[~out].max() if (~out).any() else 0.0

    def cv(x):
        d = np.diff(x)
        return float(d.std() / d.mean()) if len(d) > 1 and d.mean() > 0 else 0.0
    rows = []
    for w in np.unique(idx):
        m = idx == w
        if m.sum() < MIN_PKTS or w > last_full:
            continue
        tw, ow, sw = t[m], out[m], size[m]
        n, b = len(tw), float(sw.sum())
        hist = np.histogram(np.clip(sw, 0, 1599), bins=16, range=(0, 1600))[0] / n
        ent = float(-(hist[hist > 0] * np.log2(hist[hist > 0])).sum())
        peak, lag = _rhythm(tw)
        iat = np.diff(tw)
        rows.append([n / WIN, b / WIN, float(sw[ow].sum()) / b if b else 0.0,
                     float((ow[1:] != ow[:-1]).mean()) if n > 1 else 0.0,
                     float((sw[ow] >= smax_out - 8).mean()) if ow.any() else 0.0,
                     float((sw[~ow] >= smax_in - 8).mean()) if (~ow).any() else 0.0,
                     cv(tw[ow]), cv(tw[~ow]), ent, peak, lag,
                     float((iat < 0.005).mean()) if len(iat) else 0.0])
    R = np.asarray(rows, float)
    if len(R):
        ctx = np.array([R[max(0, i - 2):i + 3, :3].mean(axis=0) for i in range(len(R))])
        R = np.hstack([R, ctx])
    return R.tolist()


def window_features_v2(pkts: list[tuple[float, str, int]]) -> list[list[float]]:
    """EXP-42's v2 = the 31 v1 columns + 15 rhythm/shape columns, window for window (DEC-054). Only times, directions
    and IP lengths: nothing about the label, the cipher or the tunnel type."""
    pkts = sorted(pkts, key=lambda p: p[0])     # stable on time only, as the experiments ordered them
    base = window_features(pkts)
    ext = _v2_extra(pkts)
    return [a + b for a, b in zip(base, ext)]


def balanced_weights(y, family):
    """Every training family carries equal total weight; within a family every class does (EXP-42 K1)."""
    y, family = np.asarray(y), np.asarray(family)
    w = np.zeros(len(y))
    fams = set(family.tolist())
    for f in fams:
        mf = family == f
        classes = set(y[mf].tolist())
        for c in classes:
            m = mf & (y == c)
            w[m] = 1.0 / (len(fams) * len(classes) * m.sum())
    return w * len(y)


@lru_cache(maxsize=1)
def _model():
    """Train once per process on the shipped training windows (build/models/make_traffic_data.py).
    n_jobs=-1 (EXP-20/DEC-037): parallel fit, 0.68 s measured vs 5.0 s single-threaded on today's
    data, predictions identical to n_jobs=1 up to floating-point noise (same random_state)."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neighbors import NearestNeighbors
    from sklearn.preprocessing import StandardScaler

    d = np.load(DATA, allow_pickle=False)
    X, y = d["X"], d["y"]
    w = balanced_weights(y, d["family"]) if "family" in d.files else None
    rf = RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, y, sample_weight=w)
    # out-of-distribution gate: how far is a window from the nearest training
    # window, compared with how far training windows are from each other
    sc = StandardScaler().fit(X)
    Xs = sc.transform(X)
    nn = NearestNeighbors(n_neighbors=2).fit(Xs)
    self_dist = nn.kneighbors(Xs)[0][:, 1]          # [:,0] is the point itself
    return rf, sc, nn, float(np.percentile(self_dist, 99)), int(len(y))


def _packets(esp: list[dict], out_src: str | None) -> list[tuple[float, str, int]]:
    pk = sorted((p["t"], "out" if p["src"] == out_src else "in", p["ip_len"])
                for p in esp if p.get("ip_len"))
    return pk


def assess_exposure(esp: list[dict], out_src: str | None = None) -> dict:
    """Run the attacker on one tunnel's ESP packets. Returns a JSON-safe dict:
    status 'measured' | 'insufficient' | 'out_of_distribution'."""
    if out_src is None and esp:
        out_src = esp[0]["src"]
    feats = window_features_v2(_packets(esp, out_src))
    base = {"windows": len(feats), "min_windows": MIN_WINDOWS, "reference": REFERENCE,
            "label_suppressed": True}
    if len(feats) < MIN_WINDOWS:
        return {**base, "status": "insufficient", "level": None,
                "note": f"only {len(feats)} usable {WIN:g}-second window(s) of ESP traffic; "
                        f"the attacker needs at least {MIN_WINDOWS} to say anything"}
    rf, sc, nn, ood_cut, n_train = _model()
    X = np.array(feats)
    dist = nn.kneighbors(sc.transform(X), n_neighbors=1)[0][:, 0]
    in_dist = dist <= ood_cut
    base.update(n_train_windows=n_train, in_distribution_share=round(float(in_dist.mean()), 3))
    if in_dist.mean() < 0.5:
        return {**base, "status": "out_of_distribution", "level": None,
                "note": "this traffic looks unlike the lab traffic and real traffic (eight families) the attacker was trained on, "
                        "so its confidence would mean nothing here; the size/timing bits still apply"}
    P = rf.predict_proba(X[in_dist])
    top = P.max(axis=1)
    picks = P.argmax(axis=1)
    consistency = Counter(picks).most_common(1)[0][1] / len(picks)
    confidence = float(top.mean())
    score = round(100 * confidence * consistency)
    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    mean_p = P.mean(axis=0)
    order = np.argsort(mean_p)[::-1]
    guess, p_guess = str(rf.classes_[order[0]]), float(mean_p[order[0]])
    # second stage (EXP-16 D): is this ONE kind of traffic, or several at once?
    # Confidence cannot tell (EXP-15 P15-4), the probability pattern can.
    from .mixed import is_mixed
    mx = is_mixed(P)
    mixed, p_mixed = mx if mx else (False, None)
    answer = p_guess >= TAU and consistency >= MIN_CONSISTENCY and not mixed
    return {**base, "status": "measured", "level": level, "score": score,
            "confidence": round(confidence, 3), "consistency": round(float(consistency), 3),
            "traffic": {"answered": answer, "class": guess if answer else None,
                        "label": LABEL.get(guess) if answer else None, "probability": round(p_guess, 3),
                        "alternatives": [{"class": str(rf.classes_[i]), "label": LABEL.get(str(rf.classes_[i])),
                                          "probability": round(float(mean_p[i]), 3)} for i in order[:3]],
                        "mixed": mixed, "mixed_probability": p_mixed, "mixed_checked": mx is not None,
                        "dominant": {"class": guess, "label": LABEL.get(guess), "probability": round(p_guess, 3)},
                        "why_not": None if answer else (
                            f"two or more kinds of traffic are sharing this tunnel ({p_mixed:.0%} confidence); "
                            f"the loudest one looks like {LABEL.get(guess)}" if mixed else
                            f"windows disagree (only {consistency:.0%} agree): likely mixed traffic"
                            if consistency < MIN_CONSISTENCY else f"top probability {p_guess:.0%} is below {TAU:.0%}")},
            "note": _note(level, confidence, consistency, len(picks))}


def _note(level: str, conf: float, cons: float, n: int) -> str:
    what = {"high": "can reliably tell what kind of traffic this tunnel carries",
            "medium": "can partly tell what kind of traffic this tunnel carries",
            "low": "cannot reliably tell what kind of traffic this tunnel carries"}[level]
    return (f"A passive attacker model trained on eight families of lab and real traffic {what}, from packet sizes and timing alone "
            f"(average confidence {conf:.0%}, same guess in {cons:.0%} of {n} windows). "
            "Encryption hides the content, not the shape.")


def extract_attacker(rec) -> None:
    """Pipeline hook: 'attacker_exposure' (MEASURED/UNKNOWN) and 'traffic_type'
    (INFERRED with its probability, or UNKNOWN when the classifier abstains)."""
    from ..evidence.record import EvidencePtr, Finding, Status, Vantage
    esp = getattr(rec, "_esp", [])
    if not esp:
        return
    r = assess_exposure(esp, rec.src if any(p["src"] == rec.src for p in esp) else None)
    if r["status"] != "measured":
        rec.add(Finding("attacker_exposure", Status.UNKNOWN, Vantage.T0, "random-forest attacker (EXP-05)",
                        note=r["note"]))
        rec.add(Finding("traffic_type", Status.UNKNOWN, Vantage.T0, "traffic classifier (EXP-15)",
                        note="uncertain: " + r["note"]))
        return
    t = r["traffic"]
    ev = [EvidencePtr(rec.source_pcap, esp[0]["frame"], "esp sizes/timing/direction", f"{r['windows']} windows")]
    if t["answered"]:
        alts = ", ".join(f"{a['label']} {a['probability']:.0%}" for a in t["alternatives"][1:])
        rec.add(Finding("traffic_type", Status.INFERRED, Vantage.T0, "traffic classifier (EXP-15)",
                        value={"class": t["class"], "label": t["label"], "probability": t["probability"],
                               "alternatives": t["alternatives"]},
                        confidence=t["probability"], evidence=ev,
                        note=f"predicted from packet sizes, timing and direction over {r['windows']} windows; "
                             f"{r['consistency']:.0%} of windows agree. Next most likely: {alts}. The traffic "
                             "classes are learned from our lab traffic (synthetic shapes plus real browser, SSH, "
                             "SFTP, SMTP, XMPP and RTP sessions) and from real public traffic in other people's OpenVPN "
                             "tunnels (MIT VNAT), not from app fingerprints; traffic unlike anything in that training "
                             "set can be misread (EXP-16: a synthetic-only model scored 0.46 on real applications; "
                             "EXP-19: 0.74 on real public tunnels it never saw); "
                             + (MIXED_NOTE if t.get("mixed_checked") else MIXED_NOT_RUN)
                             + (f"; caution: {KNOWN_CONFUSION[t['class']]}" if t["class"] in KNOWN_CONFUSION else "")
                             + "."))
    else:
        note = ("mixed traffic: " if t.get("mixed") else "uncertain: ") + t["why_not"] + ". Closest guesses: " \
               + ", ".join(f"{a['label']} {a['probability']:.0%}" for a in t["alternatives"])
        rec.add(Finding("traffic_type", Status.UNKNOWN, Vantage.T0, "traffic classifier (EXP-15/16)", note=note))
    rec.add(Finding("attacker_exposure", Status.MEASURED, Vantage.T0, "random-forest attacker (EXP-05)",
                    value={k: r[k] for k in ("level", "score", "confidence", "consistency", "windows")},
                    confidence=1.0,
                    evidence=[EvidencePtr(rec.source_pcap, esp[0]["frame"], "esp sizes/timing/direction",
                                          f"{r['windows']} windows")],
                    note=r["note"]))
