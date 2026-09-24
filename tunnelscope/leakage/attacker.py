"""The traffic classifier and Random Forest ATTACKER (EXP-05, EXP-15), run live on a capture.

What it is: a model of a passive eavesdropper. It was trained on our own lab
traffic (and, since EXP-19 / DEC-036, real public VPN traffic from MIT VNAT) (EXP-05: voip / web / bulk / interactive / video, with and without TFC
padding) to guess what kind of traffic is inside an encrypted ESP tunnel from
packet sizes, timing and direction alone. On that data it was right almost
every time (macro-F1 1.000 unpadded, 0.995 padded; leave-one-repetition-out).

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
the training windows ship as a plain .npz (build/models/make_attacker_data.py)
and the forest is trained on first use, in about a second, then cached.
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
# abstain rule (set from EXP-15's leave-one-repetition-out analysis; see RESULT.md)
TAU = 0.60              # minimum mean top-class probability
MIN_CONSISTENCY = 0.70  # minimum share of windows agreeing with the session's top class
WIN = 2.0                  # seconds per window (EXP-05)
MIN_PKTS = 3               # a window with fewer packets carries no usable signal
SIZE_EDGES = [0, 128, 256, 512, 1024, 1600]
MIN_WINDOWS = 3            # below this, too little traffic to say anything
DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "traffic_windows.npz")

# Measured on held-out repetitions: EXP-15 (synthetic shapes) and EXP-16 (real
# lab applications + Libreswan). The last number is the one to keep in mind: a
# model trained ONLY on synthetic shapes scored 0.46 on real applications, so
# training data that looks like the target traffic is what matters, not the tuning.
# EXP-19 (DEC-036) adds real public traffic (MIT VNAT, OpenVPN tunnels recorded by others): a lab-only
# model scored 0.47 on it, the shipped lab + real model 0.74 on capture files it never saw.
REFERENCE = {"f1_unpadded": 0.995, "f1_tfc_padded": 0.958, "f1_real_apps_loro": 0.995,
             "f1_cross_implementation": 1.0, "f1_synthetic_only_on_real_apps": 0.461,
             "f1_lab_only_on_real_public": 0.472, "f1_real_public_heldout": 0.741,
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


@lru_cache(maxsize=1)
def _model():
    """Train once per process on the shipped EXP-05 windows (base + TFC arms)."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neighbors import NearestNeighbors
    from sklearn.preprocessing import StandardScaler

    d = np.load(DATA, allow_pickle=False)
    X, y = d["X"], d["y"]
    rf = RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=1, min_samples_leaf=2).fit(X, y)
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
    feats = window_features(_packets(esp, out_src))
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
                "note": "this traffic looks unlike the lab traffic and real public traffic the attacker was trained on, "
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
                        "mixed": mixed, "mixed_probability": p_mixed,
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
    return (f"A passive attacker model trained on lab and real public traffic {what}, from packet sizes and timing alone "
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
                             + MIXED_NOTE
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
