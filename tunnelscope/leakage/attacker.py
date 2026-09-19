"""The Random Forest ATTACKER (EXP-05, CS-01), run live on a capture.

What it is: a model of a passive eavesdropper. It was trained on our own lab
traffic (EXP-05: voip / web / bulk / interactive / video, with and without TFC
padding) to guess what kind of traffic is inside an encrypted ESP tunnel from
packet sizes, timing and direction alone. On that data it was right almost
every time (macro-F1 1.000 unpadded, 0.995 padded; leave-one-repetition-out).

What it reports for a capture: how SURE and how CONSISTENT that attacker is
about this tunnel's traffic, i.e. how exposed the traffic's shape is. It never
reports WHICH class it guessed: EXP-05 showed that on mixed traffic the model is
confidently wrong ("web, 100%" for video+interactive), so a label would be a
false fact about the user's traffic (DEC-021). Exposure, not identification.

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

CLASSES = ["voip", "web", "bulk", "interactive", "video"]   # training labels, never output
WIN = 2.0                  # seconds per window (EXP-05)
MIN_PKTS = 3               # a window with fewer packets carries no usable signal
SIZE_EDGES = [0, 128, 256, 512, 1024, 1600]
MIN_WINDOWS = 3            # below this, too little traffic to say anything
DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "exp05_windows.npz")

# EXP-05's measured attacker skill on its own lab data (results/exp05_results.json)
REFERENCE = {"f1_unpadded": 1.000, "f1_tfc_padded": 0.995, "chance": round(1 / len(CLASSES), 3)}


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
    rf = RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=1).fit(X, y)
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
                "note": "this traffic looks unlike the lab traffic the attacker was trained on, "
                        "so its confidence would mean nothing here; the size/timing bits still apply"}
    P = rf.predict_proba(X[in_dist])
    top = P.max(axis=1)
    picks = P.argmax(axis=1)
    consistency = Counter(picks).most_common(1)[0][1] / len(picks)
    confidence = float(top.mean())
    score = round(100 * confidence * consistency)
    level = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return {**base, "status": "measured", "level": level, "score": score,
            "confidence": round(confidence, 3), "consistency": round(float(consistency), 3),
            "note": _note(level, confidence, consistency, len(picks))}


def _note(level: str, conf: float, cons: float, n: int) -> str:
    what = {"high": "can reliably tell what kind of traffic this tunnel carries",
            "medium": "can partly tell what kind of traffic this tunnel carries",
            "low": "cannot reliably tell what kind of traffic this tunnel carries"}[level]
    return (f"A passive attacker model trained on lab traffic {what}, from packet sizes and timing alone "
            f"(average confidence {conf:.0%}, same guess in {cons:.0%} of {n} windows). "
            "Encryption hides the content, not the shape. The guessed type is deliberately not shown.")


def extract_attacker(rec) -> None:
    """Pipeline hook: add a MEASURED/UNKNOWN 'attacker_exposure' finding."""
    from ..evidence.record import EvidencePtr, Finding, Status, Vantage
    esp = getattr(rec, "_esp", [])
    if not esp:
        return
    r = assess_exposure(esp, rec.src if any(p["src"] == rec.src for p in esp) else None)
    if r["status"] != "measured":
        rec.add(Finding("attacker_exposure", Status.UNKNOWN, Vantage.T0, "random-forest attacker (EXP-05)",
                        note=r["note"]))
        return
    rec.add(Finding("attacker_exposure", Status.MEASURED, Vantage.T0, "random-forest attacker (EXP-05)",
                    value={k: r[k] for k in ("level", "score", "confidence", "consistency", "windows")},
                    confidence=1.0,
                    evidence=[EvidencePtr(rec.source_pcap, esp[0]["frame"], "esp sizes/timing/direction",
                                          f"{r['windows']} windows")],
                    note=r["note"]))
