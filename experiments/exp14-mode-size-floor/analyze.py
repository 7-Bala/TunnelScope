#!/usr/bin/env python3
"""EXP-14 analysis: (1) the size-floor proof of transport mode against every
pre-registered prediction; (2) the exploratory ACK-size mode model declared in
addendum A, evaluated leave-one-repetition-out.

Data: EXP-15 traffic sessions (tun / tra / tfc arms, AES-GCM-256, per-packet
tables: native ESP, content = ip.len - 20 - 8) and every tracked capture with a
ground-truth mode. Writes results/exp14_results.json.
"""
import csv
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tunnelscope.evidence.protocol import tunnel_floor  # noqa: E402
from tunnelscope.leakage.mode_model import features, purity, BUCKETS, MIN_PURITY  # noqa: E402

TR = ROOT / "testbed/captures/exp15/traffic"
AEAD = ["AES-CTR+HMAC-SHA256-128", "AES-GCM-16", "AES-CCM-16", "ChaCha20-Poly1305"]


def sessions():
    out = []
    seen = set()
    for tag, arm, cls, rep, *_ in csv.reader(open(TR / "manifest.csv")):
        if tag in seen or arm not in ("tun", "tra", "tfc"):
            continue
        seen.add(tag)
        with gzip.open(TR / f"{tag}.pkts.csv.gz", "rt") as f:
            next(f)
            lens = [int(n) - 28 for _, _, n in (l.strip().split(",") for l in f) if n]
        out.append(dict(tag=tag, mode="transport" if arm == "tra" else "tunnel", arm=arm, cls=cls, rep=int(rep), content=lens))
    return out


def main():
    S = sessions()
    floor = tunnel_floor(AEAD)
    res = {"floor_aead": floor, "n_sessions": len(S)}

    # (1) size floor, per session
    fired = [(s, any(c < floor for c in s["content"])) for s in S]
    res["P14-1 false transport on tunnel sessions"] = sum(1 for s, f in fired if f and s["mode"] == "tunnel")
    res["P14-4 TFC sessions fired"] = sum(1 for s, f in fired if f and s["arm"] == "tfc")
    cov = defaultdict(list)
    for s, f in fired:
        if s["mode"] == "transport":
            cov[s["cls"]].append(f)
    res["P14-3 floor coverage on transport, by class"] = {c: round(np.mean(v), 2) for c, v in sorted(cov.items())}

    # (2) exploratory ACK-size model, leave-one-repetition-out, tun vs tra only
    from sklearn.ensemble import RandomForestClassifier
    D = [s for s in S if s["arm"] in ("tun", "tra")]
    X = np.array([features(s["content"]) for s in D]); y = np.array([s["mode"] for s in D])
    reps = np.array([s["rep"] for s in D]); cls = np.array([s["cls"] for s in D])
    usable = np.array([x[-1] >= 0.05 and purity(x) >= MIN_PURITY for x in X])   # addendum B guard
    rows = []
    for k in sorted(set(reps)):
        tr, te = (reps != k) & usable, (reps == k)
        m = RandomForestClassifier(n_estimators=200, random_state=0, min_samples_leaf=2).fit(X[tr], y[tr])
        P = m.predict_proba(X[te])
        for i, p in zip(np.where(te)[0], P):
            j = int(np.argmax(p))
            rows.append(dict(tag=D[i]["tag"], cls=cls[i], truth=y[i], pred=m.classes_[j], p=float(p[j]), usable=bool(usable[i])))
    best = None
    for tau in (0.8, 0.85, 0.9, 0.95):
        ans = [r for r in rows if r["usable"] and r["p"] >= tau]
        acc = np.mean([r["pred"] == r["truth"] for r in ans]) if ans else 0
        ft = sum(1 for r in ans if r["truth"] == "tunnel" and r["pred"] == "transport")
        cand = dict(tau=tau, answered=len(ans), of=len(rows), accuracy=round(float(acc), 4), tunnel_called_transport=ft)
        res.setdefault("model_by_tau", []).append(cand)
        if best is None and acc >= 0.95 and ft == 0:
            best = cand
    res["model_chosen"] = best
    res["model_ships"] = best is not None
    if best:
        by = defaultdict(list)
        for r in rows:
            by[r["cls"]].append(r["usable"] and r["p"] >= best["tau"])
        res["model_coverage_by_class"] = {c: round(np.mean(v), 2) for c, v in sorted(by.items())}
    res["model_errors"] = [r for r in rows if r["usable"] and r["pred"] != r["truth"]]
    # the shipped model: written ONLY when the pre-declared bar is met, else removed
    npz = ROOT / "tunnelscope/models/mode_windows.npz"
    if best:
        np.savez_compressed(npz, X=X[usable], y=y[usable], tau=np.array(best["tau"]))
    elif npz.exists():
        npz.unlink()
    res["buckets"] = BUCKETS
    # addendum B: out-of-domain check on every tracked capture with ground-truth mode
    from tunnelscope.evidence.extract import build_records
    ood = []
    for r in csv.DictReader(open(ROOT / "dataset/MANIFEST.csv")):
        if not r["gt_mode"]:
            continue
        for rec in build_records(str(ROOT / "testbed/captures" / r["path"])):
            f = rec.findings.get("mode")
            if f is not None and f.value is not None:
                ood.append(dict(path=r["path"], truth=r["gt_mode"], got=f.value, method=f.method))
    res["ood_claims"] = ood
    res["ood_false"] = [o for o in ood if o["got"] != o["truth"]]
    out = ROOT / "experiments/exp14-mode-size-floor/results/exp14_results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps({k: v for k, v in res.items() if k not in ("model_errors",)}, indent=1, default=float))


if __name__ == "__main__":
    main()
