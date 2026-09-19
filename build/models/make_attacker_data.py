#!/usr/bin/env python3
"""Build tunnelscope/models/exp05_windows.npz: the attacker's training windows.

Input: testbed/captures/exp05/*.pkts.csv.gz + manifest.csv (EXP-05, tracked).
Uses the single-class arms only (base, tfc): the mixture arm is the one EXP-05
showed produces confident wrong labels. Deterministic; re-run after EXP-05
data changes. Output is plain arrays (allow_pickle=False on load)."""
import csv
import gzip
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tunnelscope.leakage.attacker import window_features  # noqa: E402

cap = ROOT / "testbed/captures/exp05"
X, y, arm, rep = [], [], [], []
seen = set()
for tag, a, cls, r, *_ in csv.reader(open(cap / "manifest.csv")):
    if tag in seen or a not in ("base", "tfc"):
        continue
    seen.add(tag)
    with gzip.open(cap / f"{tag}.pkts.csv.gz", "rt") as f:
        next(f)
        pk = [(float(t), d, int(n)) for t, d, n in (l.strip().split(",") for l in f) if n]
    for v in window_features(pk):
        X.append(v); y.append(cls); arm.append(a); rep.append(int(r))
out = ROOT / "tunnelscope/models/exp05_windows.npz"
np.savez_compressed(out, X=np.array(X, float), y=np.array(y), arm=np.array(arm), rep=np.array(rep))
print(f"{out.relative_to(ROOT)}: {len(y)} windows from {len(seen)} sessions")
