#!/usr/bin/env python3
"""Build tunnelscope/models/traffic_windows_v2.npz: the traffic classifier's training windows for EXP-42's K4 recipe, the one
EXP-43 tested on lab D (DEC-054).

  v2 features (build/models/features_v2.py, mirrored in tunnelscope/leakage/attacker.py), every session of the eight families in
  build/models/corpus.py with at least 3 windows, plus two seeded augmented copies each (constant size offset in [-40, +80] bytes,
  time scale in [0.8, 1.25]); at most CAP (30) windows per session and per copy, chosen with a per-session seed; values rounded to 3 significant
  digits so the file stays under 5 MB (cap and rounding chosen from size alone, before lab D was looked at for this artifact).

Since DEC-066 (EXP-51's R6) the file holds TEN families: the eight above plus lab E's single sessions (EXP-45) and lab H's (EXP-51),
same features and copies. The product trains a RandomForest and an ExtraTrees forest on it and averages them. The cap is whatever keeps
the file under 5 MB (chosen from size alone).

Stored: X (float32), y (class), family. The family/class-balanced weights are recomputed from y and family when the product trains
(tunnelscope.leakage.attacker._model), so the file holds data, never a model (no pickles). Deterministic.

  TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python build/models/make_traffic_data_v2.py [--cap 30] [--digits 3] [--measure]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import os
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(HERE))
import corpus  # noqa: E402
import featurize  # noqa: E402

OUT = ROOT / "tunnelscope/models/traffic_windows_v2.npz"
_spec = importlib.util.spec_from_file_location("exp42", ROOT / "experiments/exp42-generalise/analyze.py")
E42 = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(E42)


def _cap(W, key, cap):
    if len(W) <= cap:
        return W
    rng = np.random.default_rng(int(hashlib.sha256(key.encode()).hexdigest()[:8], 16))
    return W[np.sort(rng.choice(len(W), cap, replace=False))]


def significant(X, digits):
    """Round to `digits` significant digits (at most 0.5% for 3), so the file compresses under 5 MB (DEC-054)."""
    X = X.astype(np.float64)
    out = np.zeros_like(X)
    nz = X != 0
    f = 10.0 ** (digits - 1 - np.floor(np.log10(np.abs(X[nz]))))
    out[nz] = np.round(X[nz] * f) / f
    return out.astype(np.float32)


def extra_families():
    """DEC-066 (EXP-51's R6): lab E's single sessions (EXP-45) and lab H's (EXP-51) join the eight corpus families."""
    out = []
    for folder, lab, fam in (("exp45", "E", "lab-e"), ("exp51", "H", "lab-h")):
        cap = ROOT / "testbed/captures" / folder
        rows = {}
        for r in csv.DictReader(open(cap / "manifest.csv")):
            if r["lab"] == lab and r["class"] != "mixed":
                rows[r["tag"]] = r                      # a tag captured twice keeps its last row, as the experiments read it
        for tag, r in sorted(rows.items()):
            out.append(corpus._mk(fam, f"{fam}:{tag}", r["class"], *corpus._table(cap / f"{tag}.pkts.csv.gz")))
    return out


def build(cap: int):
    ss = corpus.load() + extra_families()
    data = E42.Data("v2", ss, aug=True)
    import re
    rep_of = lambda sid: int(m[1]) if (m := re.search(r"rep(\d+)", sid)) else 0     # lab repetitions; 0 elsewhere
    X, y, fam, rep = [], [], [], []
    for i, w in enumerate(data.w):
        if len(w) >= featurize.MIN_WINDOWS:
            w = _cap(w, ss[i].sid, cap)
            X.append(w); y += [ss[i].label] * len(w); fam += [ss[i].family] * len(w); rep += [rep_of(ss[i].sid)] * len(w)
    for j, i in enumerate(data.aug_src):
        w = data.aug_w[j]
        if len(data.w[i]) >= featurize.MIN_WINDOWS and len(w) >= featurize.MIN_WINDOWS:
            w = _cap(w, data.aug_s[j].sid, cap)
            X.append(w); y += [ss[i].label] * len(w); fam += [ss[i].family] * len(w); rep += [rep_of(ss[i].sid)] * len(w)
    return np.vstack(X).astype(np.float32), np.array(y), np.array(fam), np.array(rep)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", type=int, default=30)
    ap.add_argument("--digits", type=int, default=3, help="significant digits kept (size: the file must stay under 5 MB)")
    ap.add_argument("--measure", action="store_true", help="report size and startup fit time, write nothing to the package")
    a = ap.parse_args()
    X, y, fam, rep = build(a.cap)
    X = significant(X, a.digits)
    target = Path(os.environ.get("TMPDIR", "/tmp")) / f"tw_v2_cap{a.cap}.npz" if a.measure else OUT
    np.savez_compressed(target, X=X, y=y, family=fam, rep=rep)
    from sklearn.ensemble import RandomForestClassifier
    sys.path.insert(0, str(ROOT))
    from tunnelscope.leakage.attacker import balanced_weights
    t = time.time()
    RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, y, sample_weight=balanced_weights(y, fam))
    print(f"cap={a.cap} windows={len(y)} bytes={target.stat().st_size} fit_s={time.time() - t:.2f} -> {target}")


if __name__ == "__main__":
    main()
