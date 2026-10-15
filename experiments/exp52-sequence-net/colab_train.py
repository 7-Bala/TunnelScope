"""Runs on a Colab GPU (EXP-52). Trains every fold of `folds.json` with `netlib.py` exactly as `analyze.py` would on the Mac, and writes
`probs.npz` with the window probabilities of each fold's score sessions. Nothing here scores, chooses or gates.

    !python colab_train.py          (data and netlib.py in the working directory; optional DONE_DIR to resume)
"""
import json
import os
import sys
import time

import numpy as np

sys.path.insert(0, ".")
import netlib  # noqa: E402

W = np.load("windows.npz")
M = json.load(open("folds.json"))
X, LN, Y, FAM, SID, SC = W["X"], W["lens"].astype(int), W["y"], W["fam"], W["sid"], W["scale"]
IS_VAL = np.array(M["is_val"], bool)
CLASSES, FAMS = M["classes"], M["families"]
OUT = "probs.npz"
res = dict(np.load(OUT)) if os.path.exists(OUT) else {}


def part(sessions):
    return np.flatnonzero(np.isin(SID, sessions))


def fit_weights(idx):
    return netlib.weights(np.array([FAMS[f] for f in FAM[idx]]), np.array([CLASSES[k] for k in Y[idx]])).astype(np.float32)


def arr(idx):
    return X[idx], LN[idx], Y[idx].astype(int)


for tag, f in M["folds"].items():
    train = np.array(f["train"])
    tr, va = part(train[~IS_VAL[train]]), part(train[IS_VAL[train]])
    score = part(f["score"])
    res[f"I|{tag}"] = score
    for variant, gap in (("gap", True), ("nogap", False)):
        if f"P|{tag}|{variant}" in res:
            continue
        t0 = time.time()
        P, info = 0.0, []
        for seed in netlib.SEEDS:
            net, inf = netlib.train_one(*arr(tr)[:2], arr(tr)[2], fit_weights(tr), *arr(va)[:2], arr(va)[2], fit_weights(va), seed, gap, SC[tr])
            info.append(inf)
            P = P + netlib.predict(net, X[score], LN[score], gap) / len(netlib.SEEDS)
        res[f"P|{tag}|{variant}"] = P.astype(np.float32)
        np.savez(OUT, **res)
        print(f"{tag:22} {variant:5} train {len(tr):6} val {len(va):5} score {len(score):5}  {info}  {time.time() - t0:.0f}s", flush=True)
print("DONE", len([k for k in res if k.startswith('P|')]), "of", 2 * len(M["folds"]))
