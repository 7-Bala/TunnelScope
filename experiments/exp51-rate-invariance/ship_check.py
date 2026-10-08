"""DEC-066: the two steps that turn EXP-51's chosen pair (R6 and the gate set on held-out families) into shipped files.

    .venv/bin/python experiments/exp51-rate-invariance/ship_check.py mixed    # writes tunnelscope/models/mixed_windows.npz
    .venv/bin/python experiments/exp51-rate-invariance/ship_check.py check    # lab G through the product, writes results/artifact_check.json

`mixed` stores what EXP-51's lab-G detector was trained on: the window-probability shape (tunnelscope.leakage.mixed.session_features)
of every held-out single and mixed session, each scored by R6 trained without that session's family (results/heldout_R6.pkl, written
by analyze.py), with the threshold of results/choice.json. No model is stored.

`check` runs every lab-G session through tunnelscope.leakage.attacker (the shipped training file, model and gate). Lab G was already
looked at by EXP-51, so this is a reproduction check of the shipped files, not a new measurement: the shipped training file keeps
fewer windows per session and three significant digits, so small differences from R6 are expected and are reported as they are.
"""
from __future__ import annotations

import csv
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "build" / "models"))
import corpus  # noqa: E402

RES = HERE / "results"
CAP = ROOT / "testbed/captures/exp51"


def mixed():
    rec = pickle.load(open(RES / "heldout_R6.pkl", "rb"))
    tau = json.load(open(RES / "choice.json"))["gate"]["tau_m"]
    X = np.array([r["shape"] for r in rec], np.float64)
    y = np.array([r["kind"] for r in rec])
    out = ROOT / "tunnelscope/models/mixed_windows.npz"
    np.savez_compressed(out, X=X, y=y, tau=np.array(tau))
    print(f"{out}: {dict(Counter(y.tolist()))} tau={tau} bytes={out.stat().st_size}")


def check():
    from tunnelscope.leakage import attacker as A
    model = A._model()[0]
    rows = {}
    for r in csv.DictReader(open(CAP / "manifest.csv")):
        if r["lab"] == "G":
            rows[r["tag"]] = r
    out = []
    for tag, r in sorted(rows.items()):
        pk = corpus.packets(CAP / f"{tag}.pkts.csv.gz")
        W = np.array(A.window_features_v2(pk))
        res = A.assess_exposure([{"t": t, "src": d, "ip_len": n} for t, d, n in pk], "out")
        ans = res["status"] == "measured" and res["traffic"]["answered"]
        out.append({"tag": tag, "label": r["class"], "variant": r["variant"],
                    "ungated": str(model.classes_[int(model.predict_proba(W).mean(axis=0).argmax())]) if len(W) >= A.MIN_WINDOWS else None,
                    "answer": res["traffic"]["class"] if ans else None})
    single = [o for o in out if o["label"] != "mixed"]; mix = [o for o in out if o["label"] == "mixed"]
    y = [o["label"] for o in single]; p = [o["ungated"] for o in single]
    a = [o for o in single if o["answer"]]
    S = {"singles": len(single), "ungated_macro_f1": round(float(f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0)), 4),
         "ungated_right": sum(1 for u, v in zip(y, p) if u == v),
         "answered": len(a), "answers_right": sum(1 for o in a if o["answer"] == o["label"]),
         "answers_wrong": [(o["variant"], o["answer"]) for o in a if o["answer"] != o["label"]],
         "mixed": len(mix), "mixed_answered": [(o["variant"], o["answer"]) for o in mix if o["answer"]],
         "exp51_r6_for_comparison": {"ungated_macro_f1": 0.8553, "answered": 20, "answers_right": 20, "mixed_answered": 2}}
    json.dump(S, open(RES / "artifact_check.json", "w"), indent=1)
    print(json.dumps(S, indent=1))


if __name__ == "__main__":
    {"mixed": mixed, "check": check}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()
