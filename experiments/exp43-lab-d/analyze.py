"""EXP-43 scorer (pre-registered in PREREG.md, commit 31c3bc5). Writes results/summary.json and results/sessions.csv.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp43-lab-d/analyze.py

S = the shipped model through the shipped product path. K4 = EXP-42's chosen recipe, trained with EXP-42's own code
(`experiments/exp42-generalise/analyze.py`: augmentation, weights) on all eight families; lab D never trains anything.
"""
from __future__ import annotations

import csv
import gzip
import importlib.util
import json
import re
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "build" / "models"))
import corpus  # noqa: E402
import featurize  # noqa: E402
import features_v2  # noqa: E402

spec = importlib.util.spec_from_file_location("exp42", ROOT / "experiments/exp42-generalise/analyze.py")
E42 = importlib.util.module_from_spec(spec); spec.loader.exec_module(E42)
CLASSES = corpus.CLASSES
TAU, MIN_CONSISTENCY = 0.60, 0.70


def lab_d():
    out = []
    for p in sorted((ROOT / "testbed/captures/exp43").glob("exp43-*.pkts.csv.gz")):
        m = re.match(r"exp43-(chacha|sha384)-(\w+)-rep(\d)\.pkts\.csv\.gz", p.name)
        t, o, s = [], [], []
        with gzip.open(p, "rt") as f:
            next(f)
            for line in f:
                a, d, n = line.strip().split(",")
                if n:
                    t.append(float(a)); o.append(d == "out"); s.append(int(n))
        out.append({"name": p.name, "suite": m[1], "label": m[2], "rep": int(m[3]),
                    "t": np.array(t), "out": np.array(o, bool), "size": np.array(s)})
    return out


def train_k4():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.neighbors import NearestNeighbors
    from sklearn.preprocessing import StandardScaler
    ss = corpus.load()
    data = E42.Data("v2", ss, aug=True)
    keep = [i for i, w in enumerate(data.w) if len(w) >= featurize.MIN_WINDOWS]
    X, y, w = data.train(keep, balanced=True)
    rf = RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, y, sample_weight=w)
    sc = StandardScaler().fit(X)
    Xs = sc.transform(X)
    nn = NearestNeighbors(n_neighbors=2).fit(Xs)
    cut = float(np.percentile(nn.kneighbors(Xs)[0][:, 1], 99))
    return {"rf": rf, "sc": sc, "nn": nn, "cut": cut, "n_train_windows": int(len(y)), "families": sorted({ss[i].family for i in keep})}


def gated(rf, sc, nn, cut, W):
    """The shipped abstain logic, for any forest and its own training windows."""
    from tunnelscope.leakage.mixed import is_mixed
    if len(W) < featurize.MIN_WINDOWS:
        return "insufficient", None
    d = nn.kneighbors(sc.transform(W), n_neighbors=1)[0][:, 0]
    ind = d <= cut
    if ind.mean() < 0.5:
        return "out_of_distribution", None
    P = rf.predict_proba(W[ind])
    picks = P.argmax(axis=1)
    consistency = np.bincount(picks).max() / len(picks)
    mean = P.mean(axis=0)
    guess, p = str(rf.classes_[int(mean.argmax())]), float(mean.max())
    mx = is_mixed(P)
    if p >= TAU and consistency >= MIN_CONSISTENCY and not (mx and mx[0]):
        return "answered", guess
    return "abstained", None


def macro(y, p):
    return float(f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0))


def main():
    from tunnelscope.leakage import attacker as A
    (HERE / "results").mkdir(exist_ok=True)
    D = lab_d()
    k4 = train_k4()
    rf_s = A._model()[0]
    rows = []
    for s in D:
        W1 = np.array(A.window_features(list(zip(s["t"].tolist(), np.where(s["out"], "out", "in").tolist(), s["size"].tolist()))))
        W2 = np.array(features_v2.v2(s["t"], s["out"], s["size"]))
        r = {"name": s["name"], "suite": s["suite"], "label": s["label"], "windows": len(W1)}
        if len(W1):
            r["S_ungated"] = str(rf_s.classes_[int(rf_s.predict_proba(W1).mean(axis=0).argmax())])
            r["K4_ungated"] = str(k4["rf"].classes_[int(k4["rf"].predict_proba(W2).mean(axis=0).argmax())])
        esp = [{"t": float(t), "src": "out" if o else "in", "ip_len": int(n)} for t, o, n in zip(s["t"], s["out"], s["size"])]
        a = A.assess_exposure(esp, "out")
        r["S_stage"] = a["status"] if a["status"] != "measured" else ("answered" if a["traffic"]["answered"] else "abstained")
        r["S_answer"] = a.get("traffic", {}).get("class") if r["S_stage"] == "answered" else None
        r["K4_stage"], r["K4_answer"] = gated(k4["rf"], k4["sc"], k4["nn"], k4["cut"], W2) if len(W2) else ("insufficient", None)
        rows.append(r)
    sc = [r for r in rows if r["windows"] >= featurize.MIN_WINDOWS]
    y = [r["label"] for r in sc]
    S = {"captures": len(rows), "scored": len(sc), "k4_train": {k: k4[k] for k in ("n_train_windows", "families")}}
    S["S_ungated_macro_f1"] = round(macro(y, [r["S_ungated"] for r in sc]), 4)
    S["K4_ungated_macro_f1"] = round(macro(y, [r["K4_ungated"] for r in sc]), 4)
    for m in ("S", "K4"):
        ans = [r for r in sc if r[f"{m}_stage"] == "answered"]
        right = [r for r in ans if r[f"{m}_answer"] == r["label"]]
        S[f"{m}_gated"] = {"answered": len(ans), "correct": len(right), "coverage": round(len(ans) / len(sc), 4) if sc else None,
                           "accuracy_among_answered": round(len(right) / len(ans), 4) if ans else None,
                           "stages": {st: sum(1 for r in sc if r[f"{m}_stage"] == st) for st in ("answered", "abstained", "out_of_distribution", "insufficient")}}
        S[f"{m}_per_class_f1"] = {c: round(float(v), 3) for c, v in zip(sorted(set(y)), f1_score(y, [r[f"{m}_ungated"] for r in sc], labels=sorted(set(y)), average=None, zero_division=0))}
    S["by_suite"] = {}
    for suite in ("chacha", "sha384"):
        sub = [r for r in sc if r["suite"] == suite]
        S["by_suite"][suite] = {m: round(macro([r["label"] for r in sub], [r[f"{m}_ungated"] for r in sub]), 4) for m in ("S", "K4")}
    S["P43-1"] = {"S": S["S_ungated_macro_f1"], "pass": S["S_ungated_macro_f1"] < 0.60}
    S["P43-2"] = {"K4": S["K4_ungated_macro_f1"], "S": S["S_ungated_macro_f1"], "gain": round(S["K4_ungated_macro_f1"] - S["S_ungated_macro_f1"], 4),
                  "pass": S["K4_ungated_macro_f1"] - S["S_ungated_macro_f1"] >= 0.10}
    g4, gs = S["K4_gated"], S["S_gated"]
    S["P43-3"] = {"k4_accuracy_among_answered": g4["accuracy_among_answered"], "k4_correct": g4["correct"], "s_correct": gs["correct"],
                  "pass": bool(g4["accuracy_among_answered"] is not None and g4["accuracy_among_answered"] >= 0.90 and g4["correct"] >= gs["correct"])}
    S["P43-4"] = {"by_suite": S["by_suite"], "pass": all(v["K4"] >= v["S"] for v in S["by_suite"].values())}
    S["ship"] = bool(S["P43-2"]["pass"] and S["P43-3"]["pass"])
    with open(HERE / "results/sessions.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    json.dump(S, open(HERE / "results/summary.json", "w"), indent=1)
    print(json.dumps(S, indent=1))


if __name__ == "__main__":
    main()
