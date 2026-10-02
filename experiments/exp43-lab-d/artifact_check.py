"""EXP-43 ship-rule check (PREREG: a reduced training set is allowed only if its lab-D ungated macro-F1 is within 0.02 of K4's,
measured once). Run once, after `tunnelscope/models/traffic_windows_v2.npz` was built (cap 30, 3 significant digits, chosen from
size alone). Writes results/artifact_check.json.

Also checks that the product's v2 features (tunnelscope.leakage.attacker.window_features_v2) equal the frozen experiment code
(build/models/features_v2.v2) on every lab-C and lab-D session.
"""
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "build" / "models")); sys.path.insert(0, str(HERE))
import corpus  # noqa: E402
import features_v2  # noqa: E402
from analyze import lab_d  # noqa: E402
from tunnelscope.leakage import attacker as A  # noqa: E402


def main():
    S = json.load(open(HERE / "results/summary.json"))
    k4 = S["K4_ungated_macro_f1"]
    # 1. product v2 == experiment v2
    mism, checked = [], 0
    for s in corpus.load(["lab-c"]) + [corpus.Session("lab-d", d["name"], d["label"], d["t"], d["out"], d["size"]) for d in lab_d()]:
        a = np.array(features_v2.v2(s.t, s.out, s.size))
        b = np.array(A.window_features_v2(list(zip(s.t.tolist(), np.where(s.out, "out", "in").tolist(), s.size.tolist()))))
        checked += 1
        if a.shape != b.shape or not np.allclose(a, b):
            mism.append(s.sid)
    # 2. the shipped artifact through the product, on lab D
    rf = A._model()[0]
    ys, ps, ans, right = [], [], 0, 0
    for d in lab_d():
        pk = list(zip(d["t"].tolist(), np.where(d["out"], "out", "in").tolist(), d["size"].tolist()))
        W = np.array(A.window_features_v2(pk))
        if len(W) < A.MIN_WINDOWS:
            continue
        ys.append(d["label"]); ps.append(str(rf.classes_[int(rf.predict_proba(W).mean(axis=0).argmax())]))
        r = A.assess_exposure([{"t": t, "src": o, "ip_len": n} for t, o, n in pk], "out")
        if r["status"] == "measured" and r["traffic"]["answered"]:
            ans += 1; right += int(r["traffic"]["class"] == d["label"])
    f = float(f1_score(ys, ps, labels=sorted(set(ys)), average="macro", zero_division=0))
    out = {"features_identical": not mism, "sessions_checked": checked, "mismatches": mism[:5],
           "artifact": "tunnelscope/models/traffic_windows_v2.npz", "artifact_bytes": (ROOT / "tunnelscope/models/traffic_windows_v2.npz").stat().st_size,
           "artifact_ungated_macro_f1": round(f, 4), "k4_ungated_macro_f1": k4, "within_0.02": f >= k4 - 0.02,
           "artifact_gated": {"answered": ans, "correct": right, "scored": len(ys)},
           "pass": (not mism) and f >= k4 - 0.02}
    json.dump(out, open(HERE / "results/artifact_check.json", "w"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
