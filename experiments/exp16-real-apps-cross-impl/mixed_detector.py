#!/usr/bin/env python3
"""EXP-16 part D: the mixed-traffic detector, evaluated leave-one-repetition-out
against the pre-registered P16-5 (catch >= 80% of mixed sessions, wrongly flag
<= 10% of single-class sessions, and catch video+interactive specifically).

Writes results/exp16_mixed.json and, ONLY if the bar is met,
tunnelscope/models/mixed_windows.npz (the shipped detector's data).
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/models"))
sys.path.insert(0, str(ROOT))
from make_traffic_data import load  # noqa: E402
from tunnelscope.leakage.mixed import session_features  # noqa: E402


def sessions(include_mux):
    X, y, arm, rep, sess, src = load(include_mux=include_mux)
    return X, y, arm, rep, sess


def main():
    X, y, arm, rep, sess = sessions(True)
    single = arm != "mux"
    rows = []                       # (session, rep, label, features) built per fold
    for k in sorted(set(rep)):
        tr = single & (rep != k)
        clf = RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1,
                                     min_samples_leaf=2).fit(X[tr], y[tr])
        te = rep == k
        for s in sorted(set(sess[te])):
            m = sess == s
            P = clf.predict_proba(X[m])
            rows.append(dict(session=s, rep=int(rep[m][0]), label="mixed" if arm[m][0] == "mux" else "single",
                             truth=str(y[m][0]), f=session_features(P)))
    F = np.array([r["f"] for r in rows]); L = np.array([r["label"] for r in rows])
    R = np.array([r["rep"] for r in rows])
    # leave-one-repetition-out again, now for the detector itself
    prob = np.zeros(len(rows))
    for k in sorted(set(R.tolist())):
        tr, te = R != k, R == k
        d = RandomForestClassifier(n_estimators=300, random_state=0, min_samples_leaf=2,
                                   class_weight="balanced").fit(F[tr], L[tr])
        prob[te] = d.predict_proba(F[te])[:, list(d.classes_).index("mixed")]
    res = {"n_sessions": len(rows), "n_mixed": int((L == "mixed").sum()), "by_tau": []}
    best = None
    for tau in np.arange(0.20, 0.85, 0.05):
        flag = prob >= tau
        recall = float(flag[L == "mixed"].mean())
        fpr = float(flag[L == "single"].mean())
        vi = [i for i, r in enumerate(rows) if r["truth"] in ("video+interactive", "video_interactive")]
        vi_caught = float(np.mean([flag[i] for i in vi])) if vi else None
        row = dict(tau=round(float(tau), 2), mixed_caught=round(recall, 3), single_wrongly_flagged=round(fpr, 3),
                   video_interactive_caught=vi_caught)
        res["by_tau"].append(row)
        if best is None and recall >= 0.80 and fpr <= 0.10:
            best = row
    res["chosen"] = best
    res["ships"] = best is not None
    res["P16-5"] = bool(best and (best["video_interactive_caught"] or 0) >= 0.8)
    npz = ROOT / "tunnelscope/models/mixed_windows.npz"
    if best:
        np.savez_compressed(npz, X=F, y=L, tau=np.array(best["tau"]))
    elif npz.exists():
        npz.unlink()
    out = ROOT / "experiments/exp16-real-apps-cross-impl/results/exp16_mixed.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps({k: res[k] for k in ("n_sessions", "n_mixed", "chosen", "ships", "P16-5")}, indent=1, default=float))


if __name__ == "__main__":
    main()
