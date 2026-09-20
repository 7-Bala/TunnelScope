#!/usr/bin/env python3
"""EXP-16 analysis: real applications, cross-implementation transfer, and the
stability of the EXP-15 numbers after more repetitions (P16-1..P16-4, P16-6).
Part D (mixed detector) has its own script. Writes results/exp16_results.json.
"""
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/models"))
sys.path.insert(0, str(ROOT))
from make_traffic_data import load  # noqa: E402

SYN = ("tunnel", "tunnel+tfc", "transport", "tunnel-cbc")       # strongSwan, synthetic generator
rf = lambda: RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1, min_samples_leaf=2)


def macro(y, p):
    return round(float(f1_score(y, p, average="macro", zero_division=0)), 4)


def loro(X, y, rep):
    out = []
    for k in sorted(set(rep.tolist())):
        tr, te = rep != k, rep == k
        if not tr.any() or not te.any():
            continue
        out.append(macro(y[te], rf().fit(X[tr], y[tr]).predict(X[te])))
    return out


def session_vote(model, X, sess, y):
    """session-level accuracy: mean window probabilities decide."""
    ok = []
    for s in sorted(set(sess.tolist())):
        m = sess == s
        p = model.predict_proba(X[m]).mean(axis=0)
        ok.append(str(model.classes_[int(np.argmax(p))]) == str(y[m][0]))
    return round(float(np.mean(ok)), 4), len(ok)


def main():
    Xs, ys, arms, reps, sess_s, _ = load(keep=SYN)
    Xr, yr, armr, repr_, sess_r, _ = load(keep=("real-apps",))
    Xl, yl, arml, repl, sess_l, _ = load(keep=("libreswan",))
    res = {"synthetic_windows": len(ys), "real_windows": len(yr), "libreswan_windows": len(yl),
           "real_sessions": len(set(sess_r.tolist())), "libreswan_sessions": len(set(sess_l.tolist()))}

    syn_model = rf().fit(Xs, ys)
    # P16-1: synthetic -> real applications
    res["P16-1 synthetic->real macro_f1"] = macro(yr, syn_model.predict(Xr))
    acc, n = session_vote(syn_model, Xr, sess_r, yr)
    res["P16-1 synthetic->real session accuracy"] = acc
    res["P16-1 real sessions"] = n
    per = f1_score(yr, syn_model.predict(Xr), average=None, labels=sorted(set(yr.tolist())), zero_division=0)
    res["P16-1 per class"] = {c: round(float(v), 3) for c, v in zip(sorted(set(yr.tolist())), per)}

    # P16-2: trained on real applications, held-out repetition
    res["P16-2 real LORO macro_f1"] = loro(Xr, yr, repr_)
    res["P16-2 mean"] = round(float(np.mean(res["P16-2 real LORO macro_f1"])), 4)

    # P16-3: strongSwan-trained -> Libreswan-carried synthetic traffic
    res["P16-3 strongswan->libreswan macro_f1"] = macro(yl, syn_model.predict(Xl))
    acc, n = session_vote(syn_model, Xl, sess_l, yl)
    res["P16-3 libreswan session accuracy"] = acc

    # P16-6: stability of the EXP-15 number when repetitions 5-6 are added
    r4 = reps <= 4
    res["P16-6 macro_f1 reps1-4"] = round(float(np.mean(loro(Xs[r4], ys[r4], reps[r4]))), 4)
    res["P16-6 macro_f1 reps1-6"] = round(float(np.mean(loro(Xs, ys, reps))), 4)
    res["P16-6 delta"] = round(abs(res["P16-6 macro_f1 reps1-6"] - res["P16-6 macro_f1 reps1-4"]), 4)

    # combined model (what ships): everything, held-out repetition
    Xa, ya, arma, repa, sess_a, _ = load()
    res["combined_windows"] = len(ya)
    res["combined LORO macro_f1"] = round(float(np.mean(loro(Xa, ya, repa))), 4)
    res["verdicts"] = {
        "P16-1 synthetic->real >= 0.60": res["P16-1 synthetic->real macro_f1"] >= 0.60,
        "P16-2 real LORO >= 0.85": res["P16-2 mean"] >= 0.85,
        "P16-3 cross-implementation >= 0.90": res["P16-3 strongswan->libreswan macro_f1"] >= 0.90,
        "P16-6 reps delta <= 0.02": res["P16-6 delta"] <= 0.02,
    }
    out = ROOT / "experiments/exp16-real-apps-cross-impl/results/exp16_results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps(res, indent=1, default=float))


if __name__ == "__main__":
    main()
