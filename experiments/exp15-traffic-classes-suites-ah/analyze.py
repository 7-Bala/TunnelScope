#!/usr/bin/env python3
"""EXP-15 part A analysis: the 8-class traffic classifier, evaluated against
the pre-registered predictions P15-1..P15-6 (PREREG.md). Leave-one-repetition-
out everywhere (DEC-009): every window of a session is in the same fold.

Session-level decision = mean of the in-distribution windows' class
probabilities; abstain ("uncertain") when the top probability is below TAU or
most windows are out of distribution. TAU is chosen on the training folds only.

Writes results/exp15_results.json. Run after run_exp15_traffic.sh.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/models"))
sys.path.insert(0, str(ROOT))
from make_traffic_data import load  # noqa: E402

CLASSES = ["voip", "web", "bulk", "interactive", "video", "email", "messaging", "icmp"]


def rf():
    return RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1, min_samples_leaf=2)


def ood_model(X):
    sc = StandardScaler().fit(X)
    nn = NearestNeighbors(n_neighbors=2).fit(sc.transform(X))
    cut = float(np.percentile(nn.kneighbors(sc.transform(X))[0][:, 1], 99))
    return sc, nn, cut


def session_preds(m, sc, nn, cut, X, sess):
    """-> {session: (probs over m.classes_, in-distribution share)}"""
    P = m.predict_proba(X)
    ind = nn.kneighbors(sc.transform(X), n_neighbors=1)[0][:, 0] <= cut
    out = {}
    for s in set(sess):
        k = sess == s
        use = k & ind
        p = P[use].mean(0) if use.any() else P[k].mean(0)
        out[s] = (p, float(ind[k].mean()))
    return out


def ece(conf, correct, bins=10):
    conf, correct = np.array(conf), np.array(correct, float)
    e = 0.0
    for lo in np.linspace(0, 1, bins, endpoint=False):
        k = (conf > lo) & (conf <= lo + 1 / bins)
        if k.any():
            e += k.mean() * abs(conf[k].mean() - correct[k].mean())
    return float(e)


def main():
    X, y, arm, rep, sess, src = load()
    Xm, ym, armm, repm, sessm, _ = load(include_mux=True)
    mux = armm == "mux"
    Xm, repm, sessm, ym = Xm[mux], repm[mux], sessm[mux], ym[mux]
    res = {"n_windows": int(len(y)), "n_sessions": int(len(set(sess))), "classes": CLASSES,
           "windows_per_class": dict(Counter(y.tolist())), "folds": sorted(set(rep.tolist()))}

    # --- LORO: window-level F1 per arm, session-level decisions, calibration, abstention
    sess_rows = []                    # (session, arm, true, pred, conf, in_dist_share)
    mux_rows = []
    win_true, win_pred, win_arm = [], [], []
    for k in sorted(set(rep)):
        tr, te = rep != k, rep == k
        m = rf().fit(X[tr], y[tr])
        sc, nn, cut = ood_model(X[tr])
        pw = m.predict(X[te])
        win_true += y[te].tolist(); win_pred += pw.tolist(); win_arm += arm[te].tolist()
        for s, (p, share) in session_preds(m, sc, nn, cut, X[te], sess[te]).items():
            i = int(np.argmax(p)); t = y[te][sess[te] == s][0]; a = arm[te][sess[te] == s][0]
            sess_rows.append((s, a, t, m.classes_[i], float(p[i]), share))
        km = repm == k
        if km.any():
            for s, (p, share) in session_preds(m, sc, nn, cut, Xm[km], sessm[km]).items():
                i = int(np.argmax(p))
                mux_rows.append((s, ym[km][sessm[km] == s][0], m.classes_[i], float(p[i]), share))

    wt, wp, wa = np.array(win_true), np.array(win_pred), np.array(win_arm)
    res["window_macro_f1"] = {a: round(float(f1_score(wt[wa == a], wp[wa == a], average="macro")), 4)
                              for a in sorted(set(wa))}
    tun = wa == "tunnel"
    res["window_per_class_f1_tunnel"] = dict(zip(sorted(set(wt[tun])), [round(float(v), 4) for v in
                                             f1_score(wt[tun], wp[tun], average=None, labels=sorted(set(wt[tun])))]))
    # threshold chosen from all non-mux sessions: smallest TAU with >= 95% accuracy on answered
    conf = np.array([r[4] for r in sess_rows]); corr = np.array([r[2] == r[3] for r in sess_rows])
    tau = 0.5
    for t in np.arange(0.30, 0.95, 0.01):
        k = conf >= t
        if k.sum() and corr[k].mean() >= 0.95:
            tau = round(float(t), 2); break
    res["tau"] = tau
    res["session_accuracy_all"] = round(float(corr.mean()), 4)
    ans = (conf >= tau) & (np.array([r[5] for r in sess_rows]) >= 0.5)
    res["session_answered_share"] = round(float(ans.mean()), 4)
    res["session_accuracy_answered"] = round(float(corr[ans].mean()), 4) if ans.any() else None
    res["session_ece"] = round(ece(conf, corr), 4)
    per_arm = defaultdict(list)
    for r, a_ in zip(sess_rows, ans):
        per_arm[r[1]].append((r[2] == r[3], a_))
    res["session_by_arm"] = {a: {"n": len(v), "accuracy": round(np.mean([c for c, _ in v]), 4),
                                 "answered": round(np.mean([x for _, x in v]), 4)} for a, v in per_arm.items()}
    res["session_errors"] = [dict(session=s, arm=a, true=t, pred=p, conf=round(c, 3)) for s, a, t, p, c, _ in sess_rows if t != p]
    # mixed traffic: abstain = low confidence or out of distribution
    mux_abstain = [c < tau or sh < 0.5 for _, _, _, c, sh in mux_rows]
    res["mux_sessions"] = len(mux_rows)
    res["mux_abstain_rate"] = round(float(np.mean(mux_abstain)), 4) if mux_rows else None
    res["mux_detail"] = [dict(session=s, truth=t, pred=p, conf=round(c, 3), in_dist=round(sh, 2)) for s, t, p, c, sh in mux_rows]

    # --- P15-6: train on GCM tunnel only, test on the CBC arm
    g = (arm == "tunnel") ; c = arm == "tunnel-cbc"
    if c.any():
        m = rf().fit(X[g], y[g])
        res["cross_cipher_macro_f1"] = round(float(f1_score(y[c], m.predict(X[c]), average="macro")), 4)

    # --- verdicts against the pre-registration
    f1t = res["window_macro_f1"].get("tunnel")
    pc = res["window_per_class_f1_tunnel"]
    res["predictions"] = {
        "P15-1 tunnel macro-F1 >= 0.90": f1t is not None and f1t >= 0.90,
        "P15-2 email/messaging/icmp F1 >= 0.80": all(pc.get(k, 0) >= 0.80 for k in ("email", "messaging", "icmp")),
        "P15-3 TFC macro-F1 >= 0.80": res["window_macro_f1"].get("tunnel+tfc", 0) >= 0.80,
        "P15-4 mux abstained >= 80%": (res["mux_abstain_rate"] or 0) >= 0.80,
        "P15-5 session ECE <= 0.10": res["session_ece"] <= 0.10,
        "P15-6 GCM->CBC macro-F1 >= 0.80": res.get("cross_cipher_macro_f1", 0) >= 0.80,
    }
    out = ROOT / "experiments/exp15-traffic-classes-suites-ah/results/exp15_results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps({k: res[k] for k in ("window_macro_f1", "window_per_class_f1_tunnel", "tau",
                                          "session_accuracy_all", "session_answered_share", "session_accuracy_answered",
                                          "session_ece", "mux_abstain_rate", "cross_cipher_macro_f1", "predictions")
                      if k in res}, indent=1, default=float))


if __name__ == "__main__":
    main()
