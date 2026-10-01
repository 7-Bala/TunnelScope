"""EXP-38 scorer (pre-registered in PREREG.md, commit 9d7a03c). Writes results/summary.json and results/captures.csv.

    .venv/bin/python experiments/exp38-traffic-transfer-diagnosis/analyze.py --lab DIR/ipsec-pcap-lab --work DIR/scratch

Nothing that ships is changed. Features come from the shipped `window_features` / `_packets`; the stage census uses
the shipped `assess_exposure`; the ungated model is the shipped forest. Per-window feature vectors derived from the
other team's captures are kept in --work (outside the repository), never in results/.
"""
import argparse
import csv
import glob
import json
import os
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
CLASSES7 = ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"]
MAP = {"bulk": "file_transfer"}
FEATS = [f"{d}_{n}" for d in ("out", "in") for n in
         ("count", "bytes", "mean", "std", "min", "max", "log_iat_mean", "log_iat_std", "log_iat_median", "frac_iat_lt_1ms",
          "hist_0_128", "hist_128_256", "hist_256_512", "hist_512_1024", "hist_1024_1600")] + ["out_share"]


def one(path):
    from tunnelscope.evidence.extract import build_records
    from tunnelscope.leakage import attacker as A
    recs = build_records(path)
    if not recs:
        return {"path": path, "error": "no records"}
    rec = max(recs, key=lambda r: len(getattr(r, "_esp", [])))
    esp = getattr(rec, "_esp", [])
    if not esp:
        return {"path": path, "error": "no ESP packets"}
    out_src = rec.src if any(p["src"] == rec.src for p in esp) else None
    feats = A.window_features(A._packets(esp, out_src if out_src else esp[0]["src"]))
    r = A.assess_exposure(esp, out_src)
    stage = ("insufficient" if r["status"] == "insufficient" else "out_of_distribution" if r["status"] == "out_of_distribution"
             else "answered" if r["traffic"]["answered"] else "abstained")
    return {"path": path, "feats": feats, "stage": stage, "in_dist": r.get("in_distribution_share"),
            "n_windows": len(feats), "shipped_answer": (r.get("traffic") or {}).get("class")}


def macro_f1(y, p):
    from sklearn.metrics import f1_score
    return float(f1_score(y, p, labels=CLASSES7, average="macro", zero_division=0))


def cap_pred(rf, feats):
    P = rf.predict_proba(np.array(feats))
    return str(rf.classes_[int(P.mean(axis=0).argmax())])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    os.makedirs(RES, exist_ok=True)
    os.makedirs(a.work, exist_ok=True)
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import GroupKFold
    from tunnelscope.leakage import attacker as A

    meta = {r["pcap_path"]: r for r in csv.DictReader(open(os.path.join(a.lab, "metadata.csv")))}
    paths = [(s, p) for s in ("known", "ood") for p in sorted(glob.glob(os.path.join(a.lab, "pcaps", s, "**", "*.pcap"), recursive=True))]
    with ProcessPoolExecutor(4) as ex:
        res = list(ex.map(one, [p for _, p in paths]))
    rows = []
    for (s, p), r in zip(paths, res):
        rel = os.path.relpath(p, a.lab)
        m = meta.get(rel)
        if m is None or "error" in r:
            rows.append({"set": s, "rel": rel, "error": r.get("error", "no metadata")})
            continue
        rows.append({"set": s, "rel": rel, "label": m["canonical_label"], "profile": m["profile_id"], "run": m["run_id"],
                     "role": m["dataset_role"], **{k: r[k] for k in ("feats", "stage", "in_dist", "n_windows", "shipped_answer")}})
    S = {"errors": [r["rel"] for r in rows if "error" in r]}
    known = [r for r in rows if r["set"] == "known" and "error" not in r]
    S["n_known"] = len(known)
    # stage census + P38-1
    S["stage_census"] = dict(Counter(r["stage"] for r in known))
    ood_share = sum(1 for r in known if r["in_dist"] is not None and r["in_dist"] < 0.5) / len(known)
    S["P38-1"] = {"share_in_distribution_below_0.5": round(ood_share, 4), "pass": ood_share >= 0.80}
    S["in_dist_share_quartiles"] = [round(float(x), 3) for x in np.percentile([r["in_dist"] for r in known if r["in_dist"] is not None], [0, 25, 50, 75, 100])]
    # P38-2 ungated shipped model
    rf_ship = A._model()[0]
    usable = [r for r in known if r["n_windows"] > 0]
    pred = [MAP.get(cap_pred(rf_ship, r["feats"]), cap_pred(rf_ship, r["feats"])) for r in usable]
    y = [r["label"] for r in usable]
    f2 = macro_f1(y, pred)
    S["P38-2"] = {"captures_with_windows": len(usable), "macro_f1": round(f2, 4), "accuracy": round(float(np.mean([a_ == b for a_, b in zip(y, pred)])), 4),
                  "pass": f2 < 0.50, "pred_counts": dict(Counter(pred))}
    # within-lab data
    def windows(rs):
        X, Y, G = [], [], []
        for r in rs:
            for f in r["feats"]:
                X.append(f); Y.append(r["label"]); G.append(r["rel"])
        return np.array(X), np.array(Y), G
    def fit(X, Y):
        return RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, Y)
    train = [r for r in usable if r["run"] in ("R01", "R02", "R03")]
    test = [r for r in usable if r["run"] == "R05"]
    Xtr, Ytr, _ = windows(train)
    rf = fit(Xtr, Ytr)
    p3 = [cap_pred(rf, r["feats"]) for r in test]
    f3 = macro_f1([r["label"] for r in test], p3)
    S["P38-3"] = {"train_captures": len(train), "test_captures": len(test), "macro_f1": round(f3, 4), "pass": f3 >= 0.80}
    # P38-4 leave-one-profile-out
    per = {}
    for prof in sorted({r["profile"] for r in usable}):
        tr = [r for r in usable if r["profile"] != prof]
        te = [r for r in usable if r["profile"] == prof]
        X_, Y_, _ = windows(tr)
        m_ = fit(X_, Y_)
        per[prof] = round(macro_f1([r["label"] for r in te], [cap_pred(m_, r["feats"]) for r in te]), 4)
    f4 = float(np.mean(list(per.values())))
    S["P38-4"] = {"per_profile": per, "mean_macro_f1": round(f4, 4), "pass": f4 >= 0.70}
    # P38-5 / P38-6 mixed training
    d = np.load(A.DATA, allow_pickle=False)
    Xs = d["X"]
    ys = np.array([MAP.get(v, v) for v in d["y"]])
    groups = d["session"]
    rf_mix = fit(np.vstack([Xs, Xtr]), np.concatenate([ys, Ytr]))
    p5 = [cap_pred(rf_mix, r["feats"]) for r in test]
    f5 = macro_f1([r["label"] for r in test], p5)
    S["P38-5"] = {"macro_f1_on_R05": round(f5, 4), "pass": f5 >= 0.80}
    from sklearn.metrics import f1_score
    def cv(add):
        preds = np.empty(len(ys), dtype=object)
        for tr_i, te_i in GroupKFold(n_splits=5).split(Xs, ys, groups):
            X_, Y_ = Xs[tr_i], ys[tr_i]
            if add:
                X_, Y_ = np.vstack([X_, Xtr]), np.concatenate([Y_, Ytr])
            preds[te_i] = fit(X_, Y_).predict(Xs[te_i])
        return float(f1_score(ys, preds.astype(str), average="macro", zero_division=0))
    base, mixed = cv(False), cv(True)
    S["P38-6"] = {"cv_macro_f1_shipped_only": round(base, 4), "cv_macro_f1_with_their_windows": round(mixed, 4),
                  "change": round(mixed - base, 4), "pass": (mixed - base) >= -0.02}
    # exploratory
    allX = np.vstack([np.array(r["feats"]) for r in usable])
    sd = Xs.std(axis=0) + 1e-9
    shift = (np.median(allX, axis=0) - np.median(Xs, axis=0)) / sd
    top = np.argsort(-np.abs(shift))[:5]
    S["exploratory_top_feature_shifts"] = [{"feature": FEATS[i], "shift_in_train_sd": round(float(shift[i]), 2)} for i in top]
    ood = [r for r in rows if r["set"] == "ood" and "error" not in r and r["role"] == "ood_eval" and r["n_windows"] > 0]
    S["exploratory_ood_eval_ungated_labels"] = dict(Counter(cap_pred(rf_ship, r["feats"]) for r in ood))
    S["exploratory_shipped_answers_by_class"] = {c: dict(Counter(str(r["shipped_answer"]) for r in known if r["label"] == c)) for c in CLASSES7}
    with open(os.path.join(RES, "captures.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rel", "label", "profile", "run", "windows", "stage", "in_dist_share", "ungated_label"])
        for r in rows:
            if "error" in r:
                continue
            w.writerow([r["rel"], r.get("label"), r.get("profile"), r.get("run"), r["n_windows"], r["stage"], r["in_dist"],
                        MAP.get(cap_pred(rf_ship, r["feats"]), cap_pred(rf_ship, r["feats"])) if r["n_windows"] else ""])
    json.dump(S, open(os.path.join(RES, "summary.json"), "w"), indent=1, default=str)
    print(json.dumps(S, indent=1, default=str))


if __name__ == "__main__":
    main()
