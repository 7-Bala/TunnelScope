"""EXP-39 scorer (pre-registered in PREREG.md, commit d32724e). Writes results/summary.json and results/captures.csv.

    .venv/bin/python experiments/exp39-two-lab-transfer/analyze.py --lab-a DIR/ipsec-pcap-lab --lab-b DIR/labB --work DIR/scratch

No shipped file is edited. Models are the shipped forest and gates retrained on other training windows by pointing
`attacker.DATA` at a temporary .npz in --work and clearing the model cache; window_features, the out-of-distribution
gate and the abstain rules are the shipped code. Everything derived from the other teams' captures stays in --work.
"""
import argparse
import csv
import glob
import json
import os
import pickle
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "results")
MAP = {"bulk": "file_transfer"}
TO_SHIPPED = {"file_transfer": "bulk"}
CLASSES_A = ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"]
CLASSES_B = ["file_transfer", "icmp", "video", "voip", "web"]
MIN_WINDOWS = 3


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
    small = [{"t": p["t"], "src": p["src"], "ip_len": p["ip_len"]} for p in esp if p.get("ip_len")]
    return {"path": path, "feats": feats, "esp": small, "out_src": out_src}


def macro_f1(y, p, labels):
    from sklearn.metrics import f1_score
    return float(f1_score(y, p, labels=labels, average="macro", zero_division=0))


def per_class_f1(y, p, labels):
    from sklearn.metrics import f1_score
    return {c: round(float(v), 3) for c, v in zip(labels, f1_score(y, p, labels=labels, average=None, zero_division=0))}


def use_training(A, X, y, path):
    np.savez(path, X=X, y=y)
    A.DATA = path
    A._model.cache_clear()


def evaluate(A, caps, labels, tag):
    rf = A._model()[0]
    use = [c for c in caps if c["n_windows"] > 0]
    yp = []
    for c in use:
        P = rf.predict_proba(np.array(c["feats"]))
        yp.append(MAP.get(str(rf.classes_[int(P.mean(axis=0).argmax())]), str(rf.classes_[int(P.mean(axis=0).argmax())])))
    y = [c["label"] for c in use]
    out = {"model": tag, "captures_with_windows": len(use), "ungated_macro_f1": round(macro_f1(y, yp, labels), 4),
           "ungated_accuracy": round(float(np.mean([a == b for a, b in zip(y, yp)])), 4), "ungated_per_class_f1": per_class_f1(y, yp, labels)}
    elig = [c for c in caps if c["n_windows"] >= MIN_WINDOWS]
    ans = right = 0
    stages = Counter()
    for c in elig:
        r = A.assess_exposure(c["esp"], c["out_src"])
        if r["status"] != "measured":
            stages[r["status"]] += 1
            continue
        if r["traffic"]["answered"]:
            ans += 1
            right += int(MAP.get(r["traffic"]["class"], r["traffic"]["class"]) == c["label"])
            stages["answered"] += 1
        else:
            stages["abstained"] += 1
    out.update({"eligible_ge3_windows": len(elig), "fewer_than_3_windows": len(caps) - len(elig), "answered": ans,
                "coverage": round(ans / len(elig), 4) if elig else None,
                "accuracy_among_answered": round(right / ans, 4) if ans else None, "stages": dict(stages)})
    return out, yp, y, use


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab-a", required=True)
    ap.add_argument("--lab-b", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    os.makedirs(RES, exist_ok=True)
    os.makedirs(a.work, exist_ok=True)
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import GroupKFold
    from sklearn.metrics import f1_score
    from tunnelscope.leakage import attacker as A
    shipped_data = A.DATA

    meta_a = {r["pcap_path"]: r for r in csv.DictReader(open(os.path.join(a.lab_a, "metadata.csv")))}
    man_b = {r["filename"]: r for r in csv.DictReader(open(os.path.join(a.lab_b, "manifest.csv")))} if os.path.exists(os.path.join(a.lab_b, "manifest.csv")) else {}
    files_a = sorted(glob.glob(os.path.join(a.lab_a, "pcaps", "known", "**", "*.pcap"), recursive=True))
    files_b = sorted(p for p in glob.glob(os.path.join(a.lab_b, "real_captures", "*.pcap")) if not p.endswith("__handshake.pcap"))
    cache = os.path.join(a.work, "windows.pkl")
    if os.path.exists(cache):
        res = pickle.load(open(cache, "rb"))
    else:
        with ProcessPoolExecutor(4) as ex:
            res = list(ex.map(one, files_a + files_b))
        pickle.dump(res, open(cache, "wb"))
    labA, labB, errors = [], [], []
    for p, r in zip(files_a + files_b, res):
        if "error" in r:
            errors.append(os.path.relpath(p, a.lab_a if p in files_a else a.lab_b))
            continue
        if p in files_a:
            m = meta_a[os.path.relpath(p, a.lab_a)]
            labA.append({**r, "label": m["canonical_label"], "run": m["run_id"], "profile": m["profile_id"], "n_windows": len(r["feats"]), "rel": os.path.relpath(p, a.lab_a)})
        else:
            m = man_b[os.path.basename(p)]
            labB.append({**r, "label": m["traffic_class"], "n_windows": len(r["feats"]), "rel": os.path.basename(p)})
    S = {"errors": errors, "n_lab_a": len(labA), "n_lab_b": len(labB)}

    d = np.load(shipped_data, allow_pickle=False)
    Xs, ys = d["X"], d["y"]

    def win(caps):
        X = [f for c in caps for f in c["feats"]]
        y = [TO_SHIPPED.get(c["label"], c["label"]) for c in caps for _ in c["feats"]]
        return np.array(X), np.array(y)

    XA, yA = win(labA)
    XB, yB = win(labB)
    tmp = os.path.join(a.work, "train.npz")
    rows = []
    # M0
    A.DATA = shipped_data
    A._model.cache_clear()
    m0b, _, _, _ = evaluate(A, labB, CLASSES_B, "M0 shipped")
    m0a, _, _, _ = evaluate(A, labA, CLASSES_A, "M0 shipped")
    # M1: shipped + A, test on B
    use_training(A, np.vstack([Xs, XA]), np.concatenate([ys, yA]), tmp)
    m1b, yp1, y1, use1 = evaluate(A, labB, CLASSES_B, "M1 shipped+A")
    # M2: shipped + B, test on A
    use_training(A, np.vstack([Xs, XB]), np.concatenate([ys, yB]), tmp)
    m2a, yp2, y2, use2 = evaluate(A, labA, CLASSES_A, "M2 shipped+B")
    # M3 exploratory
    use_training(A, np.vstack([Xs, XA, XB]), np.concatenate([ys, yA, yB]), tmp)
    m3a, _, _, _ = evaluate(A, labA, CLASSES_A, "M3 shipped+A+B (has seen A)")
    m3b, _, _, _ = evaluate(A, labB, CLASSES_B, "M3 shipped+A+B (has seen B)")
    A.DATA = shipped_data
    A._model.cache_clear()

    S["M0_on_B"], S["M0_on_A"], S["M1_on_B"], S["M2_on_A"] = m0b, m0a, m1b, m2a
    S["P39-1"] = {"m0_macro_f1_on_B": m0b["ungated_macro_f1"], "pass": m0b["ungated_macro_f1"] < 0.60}
    f1b = m1b["ungated_macro_f1"]
    S["P39-2"] = {"m1_macro_f1_on_B": f1b, "m0": m0b["ungated_macro_f1"], "gain": round(f1b - m0b["ungated_macro_f1"], 4),
                  "pass": f1b >= 0.60 and f1b - m0b["ungated_macro_f1"] >= 0.15}
    S["P39-3"] = {"coverage": m1b["coverage"], "accuracy_among_answered": m1b["accuracy_among_answered"],
                  "pass": bool(m1b["coverage"] is not None and m1b["coverage"] >= 0.5 and m1b["accuracy_among_answered"] is not None and m1b["accuracy_among_answered"] >= 0.90)}
    f1a = m2a["ungated_macro_f1"]
    S["P39-4"] = {"m2_macro_f1_on_A": f1a, "m0_on_A": m0a["ungated_macro_f1"], "gain_over_0.262": round(f1a - 0.262, 4),
                  "pass": f1a >= 0.60 and f1a >= 0.262 + 0.15}
    S["P39-5"] = {"coverage": m2a["coverage"], "accuracy_among_answered": m2a["accuracy_among_answered"],
                  "pass": bool(m2a["coverage"] is not None and m2a["coverage"] >= 0.5 and m2a["accuracy_among_answered"] is not None and m2a["accuracy_among_answered"] >= 0.90)}

    def cv(add):
        preds = np.empty(len(ys), dtype=object)
        for tr_i, te_i in GroupKFold(n_splits=5).split(Xs, ys, d["session"]):
            Xt, Yt = Xs[tr_i], ys[tr_i]
            if add:
                Xt, Yt = np.vstack([Xt, XA, XB]), np.concatenate([Yt, yA, yB])
            preds[te_i] = RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(Xt, Yt).predict(Xs[te_i])
        return float(f1_score(ys, preds.astype(str), average="macro", zero_division=0))
    base, mixed = cv(False), cv(True)
    S["P39-6"] = {"cv_shipped_only": round(base, 4), "cv_with_both_labs": round(mixed, 4), "change": round(mixed - base, 4), "pass": (mixed - base) >= -0.02}
    # exploratory
    S["exploratory_M3"] = {"on_A": m3a, "on_B": m3b}
    nov = [(c, p) for c, p in zip(use1, yp1) if c["label"] != "voip"]
    S["exploratory_M1_on_B_without_voip"] = round(macro_f1([c["label"] for c, _ in nov], [p for _, p in nov], [x for x in CLASSES_B if x != "voip"]), 4)
    S["exploratory_B_short_captures_by_class"] = {c: sum(1 for x in labB if x["label"] == c and x["n_windows"] < MIN_WINDOWS) for c in CLASSES_B}
    allB = np.vstack([np.array(c["feats"]) for c in labB if c["feats"]])
    sd = Xs.std(axis=0) + 1e-9
    sh = (np.median(allB, axis=0) - np.median(Xs, axis=0)) / sd
    names = [f"{dd}_{n}" for dd in ("out", "in") for n in ("count", "bytes", "mean", "std", "min", "max", "log_iat_mean", "log_iat_std", "log_iat_median", "frac_iat_lt_1ms", "h0_128", "h128_256", "h256_512", "h512_1024", "h1024_1600")] + ["out_share"]
    S["exploratory_B_top_shifts"] = [{"feature": names[i], "shift_in_train_sd": round(float(sh[i]), 2)} for i in np.argsort(-np.abs(sh))[:5]]
    with open(os.path.join(RES, "captures.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["lab", "rel", "label", "windows"])
        for c in labA:
            w.writerow(["A", c["rel"], c["label"], c["n_windows"]])
        for c in labB:
            w.writerow(["B", c["rel"], c["label"], c["n_windows"]])
    json.dump(S, open(os.path.join(RES, "summary.json"), "w"), indent=1, default=str)
    print(json.dumps({k: S[k] for k in S if k.startswith("P39")}, indent=1))


if __name__ == "__main__":
    main()
