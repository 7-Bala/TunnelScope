"""EXP-41 scorer (pre-registered in PREREG.md, commit a4521a2 + erratum 3b9a94c). Writes results/summary.json and results/captures.csv.

    .venv/bin/python experiments/exp41-lab-c/analyze.py --lab-a DIR/ipsec-pcap-lab --lab-b DIR/labB --work DIR/scratch

Lab C is read from the committed per-packet tables (testbed/captures/exp41/*.pkts.csv.gz). Labs A and B (other teams, kept outside the
repository) go through the product path (build_records). Models are the shipped forest and gates retrained on other windows by pointing
`attacker.DATA` at a temporary .npz in --work; no shipped file is edited.
"""
import argparse
import csv
import glob
import gzip
import json
import os
import pickle
import re
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
TABLES = os.path.join(REPO, "testbed", "captures", "exp41")
RES = os.path.join(HERE, "results")
CLASSES_C = ["bulk", "email", "icmp", "interactive", "messaging", "video", "voip", "web"]
CLASSES_A = ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"]
TO_SHIPPED = {"file_transfer": "bulk"}
TO_LAB_A = {"bulk": "file_transfer"}
MIN_WINDOWS = 3


def one(path):                       # labs A and B: the product path
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


def table_capture(path):             # lab C: a committed per-packet table
    from tunnelscope.leakage import attacker as A
    rows = []
    with gzip.open(path, "rt") as f:
        next(f)
        for line in f:
            t, d, n = line.strip().split(",")
            rows.append((float(t), d, int(n)))
    esp = [{"t": t, "src": d, "ip_len": n} for t, d, n in rows]
    return {"feats": A.window_features([(t, d, n) for t, d, n in rows]), "esp": esp, "out_src": "out"}


def f1(y, p, labels, avg="macro"):
    from sklearn.metrics import f1_score
    return float(f1_score(y, p, labels=labels, average=avg, zero_division=0))


def per_class(y, p, labels):
    from sklearn.metrics import f1_score
    return {c: round(float(v), 3) for c, v in zip(labels, f1_score(y, p, labels=labels, average=None, zero_division=0))}


def use_training(A, X, y, path):
    np.savez(path, X=X, y=y)
    A.DATA = path
    A._model.cache_clear()


def evaluate(A, caps, labels, tag, rename=lambda s: s):
    rf = A._model()[0]
    use = [c for c in caps if c["n_windows"] > 0]
    yp = []
    for c in use:
        P = rf.predict_proba(np.array(c["feats"]))
        yp.append(rename(str(rf.classes_[int(P.mean(axis=0).argmax())])))
    y = [c["label"] for c in use]
    out = {"model": tag, "captures_with_windows": len(use), "ungated_macro_f1": round(f1(y, yp, labels), 4),
           "ungated_accuracy": round(float(np.mean([a == b for a, b in zip(y, yp)])), 4), "per_class_f1": per_class(y, yp, labels)}
    elig = [c for c in caps if c["n_windows"] >= MIN_WINDOWS]
    ans = right = 0
    stages = Counter()
    for c in elig:
        r = A.assess_exposure(c["esp"], c["out_src"])
        if r["status"] != "measured":
            stages[r["status"]] += 1
        elif r["traffic"]["answered"]:
            ans += 1
            right += int(rename(r["traffic"]["class"]) == c["label"])
            stages["answered"] += 1
        else:
            stages["abstained"] += 1
    out.update({"eligible_ge3_windows": len(elig), "answered": ans, "coverage": round(ans / len(elig), 4) if elig else None,
                "accuracy_among_answered": round(right / ans, 4) if ans else None, "stages": dict(stages)})
    return out


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
    from tunnelscope.leakage import attacker as A
    shipped = A.DATA

    meta_a = {r["pcap_path"]: r for r in csv.DictReader(open(os.path.join(a.lab_a, "metadata.csv")))}
    man_b = {r["filename"]: r for r in csv.DictReader(open(os.path.join(a.lab_b, "manifest.csv")))}
    files_a = sorted(glob.glob(os.path.join(a.lab_a, "pcaps", "known", "**", "*.pcap"), recursive=True))
    files_b = sorted(p for p in glob.glob(os.path.join(a.lab_b, "real_captures", "*.pcap")) if not p.endswith("__handshake.pcap"))
    cache = os.path.join(a.work, "ab_windows.pkl")
    if os.path.exists(cache):
        res = pickle.load(open(cache, "rb"))
    else:
        with ProcessPoolExecutor(4) as ex:
            res = list(ex.map(one, files_a + files_b))
        pickle.dump(res, open(cache, "wb"))
    labA, labB, errors = [], [], []
    for p, r in zip(files_a + files_b, res):
        if "error" in r:
            errors.append(os.path.basename(p)); continue
        r["n_windows"] = len(r["feats"])
        if p in files_a:
            r["label"] = meta_a[os.path.relpath(p, a.lab_a)]["canonical_label"]; labA.append(r)
        else:
            r["label"] = man_b[os.path.basename(p)]["traffic_class"]; labB.append(r)
    labC = []
    for p in sorted(glob.glob(os.path.join(TABLES, "exp41-*.pkts.csv.gz"))):
        m = re.match(r"exp41-(gcm|cbc)-(\w+)-rep(\d)\.pkts\.csv\.gz", os.path.basename(p))
        r = table_capture(p)
        r.update({"config": m[1], "label": m[2], "rep": int(m[3]), "n_windows": len(r["feats"]), "rel": os.path.basename(p)})
        labC.append(r)
    S = {"errors": errors, "n_lab_a": len(labA), "n_lab_b": len(labB), "n_lab_c": len(labC)}

    d = np.load(shipped, allow_pickle=False)
    Xs, ys = d["X"], d["y"]

    def win(caps, rename=lambda s: s):
        X = [f for c in caps for f in c["feats"]]
        y = [rename(c["label"]) for c in caps for _ in c["feats"]]
        return np.array(X), np.array(y)

    XA, yA = win(labA, lambda s: TO_SHIPPED.get(s, s))
    XB, yB = win(labB, lambda s: TO_SHIPPED.get(s, s))
    XC, yC = win(labC)
    tmp = os.path.join(a.work, "train.npz")

    def fit(X, y):
        return RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, y)

    A.DATA = shipped; A._model.cache_clear()
    m0 = evaluate(A, labC, CLASSES_C, "M0 shipped")
    m0_on_a = evaluate(A, labA, CLASSES_A, "M0 shipped", rename=lambda s: TO_LAB_A.get(s, s))
    use_training(A, np.vstack([Xs, XA]), np.concatenate([ys, yA]), tmp)
    m1 = evaluate(A, labC, CLASSES_C, "M1 shipped+A")
    use_training(A, np.vstack([Xs, XA, XB]), np.concatenate([ys, yA, yB]), tmp)
    m3 = evaluate(A, labC, CLASSES_C, "M3 shipped+A+B")
    m3_a = evaluate(A, labA, CLASSES_A, "M3 (has seen A)", rename=lambda s: TO_LAB_A.get(s, s))
    use_training(A, np.vstack([Xs, XC]), np.concatenate([ys, yC]), tmp)
    m4_a = evaluate(A, labA, CLASSES_A, "M4 shipped+C", rename=lambda s: TO_LAB_A.get(s, s))
    A.DATA = shipped; A._model.cache_clear()

    S["M0_on_C"], S["M1_on_C"], S["M3_on_C"], S["M0_on_A"], S["M4_on_A"] = m0, m1, m3, m0_on_a, m4_a
    S["P41-1"] = {"m0_macro_f1_on_C": m0["ungated_macro_f1"], "pass": m0["ungated_macro_f1"] < 0.70}
    tr = [c for c in labC if c["rep"] == 1 and c["n_windows"]]
    te = [c for c in labC if c["rep"] == 2 and c["n_windows"]]
    Xt, yt = win(tr)
    rf_c = fit(Xt, yt)
    yp = []
    for c in te:
        P = rf_c.predict_proba(np.array(c["feats"]))
        yp.append(str(rf_c.classes_[int(P.mean(axis=0).argmax())]))
    f_c = f1([c["label"] for c in te], yp, CLASSES_C)
    S["P41-2"] = {"train_captures": len(tr), "test_captures": len(te), "macro_f1": round(f_c, 4), "per_class_f1": per_class([c["label"] for c in te], yp, CLASSES_C), "pass": f_c >= 0.90}
    S["P41-3"] = {"m1": m1["ungated_macro_f1"], "m0": m0["ungated_macro_f1"], "gain": round(m1["ungated_macro_f1"] - m0["ungated_macro_f1"], 4),
                  "pass": m1["ungated_macro_f1"] - m0["ungated_macro_f1"] >= 0.10}
    S["P41-4"] = {"m3": m3["ungated_macro_f1"], "m0": m0["ungated_macro_f1"], "gain": round(m3["ungated_macro_f1"] - m0["ungated_macro_f1"], 4),
                  "pass": m3["ungated_macro_f1"] - m0["ungated_macro_f1"] >= 0.10}
    S["P41-5"] = {"coverage": m3["coverage"], "accuracy_among_answered": m3["accuracy_among_answered"],
                  "pass": bool(m3["coverage"] is not None and m3["coverage"] >= 0.5 and m3["accuracy_among_answered"] is not None and m3["accuracy_among_answered"] >= 0.90)}
    S["P41-6"] = {"m4_macro_f1_on_A": m4_a["ungated_macro_f1"], "bar": 0.362, "pass": m4_a["ungated_macro_f1"] >= 0.362}

    def cv(add):
        preds = np.empty(len(ys), dtype=object)
        for tr_i, te_i in GroupKFold(n_splits=5).split(Xs, ys, d["session"]):
            X_, y_ = Xs[tr_i], ys[tr_i]
            if add:
                X_, y_ = np.vstack([X_, XA, XB, XC]), np.concatenate([y_, yA, yB, yC])
            preds[te_i] = fit(X_, y_).predict(Xs[te_i])
        return f1(ys, preds.astype(str), sorted(set(ys.tolist())))
    base, mixed = cv(False), cv(True)
    S["P41-7"] = {"cv_shipped_only": round(base, 4), "cv_with_A_B_C": round(mixed, 4), "change": round(mixed - base, 4), "pass": (mixed - base) >= -0.02}
    S["exploratory_M3_has_seen_A"] = {k: m3_a[k] for k in ("ungated_macro_f1", "coverage", "accuracy_among_answered")}
    S["exploratory_by_config"] = {cfg: {"M0": evaluate(A, [c for c in labC if c["config"] == cfg], CLASSES_C, "M0")["ungated_macro_f1"]} for cfg in ("gcm", "cbc")}
    S["exploratory_windows_per_class"] = {c: sorted({x["n_windows"] for x in labC if x["label"] == c}) for c in CLASSES_C}
    with open(os.path.join(RES, "captures.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["lab", "rel", "label", "windows"])
        for c in labC:
            w.writerow(["C", c["rel"], c["label"], c["n_windows"]])
    json.dump(S, open(os.path.join(RES, "summary.json"), "w"), indent=1, default=str)
    print(json.dumps({k: S[k] for k in S if k.startswith("P41")}, indent=1))


if __name__ == "__main__":
    main()
