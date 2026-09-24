#!/usr/bin/env python3
"""EXP-19 analysis (PREREG.md). Reads the converted VNAT packets (convert_vnat.py output, kept
outside the repo) and our own lab windows, answers Q1-Q4, writes results/summary.json and, only if
the pre-registered ship bar holds, results/vnat_windows.npz for the model build.

  .venv/bin/python experiments/exp19-real-public-traffic/analyze.py [~/Datasets/vnat/converted/vnat_vpn_packets.npz]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "build/models"))
from make_traffic_data import load  # noqa: E402
from tunnelscope.leakage.attacker import MIN_WINDOWS, window_features  # noqa: E402

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "Datasets/vnat/converted/vnat_vpn_packets.npz"
SEED, CAP = 19, 60
VNAT_CLASSES = ["video", "voip", "messaging", "interactive", "bulk"]
REAL_ARMS = ("real-apps", "wan-real-apps", "lossy-real-apps")
RF = dict(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2)   # the shipped settings


def macro_f1(y, p, labels):
    return round(float(f1_score(y, p, labels=labels, average="macro", zero_division=0)), 4)


def vnat_windows():
    d = np.load(SRC, allow_pickle=False)
    rng = np.random.default_rng(SEED)
    X, y, grp, conn_used = [], [], [], 0
    off = d["offsets"]
    for i in range(len(d["label"])):
        a, b = off[i], off[i + 1]
        pk = list(zip(d["t"][a:b].tolist(), np.where(d["out"][a:b], "out", "in").tolist(), d["size"][a:b].tolist()))
        w = window_features(pk)
        if len(w) < MIN_WINDOWS:
            continue
        if len(w) > CAP:
            w = [w[j] for j in sorted(rng.choice(len(w), CAP, replace=False))]
        conn_used += 1
        X += w
        y += [str(d["label"][i])] * len(w)
        grp += [str(d["capture"][i])] * len(w)
    return np.array(X, float), np.array(y), np.array(grp), conn_used


def main() -> None:
    out = {"source": str(SRC), "seed": SEED, "cap_per_connection": CAP}
    Xv, yv, gv, nconn = vnat_windows()
    out["vnat"] = {"windows": int(len(yv)), "connections": nconn, "capture_files": int(len(set(gv))),
                   "per_class_windows": {c: int((yv == c).sum()) for c in VNAT_CLASSES},
                   "per_class_files": {c: int(len(set(gv[yv == c]))) for c in VNAT_CLASSES}}
    X, y, arm, rep, sess, src = load()

    # Q1: the shipped (lab-trained) model on real VNAT traffic
    lab = RandomForestClassifier(**RF).fit(X, y)
    out["Q1_lab_model_on_vnat"] = macro_f1(yv, lab.predict(Xv), VNAT_CLASSES)

    # Q2: real-only model, grouped by capture file
    q2 = []
    for tr, te in GroupKFold(n_splits=5).split(Xv, yv, gv):
        m = RandomForestClassifier(**RF).fit(Xv[tr], yv[tr])
        q2.append(macro_f1(yv[te], m.predict(Xv[te]), VNAT_CLASSES))
    out["Q2_vnat_only_grouped_cv"] = {"folds": q2, "mean": round(float(np.mean(q2)), 4)}

    # Q3: real OpenVPN -> our IPsec real-application sessions (5 overlapping classes)
    vn = RandomForestClassifier(**RF).fit(Xv, yv)
    mask = np.isin(arm, REAL_ARMS) & np.isin(y, VNAT_CLASSES)
    out["Q3_vnat_model_on_our_ipsec_real_apps"] = {"windows": int(mask.sum()),
                                                   "macro_f1": macro_f1(y[mask], vn.predict(X[mask]), VNAT_CLASSES)}

    # Q4a: combined, VNAT held out by capture file, all lab data always in training
    q4a = []
    for tr, te in GroupKFold(n_splits=5).split(Xv, yv, gv):
        m = RandomForestClassifier(**RF).fit(np.vstack([X, Xv[tr]]), np.concatenate([y, yv[tr]]))
        q4a.append(macro_f1(yv[te], m.predict(Xv[te]), VNAT_CLASSES))
    out["Q4a_combined_on_heldout_vnat"] = {"folds": q4a, "mean": round(float(np.mean(q4a)), 4)}

    # Q4b: our lab real-app sessions, leave one repetition out, with and without VNAT in training
    real = np.isin(arm, REAL_ARMS[:1])             # EXP-16 real applications, as in EXP-16
    classes = sorted(set(y[real]))
    with_v, without = [], []
    for r in sorted(set(rep[real])):
        te = real & (rep == r)
        tr = ~te
        base = RandomForestClassifier(**RF).fit(X[tr], y[tr])
        comb = RandomForestClassifier(**RF).fit(np.vstack([X[tr], Xv]), np.concatenate([y[tr], yv]))
        without.append(macro_f1(y[te], base.predict(X[te]), classes))
        with_v.append(macro_f1(y[te], comb.predict(X[te]), classes))
    out["Q4b_lab_real_apps_loro"] = {"without_vnat": {"folds": without, "mean": round(float(np.mean(without)), 4)},
                                     "with_vnat": {"folds": with_v, "mean": round(float(np.mean(with_v)), 4)}}

    # ship bar (PREREG)
    q1, q4a_m = out["Q1_lab_model_on_vnat"], out["Q4a_combined_on_heldout_vnat"]["mean"]
    q4b = out["Q4b_lab_real_apps_loro"]
    npz = HERE / "results" / "vnat_windows.npz"
    bar = {"q4a_ge_0_80": q4a_m >= 0.80, "q4a_beats_q1_by_0_10": q4a_m >= q1 + 0.10,
           "q4b_not_worse_than_0_02": q4b["with_vnat"]["mean"] >= q4b["without_vnat"]["mean"] - 0.02}
    ship = all(bar.values())
    if ship:
        npz.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(npz, X=Xv.astype(np.float32), y=yv, group=gv)
        bar["under_5_mb"] = npz.stat().st_size < 5 * 1024 * 1024
        ship = bar["under_5_mb"]
        if not ship:
            npz.unlink()
    out["ship_bar"] = bar
    out["ship"] = ship
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "summary.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
