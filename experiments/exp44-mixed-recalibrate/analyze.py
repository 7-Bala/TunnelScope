"""EXP-44 scorer (pre-registered in PREREG.md, commit 23b179f). Writes results/summary.json and results/mixed_windows_candidate.npz.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp44-mixed-recalibrate/analyze.py

Single sessions: probabilities from the K4 recipe trained WITHOUT the session's own family. Mixed sessions (EXP-05/15 mux, all
lab-tgen): from K4 trained without lab-tgen. Detector = EXP-16's design. Lab D only ever tests. P44-5 uses out-of-fold flags,
because lab C and EXP-16 sessions are themselves training rows of the detector.
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "build" / "models"))
import corpus  # noqa: E402
import featurize  # noqa: E402
import features_v2  # noqa: E402
from tunnelscope.leakage import attacker as A  # noqa: E402
from tunnelscope.leakage import mixed as MX  # noqa: E402

featurize.register("v2", features_v2.v2)
_s = importlib.util.spec_from_file_location("exp42", ROOT / "experiments/exp42-generalise/analyze.py")
E42 = importlib.util.module_from_spec(_s); _s.loader.exec_module(E42)
RES = HERE / "results"


def mux_sessions():
    out = []
    for rel, tag in (("exp05", "EXP-05"), ("exp15/traffic", "EXP-15")):
        cap = ROOT / "testbed/captures" / rel
        seen = set()
        for row in csv.reader(open(cap / "manifest.csv")):
            if row[1] != "mux" or row[0] in seen:
                continue
            seen.add(row[0])
            t, o, s = [], [], []
            with gzip.open(cap / f"{row[0]}.pkts.csv.gz", "rt") as f:
                next(f)
                for line in f:
                    a, d, n = line.strip().split(",")
                    if n:
                        t.append(float(a)); o.append(d == "out"); s.append(int(n))
            out.append(corpus._mk("lab-tgen", f"{tag}:{row[0]}", "mixed", t, o, s))
    return out


def fit_k4(data, keep):
    X, y, w = data.train(keep, balanced=True)
    return RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, y, sample_weight=w)


def main():
    RES.mkdir(exist_ok=True)
    ss = corpus.load()
    data = E42.Data("v2", ss, aug=True)
    ok = [i for i, w in enumerate(data.w) if len(w) >= featurize.MIN_WINDOWS]
    mux = mux_sessions()
    mux_w = featurize.windows(mux, "v2")
    rows = []                       # (group, family, label, features)
    for fam in corpus.FAMILIES:
        te = [i for i in ok if ss[i].family == fam]
        if not te:
            continue
        m = fit_k4(data, [i for i in ok if ss[i].family != fam])
        for i in te:
            rows.append((ss[i].sid, fam, "single", MX.session_features(m.predict_proba(data.w[i]))))
        if fam == "lab-tgen":
            for s, w in zip(mux, mux_w):
                if len(w) >= featurize.MIN_WINDOWS:
                    rows.append((s.sid, "lab-tgen", "mixed", MX.session_features(m.predict_proba(w))))
        print(f"  probabilities for {fam}: {len(te)} singles", flush=True)
    G = np.array([r[0] for r in rows]); F = np.array([r[3] for r in rows]); L = np.array([r[2] for r in rows])
    fam_of = np.array([r[1] for r in rows])
    prob = np.zeros(len(rows))
    for tr, te in GroupKFold(5).split(F, L, G):
        d = RandomForestClassifier(n_estimators=300, random_state=0, min_samples_leaf=2, class_weight="balanced").fit(F[tr], L[tr])
        prob[te] = d.predict_proba(F[te])[:, list(d.classes_).index("mixed")]
    by_tau, chosen = [], None
    for tau in np.round(np.arange(0.20, 0.81, 0.05), 2):
        flag = prob >= tau
        row = {"tau": float(tau), "mixed_caught": round(float(flag[L == "mixed"].mean()), 4),
               "single_wrongly_flagged": round(float(flag[L == "single"].mean()), 4)}
        by_tau.append(row)
        if chosen is None and row["mixed_caught"] >= 0.80 and row["single_wrongly_flagged"] <= 0.10:
            chosen = row
    S = {"n_rows": len(rows), "n_mixed": int((L == "mixed").sum()), "by_tau": by_tau, "chosen": chosen,
         "P44-1": {"chosen": chosen, "pass": chosen is not None}}
    if chosen is None:
        json.dump(S, open(RES / "summary.json", "w"), indent=1); print(json.dumps(S, indent=1)); return
    tau = chosen["tau"]
    oof = {f: f"{int((prob[(fam_of == f) & (L == 'single')] >= tau).sum())}/{int(((fam_of == f) & (L == 'single')).sum())}"
           for f in corpus.FAMILIES if ((fam_of == f) & (L == "single")).any()}
    S["oof_single_flags_by_family"] = oof
    lc = [i for i, r in enumerate(rows) if r[1] == "lab-c" and r[2] == "single"]
    ra = [i for i, r in enumerate(rows) if r[0].startswith("EXP-16:exp16-real") and r[2] == "single"]
    S["P44-5"] = {"lab_c_oof_flags": int((prob[lc] >= tau).sum()), "lab_c_n": len(lc),
                  "exp16_real_oof_flags": int((prob[ra] >= tau).sum()), "exp16_real_n": len(ra),
                  "pass": int((prob[lc] >= tau).sum()) <= 2 and int((prob[ra] >= tau).sum()) <= 2}
    cand = RES / "mixed_windows_candidate.npz"
    np.savez_compressed(cand, X=F, y=L, tau=np.array(tau))
    # product path with the candidate detector
    MX.DATA = str(cand); MX._model.cache_clear()
    flagged = 0
    for s in mux:
        if not s.sid.startswith("EXP-05"):
            continue
        r = A.assess_exposure([{"t": float(t), "src": "o" if o else "i", "ip_len": int(n)} for t, o, n in zip(s.t, s.out, s.size)], "o")
        flagged += int(r["status"] != "measured" or not r["traffic"]["answered"])
    n05 = sum(1 for s in mux if s.sid.startswith("EXP-05"))
    S["P44-2"] = {"exp05_mixed_not_answered": flagged, "n": n05, "pass": flagged / n05 >= 0.80}
    spec = importlib.util.spec_from_file_location("e43", ROOT / "experiments/exp43-lab-d/analyze.py")
    e43 = importlib.util.module_from_spec(spec); spec.loader.exec_module(e43)
    ans = right = 0
    for d in e43.lab_d():
        r = A.assess_exposure([{"t": float(t), "src": "o" if o else "i", "ip_len": int(n)} for t, o, n in zip(d["t"], d["out"], d["size"])], "o")
        if r["status"] == "measured" and r["traffic"]["answered"]:
            ans += 1; right += int(r["traffic"]["class"] == d["label"])
    S["P44-3"] = {"lab_d_answered": ans, "n": 32, "pass": ans >= 20}
    S["P44-4"] = {"lab_d_correct": right, "answered": ans, "accuracy": round(right / ans, 4) if ans else None,
                  "pass": bool(ans) and right / ans >= 0.90}
    S["ship"] = bool(S["P44-1"]["pass"] and S["P44-2"]["pass"] and S["P44-4"]["pass"])
    json.dump(S, open(RES / "summary.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in S.items() if k != "by_tau"}, indent=1))


if __name__ == "__main__":
    main()
