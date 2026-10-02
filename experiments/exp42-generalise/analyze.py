"""EXP-42 scorer (pre-registered in PREREG.md, commit bad8196). Writes results/summary.json.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp42-generalise/analyze.py

Candidates K0-K6 exactly as the PREREG table. Leave-one-family-out: train on the other seven families, predict each held-out
session (argmax of the mean window probability), session-level macro-F1 over that family's classes. Augmented copies are
TRAINING data only and always follow their source session: a held-out family's or test session's copies never train.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "build" / "models"))
import corpus  # noqa: E402
import featurize  # noqa: E402
import features_v2  # noqa: E402

featurize.register("v2", features_v2.v2)
RES = HERE / "results"


def rf():
    return RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2)


def et():
    return ExtraTreesClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2)


def hgb():
    return HistGradientBoostingClassifier(random_state=0)


CANDIDATES = {
    "K0": dict(version="v1", balanced=False, aug=False, model=rf),
    "K1": dict(version="v1", balanced=True, aug=False, model=rf),
    "K2": dict(version="v1", balanced=True, aug=True, model=rf),
    "K3": dict(version="v2", balanced=True, aug=False, model=rf),
    "K4": dict(version="v2", balanced=True, aug=True, model=rf),
    "K5": dict(version="v2", balanced=True, aug=True, model=et),
    "K6": dict(version="v2", balanced=True, aug=True, model=hgb),
}
N_COPIES = 2


def augmented(sessions):
    """Two seeded copies per session: constant size offset in [-40, +80] bytes, time scale in [0.8, 1.25]."""
    out, src = [], []
    for i, s in enumerate(sessions):
        for k in range(N_COPIES):
            rng = np.random.default_rng(int(hashlib.sha256(f"{s.sid}#{k}".encode()).hexdigest()[:8], 16))
            off, scale = int(rng.integers(-40, 81)), float(rng.uniform(0.8, 1.25))
            t = s.t[0] + (s.t - s.t[0]) * scale
            out.append(corpus.Session(s.family, f"{s.sid}#aug{k}", s.label, t, s.out, np.maximum(28, s.size + off)))
            src.append(i)
    return out, src


def weights(fams, labels):
    """Every family equal total weight; within a family, every class equal."""
    fams, labels = np.asarray(fams), np.asarray(labels)
    w = np.zeros(len(labels))
    F = len(set(fams))
    for f in set(fams):
        mf = fams == f
        C = len(set(labels[mf]))
        for c in set(labels[mf]):
            m = mf & (labels == c)
            w[m] = 1.0 / (F * C * m.sum())
    return w * len(labels)


def macro(y, p):
    return float(f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0))


class Data:
    def __init__(self, version, sessions, aug):
        self.s = sessions
        self.w = featurize.windows(sessions, version)
        self.aug_s, self.aug_src = (augmented(sessions) if aug else ([], []))
        self.aug_w = featurize.windows(self.aug_s, version) if aug else []

    def train(self, keep_idx, balanced):
        keep = set(keep_idx)
        X, y, f = [], [], []
        for i in keep_idx:
            if len(self.w[i]) >= featurize.MIN_WINDOWS:
                X.append(self.w[i]); y += [self.s[i].label] * len(self.w[i]); f += [self.s[i].family] * len(self.w[i])
        for j, i in enumerate(self.aug_src):
            if i in keep and len(self.aug_w[j]) >= featurize.MIN_WINDOWS:
                X.append(self.aug_w[j]); y += [self.s[i].label] * len(self.aug_w[j]); f += [self.s[i].family] * len(self.aug_w[j])
        X = np.vstack(X)
        return X, np.array(y), (weights(f, y) if balanced else None)


def fit(spec, X, y, w):
    m = spec["model"]()
    return m.fit(X, y, sample_weight=w) if w is not None else m.fit(X, y)


def predict_sessions(m, data, idx):
    ys, ps = [], []
    for i in idx:
        P = m.predict_proba(data.w[i])
        ys.append(data.s[i].label); ps.append(str(m.classes_[int(P.mean(axis=0).argmax())]))
    return ys, ps


def run_candidate(name, spec, sessions):
    data = Data(spec["version"], sessions, spec["aug"])
    ok = [i for i, w in enumerate(data.w) if len(w) >= featurize.MIN_WINDOWS]
    fams = [f for f in corpus.FAMILIES if any(sessions[i].family == f for i in ok)]
    lofo = {}
    for f in fams:
        tr = [i for i in ok if sessions[i].family != f]
        te = [i for i in ok if sessions[i].family == f]
        m = fit(spec, *data.train(tr, spec["balanced"]))
        a, b = predict_sessions(m, data, te)
        lofo[f] = {"macro_f1": round(macro(a, b), 4), "accuracy": round(float(np.mean([u == v for u, v in zip(a, b)])), 4),
                   "sessions": len(te),
                   "per_class_f1": {c: round(float(v), 3) for c, v in zip(sorted(set(a)), f1_score(a, b, labels=sorted(set(a)), average=None, zero_division=0))}}
        print(f"  {name} {f:14} {lofo[f]['macro_f1']}", flush=True)
    ys, ps = [], []
    g = np.arange(len(ok))
    for tr, te in GroupKFold(5).split(g, g, g):
        m = fit(spec, *data.train([ok[j] for j in tr], spec["balanced"]))
        a, b = predict_sessions(m, data, [ok[j] for j in te]); ys += a; ps += b
    vals = [v["macro_f1"] for v in lofo.values()]
    return {"lofo": lofo, "lofo_mean": round(float(np.mean(vals)), 4), "lofo_worst": round(float(np.min(vals)), 4),
            "grouped_by_session": round(macro(ys, ps), 4), "scored_sessions": len(ok),
            "insufficient": dict(Counter(sessions[i].family for i, w in enumerate(data.w) if len(w) < featurize.MIN_WINDOWS))}


def select(R):
    k0 = R["K0"]
    eligible = [k for k in CANDIDATES if R[k]["lofo_worst"] >= k0["lofo_worst"] - 0.05
                and R[k]["grouped_by_session"] >= k0["grouped_by_session"] - 0.02]
    best = max(eligible, key=lambda k: R[k]["lofo_mean"])
    for k in CANDIDATES:                          # the simplest within 0.01 of the best
        if k in eligible and R[k]["lofo_mean"] >= R[best]["lofo_mean"] - 0.01:
            return k, eligible
    return best, eligible


def main():
    RES.mkdir(exist_ok=True)
    sessions = corpus.load()
    R = {}
    for name, spec in CANDIDATES.items():
        print(f"== {name}", flush=True)
        R[name] = run_candidate(name, spec, sessions)
        json.dump(R, open(RES / "partial.json", "w"), indent=1)
    chosen, eligible = select(R)
    S = {"candidates": R, "chosen": chosen, "eligible": eligible,
         "P42-1": {"k0_lofo_mean": R["K0"]["lofo_mean"], "pass": R["K0"]["lofo_mean"] < 0.60},
         "P42-2": {"gain": round(R["K1"]["lofo_mean"] - R["K0"]["lofo_mean"], 4), "pass": R["K1"]["lofo_mean"] - R["K0"]["lofo_mean"] >= 0.03},
         "P42-3": {"gain": round(R["K2"]["lofo_mean"] - R["K1"]["lofo_mean"], 4), "pass": R["K2"]["lofo_mean"] - R["K1"]["lofo_mean"] >= 0.03},
         "P42-4": {"gain": round(R["K3"]["lofo_mean"] - R["K1"]["lofo_mean"], 4), "pass": R["K3"]["lofo_mean"] - R["K1"]["lofo_mean"] >= 0.03},
         "P42-5": {"chosen": chosen, "gain": round(R[chosen]["lofo_mean"] - R["K0"]["lofo_mean"], 4),
                   "pass": R[chosen]["lofo_mean"] - R["K0"]["lofo_mean"] >= 0.10},
         "P42-6": {"chosen_grouped": R[chosen]["grouped_by_session"], "k0_grouped": R["K0"]["grouped_by_session"],
                   "pass": R[chosen]["grouped_by_session"] >= R["K0"]["grouped_by_session"] - 0.02}}
    json.dump(S, open(RES / "summary.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in S.items() if k != "candidates"}, indent=1))
    print({k: (v["lofo_mean"], v["lofo_worst"], v["grouped_by_session"]) for k, v in R.items()})


if __name__ == "__main__":
    main()
