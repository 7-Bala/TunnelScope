#!/usr/bin/env python3
"""T-110: the frozen scoreboard for the traffic classifier (build/14-ACCURACY-PLAN.md §4).

Scores a training *recipe* (which sources it learns from, and how) on four test sets that never
change and never mix one capture into both training and test:

  A  real IPsec traffic: USBVPN2022 L2TP-over-IPsec, 5 folds grouped by capture record
     (PRIMARY: the only real IPsec traffic we have). Scored on pooled out-of-fold predictions,
     because two classes have only a handful of records; a 95% interval from resampling records.
  B  real people: WireGuard matched-view, trained with session 1 only, tested on session 2.
  C  real OpenVPN: MIT VNAT, 5 folds grouped by capture file (as EXP-19).
  D  our lab: EXP-16 real applications, leave one repetition out (as EXP-19 Q4b).

A source the recipe does not learn from is still tested (the model simply never saw it). Test
folds are only ever predicted, never used to choose anything. Also reported for A and B: how often
the tool's abstain rule answers per capture (coverage) and how often that answer is right.

The window files are exported by experiments/exp19-* and exp20-* (plain arrays, no pickles).
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "build/models"))
from make_traffic_data import load  # noqa: E402
from tunnelscope.leakage.attacker import MIN_CONSISTENCY, TAU  # noqa: E402

MODELS = ROOT / "build/models"
FOLDS, BOOT, SEED = 5, 1000, 20
LAB_REAL_ARM = "real-apps"          # EXP-16's real applications, the lab test D (as EXP-19 Q4b)


def shipped_rf():
    return RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2)


@dataclass
class Source:
    name: str
    X: np.ndarray
    y: np.ndarray
    group: np.ndarray                 # capture / record / flow id: never split across train and test
    extra: dict = field(default_factory=dict)


def sources() -> dict[str, Source]:
    X, y, arm, rep, sess, _src = load()                    # the lab only (EXP-05/15/16/17)
    out = {"lab": Source("lab", X, y, sess, {"arm": arm, "rep": rep})}
    v = np.load(MODELS / "vnat_windows.npz", allow_pickle=False)
    out["vnat"] = Source("vnat", v["X"].astype(float), v["y"], v["capture"])
    for name, fn in (("usbvpn", "usbvpn_windows.npz"), ("wg", "wg_windows.npz")):
        p = MODELS / fn
        if p.exists():
            d = np.load(p, allow_pickle=False)
            out[name] = Source(name, d["X"].astype(float), d["y"], d["group"],
                               {k: d[k] for k in d.files if k not in ("X", "y", "group")})
    return out


@dataclass
class Recipe:
    name: str
    learn_from: tuple[str, ...]                                   # source names
    model: Callable = shipped_rf
    select: Callable[[str, Source], np.ndarray] | None = None     # optional per-source row filter for TRAINING


def _train_rows(recipe: Recipe, src: dict[str, Source], exclude: dict[str, np.ndarray]):
    Xs, ys = [], []
    for name in recipe.learn_from:
        s = src[name]
        keep = np.ones(len(s.y), bool) if recipe.select is None else recipe.select(name, s)
        if name in exclude:
            keep &= ~exclude[name]
        Xs.append(s.X[keep]); ys.append(s.y[keep])
    return np.vstack(Xs), np.concatenate(ys)


def macro(y, p, labels):
    return round(float(f1_score(y, p, labels=labels, average="macro", zero_division=0)), 4)


def per_class(y, p, labels):
    f = f1_score(y, p, labels=labels, average=None, zero_division=0)
    return {c: round(float(v), 4) for c, v in zip(labels, f)}


def boot_ci(y, p, g, labels, seed=SEED):
    """95% interval of macro-F1, resampling whole capture groups (not windows)."""
    rng = np.random.default_rng(seed)
    ug = np.unique(g)
    idx = {k: np.flatnonzero(g == k) for k in ug}
    vals = []
    for _ in range(BOOT):
        pick = np.concatenate([idx[k] for k in rng.choice(ug, len(ug), replace=True)])
        vals.append(f1_score(y[pick], p[pick], labels=labels, average="macro", zero_division=0))
    return [round(float(np.percentile(vals, 2.5)), 4), round(float(np.percentile(vals, 97.5)), 4)]


def selective(y, P, classes, g):
    """Per capture: mean probability over its windows; the tool answers if the top class clears TAU
    and at least MIN_CONSISTENCY of windows agree. Returns coverage and accuracy when answering."""
    answered = right = 0
    ug = np.unique(g)
    for k in ug:
        m = g == k
        mp = P[m].mean(axis=0)
        top = int(np.argmax(mp))
        cons = float((P[m].argmax(axis=1) == top).mean())
        if mp[top] >= TAU and cons >= MIN_CONSISTENCY:
            answered += 1
            right += int(classes[top] == y[m][0])
    return {"captures": int(len(ug)), "coverage": round(answered / len(ug), 4),
            "accuracy_when_answering": round(right / answered, 4) if answered else None}


def _pooled(recipe, src, test: str, labels, split_groups: bool):
    """Out-of-fold predictions for one test source."""
    s = src[test]
    pred = np.empty(len(s.y), dtype=object)
    P = None
    if test in recipe.learn_from and split_groups:
        folds = GroupKFold(n_splits=FOLDS).split(s.X, s.y, s.group)
    else:
        folds = [(np.array([], int), np.arange(len(s.y)))]
    for _tr, te in folds:
        mask = np.zeros(len(s.y), bool); mask[te] = True
        Xtr, ytr = _train_rows(recipe, src, {test: mask} if test in recipe.learn_from else {})
        m = recipe.model().fit(Xtr, ytr)
        pr = m.predict_proba(s.X[te])
        if P is None:
            P, classes = np.zeros((len(s.y), len(m.classes_))), m.classes_
        assert list(m.classes_) == list(classes)
        P[te] = pr
        pred[te] = classes[pr.argmax(axis=1)]
    return pred.astype(str), P, classes


def score(recipe: Recipe, src: dict[str, Source] | None = None) -> dict:
    src = src or sources()
    out: dict = {"recipe": recipe.name, "learns_from": list(recipe.learn_from)}
    # A: real IPsec
    if "usbvpn" in src:
        s = src["usbvpn"]
        labels = sorted(set(s.y))
        pred, P, classes = _pooled(recipe, src, "usbvpn", labels, split_groups=True)
        out["A_real_ipsec"] = {"macro_f1": macro(s.y, pred, labels), "ci95": boot_ci(s.y, pred, s.group, labels),
                               "per_class": per_class(s.y, pred, labels),
                               "captures_per_class": {c: int(len(set(s.group[s.y == c]))) for c in labels},
                               "selective": selective(s.y, P, classes, s.group)}
    # B: real people, session 1 -> session 2
    if "wg" in src:
        s = src["wg"]
        te = s.extra["session"] == 2
        Xtr, ytr = _train_rows(recipe, src, {"wg": te})       # session 2 never trains (no-op if wg unused)
        m = recipe.model().fit(Xtr, ytr)
        P = m.predict_proba(s.X[te]); pred = m.classes_[P.argmax(axis=1)]
        yb, gb = s.y[te], s.group[te]
        res = {}
        for tag, cls in (("without_web", sorted(set(yb) - {"web"})), ("with_web", sorted(set(yb)))):
            keep = np.isin(yb, cls)
            res[tag] = {"macro_f1": macro(yb[keep], pred[keep], cls), "ci95": boot_ci(yb[keep], pred[keep], gb[keep], cls),
                        "per_class": per_class(yb[keep], pred[keep], cls),
                        "captures_per_class": {c: int(len(set(gb[yb == c]))) for c in cls},
                        "selective": selective(yb[keep], P[keep], m.classes_, gb[keep])}
        out["B_real_users_wireguard"] = res
    # C: real OpenVPN (VNAT)
    s = src["vnat"]
    labels = sorted(set(s.y))
    pred, _, _ = _pooled(recipe, src, "vnat", labels, split_groups=True)
    out["C_real_openvpn_vnat"] = {"macro_f1": macro(s.y, pred, labels), "ci95": boot_ci(s.y, pred, s.group, labels),
                                  "per_class": per_class(s.y, pred, labels)}
    # D: our lab, EXP-16 real applications, leave one repetition out
    lab = src["lab"]
    real = lab.extra["arm"] == LAB_REAL_ARM
    labels = sorted(set(lab.y[real]))
    folds = []
    for r in sorted(set(lab.extra["rep"][real])):
        te = real & (lab.extra["rep"] == r)
        Xtr, ytr = _train_rows(recipe, src, {"lab": te})
        m = recipe.model().fit(Xtr, ytr)
        folds.append(macro(lab.y[te], m.predict(lab.X[te]), labels))
    out["D_lab_real_apps_loro"] = {"folds": folds, "mean": round(float(np.mean(folds)), 4)}
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(score(Recipe("shipped (lab + VNAT)", ("lab", "vnat"))), indent=1))
