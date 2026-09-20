"""Mixed-traffic detector (EXP-16 part D), the answer to EXP-15's failed P15-4.

The 8-class classifier is confident and consistent on a session carrying two
kinds of traffic at once — that is exactly how "video + interactive" came out
as "web browsing" 8 times out of 8. Confidence cannot catch it, so this is a
SECOND stage: it looks at the SHAPE of the first model's per-window probability
output (how spread out, how varied between windows, how much second-place mass)
and decides single vs mixed.

Trained on the project's own mixed sessions (EXP-05 and EXP-15 mux arms) against
its single-class ones. Ships only if it met the bar pre-registered in EXP-16
(catch >= 80% of mixed sessions, wrongly flag <= 10% of single ones); the data
file is written by the experiment's analysis only in that case.
"""
from __future__ import annotations

import math
import os
from functools import lru_cache

import numpy as np

DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "mixed_windows.npz")


def _entropy(p) -> float:
    return float(-sum(x * math.log(x + 1e-12) for x in p))


def _js(a, b) -> float:
    m = (a + b) / 2
    kl = lambda p, q: float(np.sum(p * np.log((p + 1e-12) / (q + 1e-12))))
    return 0.5 * kl(a, m) + 0.5 * kl(b, m)


def session_features(P: np.ndarray) -> list[float]:
    """P: one row of class probabilities per window."""
    mean = P.mean(axis=0)
    order = np.argsort(mean)[::-1]
    top = P.max(axis=1)
    picks = P.argmax(axis=1)
    agree = np.bincount(picks, minlength=P.shape[1]).max() / len(picks)
    js = [ _js(P[i], P[j]) for i in range(len(P)) for j in range(i + 1, len(P)) ] or [0.0]
    return [float(mean[order[0]]), float(mean[order[1]]), float(mean[order[0]] - mean[order[1]]),
            _entropy(mean), float(np.mean([_entropy(p) for p in P])),
            float(top.mean()), float(top.std()), float(agree),
            float(len(set(picks.tolist())) / len(picks)), float(np.mean(js)), float(np.max(js))]


@lru_cache(maxsize=1)
def _model():
    if not os.path.exists(DATA):
        return None
    from sklearn.ensemble import RandomForestClassifier
    d = np.load(DATA, allow_pickle=False)
    m = RandomForestClassifier(n_estimators=300, random_state=0, min_samples_leaf=2,
                               class_weight="balanced").fit(d["X"], d["y"])
    return m, float(d["tau"])


def is_mixed(P: np.ndarray) -> tuple[bool, float] | None:
    """(mixed?, probability) or None when no evaluated model is installed."""
    mm = _model()
    if mm is None or len(P) < 3:
        return None
    m, tau = mm
    p = float(m.predict_proba([session_features(P)])[0][list(m.classes_).index("mixed")])
    return p >= tau, round(p, 3)
