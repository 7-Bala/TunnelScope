"""DEC-054 / EXP-42-43: the shipped traffic classifier is K4 (v2 features, family/class-balanced, eight families).

These pin what EXP-43 measured, so a later change cannot quietly undo it."""
import gzip
import re
import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import f1_score

from tunnelscope.leakage import attacker as A

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "build" / "models"))


def _tables(folder, pattern):
    out = []
    for p in sorted((ROOT / "testbed" / "captures" / folder).glob("*.pkts.csv.gz")):
        m = re.match(pattern, p.name)
        if not m:
            continue
        with gzip.open(p, "rt") as f:
            next(f)
            pk = [(float(t), d, int(n)) for t, d, n in (l.strip().split(",") for l in f) if n]
        out.append((m["cls"], m.groupdict().get("suite"), pk))
    return out


LAB_D = _tables("exp43", r"exp43-(?P<suite>chacha|sha384)-(?P<cls>\w+)-rep\d\.pkts\.csv\.gz")


def test_v2_is_v1_plus_fifteen_columns_window_for_window():
    _, _, pk = LAB_D[0]
    v1, v2 = np.array(A.window_features(sorted(pk))), np.array(A.window_features_v2(pk))
    assert v2.shape == (len(v1), 31 + 15) and np.allclose(v2[:, :31], v1)


def test_product_v2_is_the_frozen_experiment_v2():
    import features_v2
    for _, _, pk in LAB_D[::4]:
        t = np.array([p[0] for p in pk]); o = np.array([p[1] == "out" for p in pk]); s = np.array([p[2] for p in pk])
        assert np.allclose(np.array(A.window_features_v2(pk)), np.array(features_v2.v2(t, o, s)))


def test_balanced_weights_give_every_family_and_class_equal_say():
    y = np.array(["a"] * 10 + ["b"] * 2 + ["a"] * 100)
    fam = np.array(["f1"] * 12 + ["f2"] * 100)
    w = A.balanced_weights(y, fam)
    assert np.isclose(w[fam == "f1"].sum(), w[fam == "f2"].sum())
    assert np.isclose(w[(fam == "f1") & (y == "a")].sum(), w[(fam == "f1") & (y == "b")].sum())


def test_shipped_training_file_is_plain_arrays_under_5_mb():
    d = np.load(A.DATA, allow_pickle=False)
    assert {"X", "y", "family", "rep"} <= set(d.files) and d["X"].shape[1] == 46
    assert Path(A.DATA).stat().st_size < 5 * 1024 * 1024
    assert len(set(d["family"].tolist())) == 8


def test_shipped_model_keeps_its_lab_d_accuracy():
    """EXP-43: on lab D (never trained on) the shipped model scored 0.833 macro-F1 and every gated answer was right."""
    rf = A._model()[0]
    y, p, answered, right = [], [], 0, 0
    for cls, _, pk in LAB_D:
        W = np.array(A.window_features_v2(pk))
        y.append(cls); p.append(str(rf.classes_[int(rf.predict_proba(W).mean(axis=0).argmax())]))
        r = A.assess_exposure([{"t": t, "src": d, "ip_len": n} for t, d, n in pk], "out")
        if r["status"] == "measured" and r["traffic"]["answered"]:
            answered += 1
            right += int(r["traffic"]["class"] == cls)
    assert f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0) >= 0.80
    assert answered >= 8 and right == answered


def test_the_product_trains_with_the_balanced_weights(monkeypatch):
    """EXP-42's K4 is balanced by family and class; a model fitted without the weights is a different model."""
    from sklearn.ensemble import RandomForestClassifier
    seen = {}
    real_fit = RandomForestClassifier.fit

    def spy(self, X, y, sample_weight=None):
        seen["w"] = sample_weight
        return real_fit(self, X[:200], y[:200], sample_weight=None if sample_weight is None else sample_weight[:200])
    monkeypatch.setattr(RandomForestClassifier, "fit", spy)
    A._model.cache_clear()
    try:
        A._model()
    finally:
        A._model.cache_clear()
    d = np.load(A.DATA, allow_pickle=False)
    assert seen["w"] is not None and np.allclose(seen["w"], A.balanced_weights(d["y"], d["family"]))
