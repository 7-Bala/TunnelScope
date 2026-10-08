"""DEC-066 / EXP-51: the shipped traffic classifier is R6 (two forests averaged, ten families) behind the gate that EXP-51 set on
whole families held out of training. These pin what was measured on lab G, so a later change cannot quietly undo it."""
import csv
import json
import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import f1_score

from tunnelscope.leakage import attacker as A
from tunnelscope.leakage import mixed as MX

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "build" / "models"))
import corpus  # noqa: E402

CAP = ROOT / "testbed" / "captures" / "exp51"


def _lab_g():
    rows = {}
    for r in csv.DictReader(open(CAP / "manifest.csv")):
        if r["lab"] == "G":
            rows[r["tag"]] = r
    out = []
    for tag, r in sorted(rows.items()):
        out.append((r["class"], corpus.packets(CAP / f"{tag}.pkts.csv.gz")))
    return out


@pytest.fixture(scope="module")
def lab_g():
    return _lab_g()


def _esp(pk):
    return [{"t": t, "src": d, "ip_len": n} for t, d, n in pk]


def test_gate_thresholds_are_the_ones_exp51_chose():
    """The thresholds come from results/choice.json (set on held-out families, before lab G was captured), not from tuning."""
    gate = json.load(open(ROOT / "experiments/exp51-rate-invariance/results/choice.json"))["gate"]
    assert A.TAU == gate["tau_c"] == 0.65
    assert A.MIN_CONSISTENCY == 0.70
    assert float(np.load(MX.DATA)["tau"]) == gate["tau_m"] == 0.65
    assert gate["tau_o"] == 1.0            # no distance cut: see test_far_traffic_is_not_stopped_by_distance


def test_model_is_the_average_of_a_random_forest_and_an_extra_trees_forest():
    m = A._model()[0]
    X = np.load(A.DATA)["X"][::997]
    assert type(m.a).__name__ == "RandomForestClassifier" and type(m.b).__name__ == "ExtraTreesClassifier"
    assert np.allclose(m.predict_proba(X), (m.a.predict_proba(X) + m.b.predict_proba(X)) / 2)
    assert list(m.classes_) == sorted(A.CLASSES)


def test_shipped_pair_keeps_its_lab_g_result(lab_g):
    """EXP-51 on lab G (nobody trained on it): R6 0.855 macro-F1, 20 of 64 singles answered and all right, 14 of 16 mixed sessions
    kept from a single label. The shipped files (fewer windows per session, 3 significant digits) were checked once:
    experiments/exp51-rate-invariance/results/artifact_check.json."""
    m = A._model()[0]
    y, p, answered, right, mixed_answered, mixed_n = [], [], 0, 0, 0, 0
    for cls, pk in lab_g:
        r = A.assess_exposure(_esp(pk), "out")
        ans = r["status"] == "measured" and r["traffic"]["answered"]
        if cls == "mixed":
            mixed_n += 1; mixed_answered += int(ans)
            continue
        W = np.array(A.window_features_v2(pk))
        y.append(cls); p.append(str(m.classes_[int(m.predict_proba(W).mean(axis=0).argmax())]))
        answered += int(ans); right += int(ans and r["traffic"]["class"] == cls)
    assert len(y) == 64 and mixed_n == 16
    assert f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0) >= 0.83
    assert answered >= 18 and right == answered          # about one in three, and never wrong on this lab
    assert mixed_answered <= 2


def test_far_traffic_is_not_stopped_by_distance(lab_g):
    """Until DEC-066 a session whose windows were mostly far from the training windows got status 'out_of_distribution'. The
    distance is still reported, but the status no longer exists: every session with enough windows is 'measured'."""
    statuses, shares = set(), []
    for _, pk in lab_g:
        r = A.assess_exposure(_esp(pk), "out")
        statuses.add(r["status"])
        if r["status"] == "measured":
            shares.append(r["in_distribution_share"])
    assert statuses <= {"measured", "insufficient"}
    assert min(shares) < 0.5                              # some lab-G sessions are mostly far away, and are still measured


def test_low_confidence_says_what_it_means(monkeypatch):
    """Below the confidence threshold the reason names both causes EXP-51 saw: unseen tools and mixed traffic."""
    class Flat:
        classes_ = np.array(sorted(A.CLASSES))

        def predict_proba(self, X):
            P = np.full((len(X), 8), 0.08); P[:, 1] = 0.44
            return P
    real = A._model()
    monkeypatch.setattr(A, "_model", lambda: (Flat(),) + tuple(real[1:]))
    monkeypatch.setattr(MX, "is_mixed", lambda P: (False, 0.1))
    monkeypatch.setattr(A, "window_features_v2", lambda pk: np.load(A.DATA)["X"][:6].tolist())
    t = A.assess_exposure(_esp([(0.0, "out", 100)]), "out")["traffic"]
    assert t["answered"] is False and t["class"] is None
    assert "below 65%" in t["why_not"] and "not seen" in t["why_not"] and "mixed" in t["why_not"]
