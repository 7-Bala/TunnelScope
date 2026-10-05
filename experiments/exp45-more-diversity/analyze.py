"""EXP-45 scorer (pre-registered in PREREG.md, commit 1acd160). Committed before any scored lab-E or lab-F capture.
Writes results/summary.json, results/lab_f_sessions.csv and, if a threshold meets the bar, results/mixed_windows_candidate.npz.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp45-more-diversity/analyze.py

Families: EXP-42's eight (build/models/corpus.py) plus lab-e (single sessions of testbed/captures/exp45, lab E). Features, augmentation
and the session rule (argmax of the mean window probability) are EXP-42's own code. Lab F trains nothing and chooses nothing.

Candidates, as the PREREG table:
  K4  the shipped recipe on the eight families (lab E never trains; its lab-e score is the eight-family model on lab E)
  K7  K4's recipe on nine families
  K8  K7 with ExtraTrees and RandomForest soft-voted (equal weight)
  K9  K7 with each family's total weight proportional to the square root of its training sessions (classes equal inside a family)

Readings of the PREREG fixed here, before any scored capture (each is also listed in the RESULT):
  - "Two ESP suites alternate": repetition 1 of every variant runs on the first suite, repetition 2 on the second.
  - "64 mixed sessions": 8 class pairs x 2 variant pairings x 2 repetitions x 2 suites (lab E); lab F's 16 = 4 x 2 x 2 suites.
  - The generator has 29 lab-E variants (the PREREG says "about 26") and 3 per class for lab F; voip.ilbc is dropped from lab F (the
    image has no iLBC encoder), so lab F has 46 single sessions, not 48. Denominators below are the sessions actually captured.
  - P45-1 compares means over the ORIGINAL eight families. Selection uses the nine-family mean and EXP-42's two guards against K4.
  - Mixed step: probabilities for a session come from the chosen recipe trained without that session's family (EXP-44's procedure);
    EXP-05/15 mixed sessions are lab-tgen, lab E's are lab-e. Detector and threshold sweep are EXP-44's code path (EXP-16's design:
    the lowest tau in 0.20..0.80 step 0.05 that catches >= 80% of mixed and flags <= 10% of single, out of fold, grouped by session).
  - P45-5 and P45-7 need a new check, so they fail if P45-4 fails; the same numbers with the current shipped check are reported for
    information. P45-6 is scored with the pair that would ship: the chosen model with the new check if P45-4 holds, else with the
    current check. "Answered" share is over all captured lab-F single sessions.
  - P45-2's "shipped K4" is the product's own model (tunnelscope.leakage.attacker._model, the shipped training file).
"""
from __future__ import annotations

import csv
import gzip
import importlib.util
import json
import os
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import GroupKFold
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

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
_s = importlib.util.spec_from_file_location("exp44", ROOT / "experiments/exp44-mixed-recalibrate/analyze.py")
E44 = importlib.util.module_from_spec(_s); _s.loader.exec_module(E44)
# Two switches exist only to rehearse this script on stand-in tables before any real capture (never for a scored run):
# EXP45_CAPTURES points at another table directory, EXP45_TREES shrinks the forests.
CAP = Path(os.environ.get("EXP45_CAPTURES", ROOT / "testbed/captures/exp45"))
TREES = int(os.environ.get("EXP45_TREES", "200"))
REHEARSAL = "EXP45_CAPTURES" in os.environ or "EXP45_TREES" in os.environ
RES = Path(os.environ["EXP45_RESULTS"]) if REHEARSAL else HERE / "results"      # a rehearsal never writes into results/
EIGHT = list(corpus.FAMILIES)
NINE = EIGHT + ["lab-e"]
TAU, MIN_CONSISTENCY = 0.60, 0.70
MINW = featurize.MIN_WINDOWS


# ------------------------------------------------------------------ data
def exp45_sessions(lab: str):
    """(singles, mixed) for lab 'E' or 'F' from the manifest; a tag captured twice keeps its last row."""
    rows = {}
    for r in csv.DictReader(open(CAP / "manifest.csv")):
        if r["lab"] == lab:
            rows[r["tag"]] = r
    fam = "lab-e" if lab == "E" else "lab-f"
    singles, mixed = [], []
    for tag, r in sorted(rows.items()):
        t, o, s = corpus._table(CAP / f"{tag}.pkts.csv.gz")
        ses = corpus._mk(fam, f"{fam}:{tag}", r["class"], t, o, s)
        ses.variant, ses.suite = r["variant"], r["suite"]
        (mixed if r["class"] == "mixed" else singles).append(ses)
    return singles, mixed


def rf():
    return RandomForestClassifier(n_estimators=TREES, random_state=0, n_jobs=-1, min_samples_leaf=2)


class SoftVote:
    """ExtraTrees and RandomForest, probabilities averaged with equal weight (K8)."""

    def fit(self, X, y, sample_weight=None):
        self.a = rf().fit(X, y, sample_weight=sample_weight)
        self.b = ExtraTreesClassifier(n_estimators=TREES, random_state=0, n_jobs=-1, min_samples_leaf=2).fit(X, y, sample_weight=sample_weight)
        self.classes_ = self.a.classes_
        assert list(self.a.classes_) == list(self.b.classes_)
        return self

    def predict_proba(self, X):
        return (self.a.predict_proba(X) + self.b.predict_proba(X)) / 2


def sqrt_weights(fams, labels, n_sessions):
    """A family's total weight is proportional to sqrt(its training sessions); inside a family every class is equal (K9)."""
    fams, labels = np.asarray(fams), np.asarray(labels)
    w = np.zeros(len(labels))
    tot = sum(np.sqrt(n_sessions[f]) for f in set(fams))
    for f in set(fams):
        mf = fams == f
        C = len(set(labels[mf]))
        for c in set(labels[mf]):
            m = mf & (labels == c)
            w[m] = np.sqrt(n_sessions[f]) / tot / (C * m.sum())
    return w * len(labels)


CANDIDATES = {
    "K4": dict(model=rf, weights="equal", lab_e_trains=False),
    "K7": dict(model=rf, weights="equal", lab_e_trains=True),
    "K8": dict(model=SoftVote, weights="equal", lab_e_trains=True),
    "K9": dict(model=rf, weights="sqrt", lab_e_trains=True),
}


def train_rows(data, keep_idx):
    """EXP-42's Data.train without the weights: the kept sessions' windows and those of their augmented copies."""
    keep = set(keep_idx)
    X, y, f = [], [], []
    for i in keep_idx:
        X.append(data.w[i]); y += [data.s[i].label] * len(data.w[i]); f += [data.s[i].family] * len(data.w[i])
    for j, i in enumerate(data.aug_src):
        if i in keep and len(data.aug_w[j]) >= MINW:
            X.append(data.aug_w[j]); y += [data.s[i].label] * len(data.aug_w[j]); f += [data.s[i].family] * len(data.aug_w[j])
    return np.vstack(X), np.array(y), np.array(f)


def fit(spec, data, keep_idx):
    X, y, f = train_rows(data, keep_idx)
    if spec["weights"] == "sqrt":
        w = sqrt_weights(f, y, Counter(data.s[i].family for i in keep_idx))
    else:
        w = E42.weights(f, y)
    return spec["model"]().fit(X, y, sample_weight=w), X


def session_pred(m, W):
    return str(m.classes_[int(m.predict_proba(W).mean(axis=0).argmax())])


def macro(y, p):
    return float(f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0))


def run_candidate(name, spec, data, ok, mixed_by_family):
    """Leave-one-family-out over the nine families, grouped-by-session CV, and (for the mixed step) the out-of-family probability
    shape of every single and mixed session."""
    pool = [i for i in ok if spec["lab_e_trains"] or data.s[i].family != "lab-e"]
    lofo, shape_rows = {}, []
    for fam in NINE:
        te = [i for i in ok if data.s[i].family == fam]
        if not te:
            continue
        m, _ = fit(spec, data, [i for i in pool if data.s[i].family != fam])
        y, p = [], []
        for i in te:
            P = m.predict_proba(data.w[i])
            y.append(data.s[i].label); p.append(str(m.classes_[int(P.mean(axis=0).argmax())]))
            shape_rows.append((data.s[i].sid, fam, "single", MX.session_features(P)))
        for sid, W in mixed_by_family.get(fam, []):
            shape_rows.append((sid, fam, "mixed", MX.session_features(m.predict_proba(W))))
        lofo[fam] = {"macro_f1": round(macro(y, p), 4), "accuracy": round(float(np.mean([a == b for a, b in zip(y, p)])), 4),
                     "sessions": len(te),
                     "per_class_f1": {c: round(float(v), 3) for c, v in zip(sorted(set(y)), f1_score(y, p, labels=sorted(set(y)), average=None, zero_division=0))}}
        print(f"  {name} {fam:14} {lofo[fam]['macro_f1']}", flush=True)
    ys, ps = [], []
    g = np.arange(len(pool))
    for tr, te in GroupKFold(5).split(g, g, g):
        m, _ = fit(spec, data, [pool[j] for j in tr])
        for j in te:
            ys.append(data.s[pool[j]].label); ps.append(session_pred(m, data.w[pool[j]]))
    nine = [lofo[f]["macro_f1"] for f in NINE if f in lofo]
    eight = [lofo[f]["macro_f1"] for f in EIGHT if f in lofo]
    return {"lofo": lofo, "lofo_mean_nine": round(float(np.mean(nine)), 4), "lofo_mean_eight": round(float(np.mean(eight)), 4),
            "lofo_worst": round(float(np.min(nine)), 4), "grouped_by_session": round(macro(ys, ps), 4),
            "train_pool_sessions": len(pool)}, shape_rows


def select(R):
    k4 = R["K4"]
    eligible = [k for k in CANDIDATES if R[k]["lofo_worst"] >= k4["lofo_worst"] - 0.05
                and R[k]["grouped_by_session"] >= k4["grouped_by_session"] - 0.02]
    best = max(R[k]["lofo_mean_nine"] for k in eligible)
    for k in CANDIDATES:                           # ties within 0.01 go to the earlier row
        if k in eligible and R[k]["lofo_mean_nine"] >= best - 0.01:
            return k, eligible
    raise AssertionError("unreachable: K4 is always eligible")


# ------------------------------------------------------------------ mixed check (EXP-44's procedure)
def mixed_step(shape_rows):
    G = np.array([r[0] for r in shape_rows]); F = np.array([r[3] for r in shape_rows]); L = np.array([r[2] for r in shape_rows])
    fam_of = np.array([r[1] for r in shape_rows])
    prob = np.zeros(len(shape_rows))
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
    out = {"n_rows": len(shape_rows), "n_mixed": int((L == "mixed").sum()),
           "mixed_by_family": dict(Counter(fam_of[L == "mixed"].tolist())), "by_tau": by_tau, "chosen": chosen}
    det = None
    if chosen is not None:
        tau = chosen["tau"]
        out["oof_single_flags_by_family"] = {f: f"{int((prob[(fam_of == f) & (L == 'single')] >= tau).sum())}/{int(((fam_of == f) & (L == 'single')).sum())}"
                                             for f in NINE if ((fam_of == f) & (L == "single")).any()}
        det = (RandomForestClassifier(n_estimators=300, random_state=0, min_samples_leaf=2, class_weight="balanced").fit(F, L), tau)
        np.savez_compressed(RES / "mixed_windows_candidate.npz", X=F, y=L, tau=np.array(tau))
    return out, det


# ------------------------------------------------------------------ the product's gate, for any model and any mixed check
def bundle(model, X):
    sc = StandardScaler().fit(X)
    Xs = sc.transform(X)
    nn = NearestNeighbors(n_neighbors=2).fit(Xs)
    return {"m": model, "sc": sc, "nn": nn, "cut": float(np.percentile(nn.kneighbors(Xs)[0][:, 1], 99))}


def shipped_bundle():
    m, sc, nn, cut, _ = A._model()
    return {"m": m, "sc": sc, "nn": nn, "cut": cut}


def is_mixed(P, det):
    """det None: the shipped check (tunnelscope.leakage.mixed). Otherwise (detector, tau). None when the check cannot run."""
    if det is None:
        return MX.is_mixed(P)
    if len(P) < 3:
        return None
    d, tau = det
    p = float(d.predict_proba([MX.session_features(P)])[0][list(d.classes_).index("mixed")])
    return p >= tau, round(p, 3)


def gate(b, W, det):
    """(stage, answer, flagged_mixed) with the shipped abstain logic (attacker.assess_exposure)."""
    if len(W) < MINW:
        return "insufficient", None, False
    d = b["nn"].kneighbors(b["sc"].transform(W), n_neighbors=1)[0][:, 0]
    ind = d <= b["cut"]
    if ind.mean() < 0.5:
        return "out_of_distribution", None, False
    P = b["m"].predict_proba(W[ind])
    picks = P.argmax(axis=1)
    consistency = np.bincount(picks).max() / len(picks)
    mean = P.mean(axis=0)
    guess, p = str(b["m"].classes_[int(mean.argmax())]), float(mean.max())
    mx = is_mixed(P, det)
    flagged = bool(mx and mx[0])
    if p >= TAU and consistency >= MIN_CONSISTENCY and not flagged:
        return "answered", guess, flagged
    return "abstained", None, flagged


def lab_f_eval(singles, mixed, chosen_b, ship_b, det):
    """Every lab-F session through: shipped model + shipped check (S), chosen model + shipped check (C_cur), and, if there is a
    new check, chosen model + new check (C_new)."""
    arms = {"S": (ship_b, None), "C_cur": (chosen_b, None)}
    if det is not None:
        arms["C_new"] = (chosen_b, det)
    rows = []
    for ses in singles + mixed:
        W = np.array(features_v2.v2(ses.t, ses.out, ses.size))
        r = {"sid": ses.sid, "label": ses.label, "variant": ses.variant, "suite": ses.suite, "windows": len(W)}
        if len(W) >= MINW:
            r["S_ungated"] = session_pred(ship_b["m"], W)
            r["C_ungated"] = session_pred(chosen_b["m"], W)
        for a, (b, d) in arms.items():
            r[f"{a}_stage"], r[f"{a}_answer"], r[f"{a}_flagged"] = gate(b, W, d) if len(W) else ("insufficient", None, False)
        rows.append(r)
    return rows, list(arms)


def gated_stats(rows, arm):
    ans = [r for r in rows if r[f"{arm}_stage"] == "answered"]
    right = [r for r in ans if r[f"{arm}_answer"] == r["label"]]
    return {"sessions": len(rows), "answered": len(ans), "correct": len(right),
            "answered_share": round(len(ans) / len(rows), 4) if rows else None,
            "accuracy_among_answered": round(len(right) / len(ans), 4) if ans else None,
            "flagged_mixed": sum(1 for r in rows if r[f"{arm}_flagged"]),
            "flagged_share": round(sum(1 for r in rows if r[f"{arm}_flagged"]) / len(rows), 4) if rows else None,
            "stages": dict(Counter(r[f"{arm}_stage"] for r in rows))}


def main():
    RES.mkdir(exist_ok=True)
    base = corpus.load()
    missing = [f for f in EIGHT if not any(s.family == f for s in base)]
    if missing:
        sys.exit(f"families missing from the corpus: {missing} (set TUNNELSCOPE_LAB_A / TUNNELSCOPE_LAB_B and the datasets)")
    e_single, e_mixed = exp45_sessions("E")
    f_single, f_mixed = exp45_sessions("F")
    sessions = base + e_single
    data = E42.Data("v2", sessions, aug=True)
    ok = [i for i, w in enumerate(data.w) if len(w) >= MINW]
    mux = E44.mux_sessions()
    mixed_by_family = {"lab-tgen": [(s.sid, w) for s, w in zip(mux, featurize.windows(mux, "v2")) if len(w) >= MINW],
                       "lab-e": [(s.sid, w) for s, w in zip(e_mixed, featurize.windows(e_mixed, "v2")) if len(w) >= MINW]}
    S = {"sessions": {"lab_e_single": len(e_single), "lab_e_single_scored": sum(1 for i in ok if sessions[i].family == "lab-e"),
                      "lab_e_mixed": len(e_mixed), "lab_e_mixed_scored": len(mixed_by_family["lab-e"]),
                      "exp05_15_mixed_scored": len(mixed_by_family["lab-tgen"]),
                      "lab_f_single": len(f_single), "lab_f_mixed": len(f_mixed),
                      "by_family_scored": dict(Counter(sessions[i].family for i in ok))}}

    part = RES / "partial.json"
    R = json.load(open(part)) if part.exists() else {}
    shapes = {}
    for name, spec in CANDIDATES.items():
        print(f"== {name}", flush=True)
        if name in R and (RES / f"shape_{name}.npz").exists():
            z = np.load(RES / f"shape_{name}.npz", allow_pickle=False)
            shapes[name] = list(zip(z["sid"].tolist(), z["fam"].tolist(), z["lab"].tolist(), z["F"].tolist()))
            continue
        R[name], shapes[name] = run_candidate(name, spec, data, ok, mixed_by_family)
        np.savez_compressed(RES / f"shape_{name}.npz", sid=np.array([r[0] for r in shapes[name]]), fam=np.array([r[1] for r in shapes[name]]),
                            lab=np.array([r[2] for r in shapes[name]]), F=np.array([r[3] for r in shapes[name]]))
        json.dump(R, open(part, "w"), indent=1)
    chosen, eligible = select(R)
    S.update(candidates=R, chosen=chosen, eligible=eligible)
    best_new = max(("K7", "K8", "K9"), key=lambda k: R[k]["lofo_mean_eight"])
    S["P45-1"] = {"k4_eight_mean": R["K4"]["lofo_mean_eight"], "best_of_K7_K8_K9": best_new, "its_eight_mean": R[best_new]["lofo_mean_eight"],
                  "gain": round(R[best_new]["lofo_mean_eight"] - R["K4"]["lofo_mean_eight"], 4),
                  "pass": R[best_new]["lofo_mean_eight"] - R["K4"]["lofo_mean_eight"] >= 0.03}

    # mixed check, from the chosen recipe's out-of-family probabilities
    S["mixed"], det = mixed_step(shapes[chosen])
    S["P45-4"] = {"chosen": S["mixed"]["chosen"], "pass": det is not None}

    # lab F: only now, and only to test
    spec = CANDIDATES[chosen]
    pool = [i for i in ok if spec["lab_e_trains"] or sessions[i].family != "lab-e"]
    model, X = fit(spec, data, pool)
    chosen_b, ship_b = bundle(model, X), shipped_bundle()
    rows, arms = lab_f_eval(f_single, f_mixed, chosen_b, ship_b, det)
    single = [r for r in rows if r["label"] != "mixed"]
    mixed = [r for r in rows if r["label"] == "mixed"]
    sc = [r for r in single if r["windows"] >= MINW]
    y = [r["label"] for r in sc]
    S["lab_f"] = {"single_captured": len(single), "single_scored": len(sc), "mixed_captured": len(mixed),
                  "S_ungated_macro_f1": round(macro(y, [r["S_ungated"] for r in sc]), 4),
                  "C_ungated_macro_f1": round(macro(y, [r["C_ungated"] for r in sc]), 4),
                  "S_per_class_f1": {c: round(float(v), 3) for c, v in zip(sorted(set(y)), f1_score(y, [r["S_ungated"] for r in sc], labels=sorted(set(y)), average=None, zero_division=0))},
                  "C_per_class_f1": {c: round(float(v), 3) for c, v in zip(sorted(set(y)), f1_score(y, [r["C_ungated"] for r in sc], labels=sorted(set(y)), average=None, zero_division=0))},
                  "gated_single": {a: gated_stats(single, a) for a in arms},
                  "gated_mixed": {a: gated_stats(mixed, a) for a in arms}}
    LF = S["lab_f"]
    S["P45-2"] = {"chosen": LF["C_ungated_macro_f1"], "shipped_k4": LF["S_ungated_macro_f1"],
                  "gain": round(LF["C_ungated_macro_f1"] - LF["S_ungated_macro_f1"], 4),
                  "pass": LF["C_ungated_macro_f1"] - LF["S_ungated_macro_f1"] >= 0.05}
    S["P45-3"] = {"chosen_interactive_f1": LF["C_per_class_f1"].get("interactive"), "shipped_interactive_f1": LF["S_per_class_f1"].get("interactive"),
                  "pass": (LF["C_per_class_f1"].get("interactive") or 0.0) >= 0.5}
    pair = "C_new" if det is not None else "C_cur"
    g = LF["gated_single"][pair]
    S["P45-6"] = {"scored_with": pair, **{k: g[k] for k in ("answered", "correct", "answered_share", "accuracy_among_answered", "sessions")},
                  "pass": bool(g["accuracy_among_answered"] is not None and g["accuracy_among_answered"] >= 0.90 and g["answered_share"] >= 0.50)}
    if det is not None:
        S["P45-5"] = {"flagged_share": LF["gated_single"]["C_new"]["flagged_share"], "pass": LF["gated_single"]["C_new"]["flagged_share"] <= 0.25}
        gm = LF["gated_mixed"]["C_new"]
        not_answered = gm["sessions"] - gm["answered"]
        S["P45-7"] = {"not_answered": not_answered, "n": gm["sessions"], "pass": bool(gm["sessions"]) and not_answered / gm["sessions"] >= 0.80}
    else:
        S["P45-5"] = {"pass": False, "why": "no threshold met the bar (P45-4), so there is no new check",
                      "current_check_flagged_share_for_information": LF["gated_single"]["C_cur"]["flagged_share"]}
        gm = LF["gated_mixed"]["C_cur"]
        S["P45-7"] = {"pass": False, "why": "no new check", "current_check_not_answered_for_information": gm["sessions"] - gm["answered"], "n": gm["sessions"]}
    S["ship_model"] = bool(chosen != "K4" and S["P45-2"]["pass"] and S["P45-6"]["pass"])
    S["ship_mixed_check"] = bool(S["P45-4"]["pass"] and S["P45-5"]["pass"] and S["P45-7"]["pass"])
    keys = sorted({k for r in rows for k in r})
    with open(RES / "lab_f_sessions.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)
    json.dump(S, open(RES / "summary.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in S.items() if k not in ("candidates", "mixed")}, indent=1))
    print({k: (v["lofo_mean_nine"], v["lofo_mean_eight"], v["lofo_worst"], v["grouped_by_session"]) for k, v in R.items()})


if __name__ == "__main__":
    main()
