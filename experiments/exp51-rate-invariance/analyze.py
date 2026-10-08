"""EXP-51 scorer (pre-registered in PREREG.md, commit cb86075). Committed before any candidate is scored.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp51-rate-invariance/analyze.py lofo [R0 R1 ...]
    ... analyze.py choose        (after lab H is captured and R5 is scored; BEFORE any lab-G capture)
    ... analyze.py labg          (once, after lab G's tables are committed)

Families: EXP-42's eight, lab-e (EXP-45's singles) and, for R5 only, lab-h (singles of testbed/captures/exp51, lab H).
Features v2, EXP-42's two augmented copies, the family/class weights and K8's ExtraTrees + RandomForest soft vote are the earlier
experiments' own code. Labs D and F are the development guard only; lab G trains nothing and chooses nothing.

Readings of the PREREG fixed here, before any candidate is scored (each is repeated in the RESULT):
  - R0 "K8 as in EXP-45" = v2, nine families, EXP-42's two copies per session, family/class weights, soft vote.
  - v3 (R1) = v2 without columns out_n, out_bytes, out_iat<1ms, in_n, in_bytes, in_iat<1ms, pps, bps, ctx_pps, ctx_bps (10), plus 14:
    log10((in_n+1)/(out_n+1)); log10((in_bytes+1)/(out_bytes+1)); per direction the window's mean, std, min and max size divided by
    the session's largest packet in that direction (8); log10 of the window's median inter-arrival time over the session's median,
    for out, in and both directions together (3; 0 when a side has fewer than two packets); the largest share of the window's packets
    that falls in one of its ten 200 ms slots (1). 50 columns. The log inter-arrival columns of v1 stay: the PREREG names the ten
    columns to drop and they are not among them.
  - R2's four speed copies REPLACE EXP-42's two copies (same size offset, -40..+80 bytes); the scale multiplies time.
  - R4's session stage: RandomForest (300 trees, leaf 2, family/class weights) over 20 descriptors per session: mean and standard
    deviation of the window probabilities (16); share of the session's full 2 s slots that hold at least 3 packets; standard
    deviation of log10(packets) over those slots; share of packets and share of bytes sent "out". Its training rows use window
    probabilities from a model trained WITHOUT the row's family (and, inside leave-one-family-out, also without the held-out family:
    one base model per pair of families). The session's class is the stage's argmax.
  - Leave-one-family-out "mean" for P51-1 and P51-3 is over EXP-42's original eight families (K8's 0.514 is that mean). The choice rule
    uses the same eight-family mean, so that R5 (which has a tenth family) is compared like with like; all-family means are reported.
  - P51-2 "web recall" = share of USBVPN's scored web sessions called web, USBVPN held out.
  - P51-4 grouped-by-session: 5 folds over sessions. For R4/R5 the fold's base model gives the test sessions' window probabilities and
    the session stage is trained on the fold's training sessions, with probabilities from the leave-one-family-out base models
    (those saw other families' test-fold sessions: a mild leak, accepted for this in-distribution guard and stated).
  - Guard: the candidate trained on all its families, ungated session macro-F1 on lab D (32) and on lab F's singles (46).
  - Gate. A session is answered iff  top probability >= tau_c  AND  mixed score < tau_m  AND  out-of-distribution share <= tau_o
    AND  window agreement >= 0.70 (the shipped consistency rule, unchanged). Mixed score: EXP-16's detector on the window-probability
    shape, here trained leave-one-family-out (mixed sessions: EXP-05/15 in lab-tgen, lab E's 64 in lab-e). Out-of-distribution share:
    share of the session's windows farther from every training window (standardised, the chosen features, at most 30 windows per
    training session) than the 99th percentile of the training windows' own nearest-neighbour distance. Thresholds: over the grid
    tau_c 0.30..0.90 step 0.05, tau_m 0.20..0.80 step 0.05 or off, tau_o 0.1..0.9 step 0.1 or off, the point with the largest
    family-weighted answered share (every held-out family counts equally, as in training; USBVPN alone would otherwise be 40% of
    the pool) among points where family-weighted held-out answers are >= 90% right AND >= 80% of held-out mixed sessions are not
    answered. Ties: the larger tau_c, then the smaller tau_m, then the smaller tau_o. No point qualifies -> no new gate, P51-6 fails.
  - P51-5 "shipped K4" and the shipped gate = the product's own model and check (tunnelscope.leakage.attacker / mixed), as EXP-45.
  - P51-6 is over all captured lab-G singles; P51-7 over all captured lab-G mixed sessions.
Two switches exist only to rehearse this script (never for a scored run): EXP51_TREES shrinks the forests, EXP51_FAMILIES limits the
families; either sends results and the probability cache to EXP51_SCRATCH and lets EXP51_CAPTURES point at stand-in tables.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import os
import pickle
import sys
from collections import Counter
from itertools import combinations
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
from tunnelscope.leakage import mixed as MX  # noqa: E402


def _load(name, rel):
    s = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m


E42 = _load("exp42", "experiments/exp42-generalise/analyze.py")
E43 = _load("exp43", "experiments/exp43-lab-d/analyze.py")
E44 = _load("exp44", "experiments/exp44-mixed-recalibrate/analyze.py")
E45 = _load("exp45", "experiments/exp45-more-diversity/analyze.py")

TREES = int(os.environ.get("EXP51_TREES", "200"))
REHEARSAL = "EXP51_TREES" in os.environ or "EXP51_FAMILIES" in os.environ
RES = Path(os.environ["EXP51_SCRATCH"]) / "results" if REHEARSAL else HERE / "results"
PCACHE = (Path(os.environ["EXP51_SCRATCH"]) if REHEARSAL else corpus.CACHE) / "exp51-probs"
CAP = Path(os.environ["EXP51_CAPTURES"]) if REHEARSAL and "EXP51_CAPTURES" in os.environ else ROOT / "testbed/captures/exp51"
EIGHT = list(corpus.FAMILIES)
MINW = featurize.MIN_WINDOWS
WIN = features_v2.WIN
MIN_CONSISTENCY = 0.70
ELASTIC = {"bulk", "web", "email"}
DROP = [0, 1, 9, 15, 16, 24, 31, 32, 43, 44]
KEEP = [j for j in range(46) if j not in DROP]

CANDIDATES = {
    "R0": dict(version="v2", aug="e42", stage2=False, lab_h=False),
    "R1": dict(version="v3", aug="e42", stage2=False, lab_h=False),
    "R2": dict(version="v2", aug="speed", stage2=False, lab_h=False),
    "R3": dict(version="v3", aug="speed", stage2=False, lab_h=False),
    "R4": dict(version="v3", aug="speed", stage2=True, lab_h=False),
    "R5": dict(version="v3", aug="speed", stage2=True, lab_h=True),
    # Addendum A (PREREG), added after R0-R4 were scored and before any model saw lab H
    "R6": dict(version="v2", aug="e42", stage2=False, lab_h=True),
    "R7": dict(version="v3", aug="speed", stage2=False, lab_h=True),
}


# ------------------------------------------------------------------ features v3
def v3(t, out, size):
    base = features_v2.v2(t, out, size)
    if not base:
        return []
    t = np.asarray(t, float); out = np.asarray(out, bool); size = np.asarray(size, float)
    idx, last_full = features_v2._window_index(t)
    smax = {True: size[out].max() if out.any() else 0.0, False: size[~out].max() if (~out).any() else 0.0}

    def med(x):
        return float(np.median(np.diff(x))) if len(x) > 1 else None
    smed = {True: med(t[out]), False: med(t[~out]), None: med(t)}
    rows = []
    for w in np.unique(idx):
        m = idx == w
        if m.sum() < features_v2.MIN_PKTS or w > last_full:
            continue
        tw, ow, sw = t[m], out[m], size[m]
        n_o, n_i = int(ow.sum()), int((~ow).sum())
        v = [float(np.log10((n_i + 1) / (n_o + 1))), float(np.log10((sw[~ow].sum() + 1) / (sw[ow].sum() + 1)))]
        for d in (True, False):
            s = sw[ow == d]
            v += [float(s.mean() / smax[d]), float(s.std() / smax[d]), float(s.min() / smax[d]), float(s.max() / smax[d])] \
                if len(s) and smax[d] > 0 else [0.0, 0.0, 0.0, 0.0]
        for d, ts in ((True, tw[ow]), (False, tw[~ow]), (None, tw)):
            mw = med(ts)
            v.append(float(np.log10((mw + 1e-6) / (smed[d] + 1e-6))) if mw is not None and smed[d] is not None else 0.0)
        slot = np.clip(((tw - (t[0] + w * WIN)) / 0.2).astype(int), 0, 9)
        v.append(float(np.bincount(slot, minlength=10).max() / len(tw)))
        rows.append(v)
    assert len(rows) == len(base), (len(rows), len(base))
    return [[b[j] for j in KEEP] + r for b, r in zip(base, rows)]


featurize.register("v2", features_v2.v2)
featurize.register("v3", v3)


def speed_copies(sessions, n=4):
    """Four seeded copies per session: size offset as EXP-42; time scale log-uniform 1/8..8 for bulk, web and email, else 0.8..1.25."""
    out, src = [], []
    for i, s in enumerate(sessions):
        if len(s.t) == 0:
            continue
        for k in range(n):
            rng = np.random.default_rng(int(hashlib.sha256(f"{s.sid}#spd{k}".encode()).hexdigest()[:8], 16))
            off = int(rng.integers(-40, 81))
            scale = float(np.exp(rng.uniform(np.log(1 / 8), np.log(8)))) if s.label in ELASTIC else float(rng.uniform(0.8, 1.25))
            out.append(corpus.Session(s.family, f"{s.sid}#spd{k}", s.label, s.t[0] + (s.t - s.t[0]) * scale, s.out,
                                      np.maximum(28, s.size + off)))
            src.append(i)
    return out, src


def session_desc(s):
    if len(s.t) < 2:
        return [0.0, 0.0, 0.0, 0.0]
    k = ((s.t - s.t[0]) // WIN).astype(int)
    nfull = max(int((s.t[-1] - s.t[0]) // WIN), 1)
    cnt = np.bincount(k, minlength=nfull)[:nfull]
    act = cnt >= 3
    spread = float(np.log10(cnt[act]).std()) if act.sum() > 1 else 0.0
    return [float(act.mean()), spread, float(s.out.mean()), float(s.size[s.out].sum() / max(s.size.sum(), 1))]


# ------------------------------------------------------------------ data
def exp51_sessions(lab):
    """(singles, mixed) of lab 'H' or 'G' from testbed/captures/exp51/manifest.csv; a tag captured twice keeps its last row."""
    man = CAP / "manifest.csv"
    if not man.exists():
        return [], []
    rows = {}
    for r in csv.DictReader(open(man)):
        if r["lab"] == lab:
            rows[r["tag"]] = r
    fam = "lab-h" if lab == "H" else "lab-g"
    singles, mixed = [], []
    for tag, r in sorted(rows.items()):
        t, o, s = corpus._table(CAP / f"{tag}.pkts.csv.gz")
        ses = corpus._mk(fam, f"{fam}:{tag}", r["class"], t, o, s)
        ses.variant, ses.suite, ses.profile = r["variant"], r["suite"], r["profile"]
        (mixed if r["class"] == "mixed" else singles).append(ses)
    return singles, mixed


def lab_d_sessions():
    return [corpus._mk("lab-d", f"lab-d:{d['name']}", d["label"], d["t"], d["out"], d["size"]) for d in E43.lab_d()]


class SoftVote:
    def fit(self, X, y, sample_weight=None):
        kw = dict(n_estimators=TREES, random_state=0, n_jobs=-1, min_samples_leaf=2)
        self.a = RandomForestClassifier(**kw).fit(X, y, sample_weight=sample_weight)
        self.b = ExtraTreesClassifier(**kw).fit(X, y, sample_weight=sample_weight)
        self.classes_ = self.a.classes_
        assert list(self.a.classes_) == list(self.b.classes_) == sorted(corpus.CLASSES), self.a.classes_
        return self

    def predict_proba(self, X):
        return (self.a.predict_proba(X) + self.b.predict_proba(X)) / 2


CLS = sorted(corpus.CLASSES)


class Pool:
    """One base recipe (feature version, augmentation, family list): sessions, windows, copies, and cached out-of-family probabilities."""

    def __init__(self, sessions, version, aug, tag, extra):
        self.s, self.version, self.tag = sessions, version, tag
        self.w = featurize.windows(sessions, version)
        cs, self.src = E42.augmented(sessions) if aug == "e42" else speed_copies(sessions)
        self.cw = featurize.windows(cs, version)
        self.ok = [i for i, w in enumerate(self.w) if len(w) >= MINW]
        self.fams = [f for f in EIGHT + ["lab-e", "lab-h"] if any(sessions[i].family == f for i in self.ok)]
        self.desc = {s.sid: session_desc(s) for s in sessions}
        # sessions that never train: mixed sessions by family, and the external labs (D, F, later G)
        self.extra = {k: [(s, w) for s, w in zip(v, featurize.windows(v, version)) if len(w) >= MINW] for k, v in extra.items()}
        for v in extra.values():
            self.desc.update({s.sid: session_desc(s) for s in v})

    def rows(self, keep):
        ks = set(keep)
        X, y, f = [], [], []
        for i in keep:
            X.append(self.w[i]); y += [self.s[i].label] * len(self.w[i]); f += [self.s[i].family] * len(self.w[i])
        for j, i in enumerate(self.src):
            if i in ks and len(self.cw[j]) >= MINW:
                X.append(self.cw[j]); y += [self.s[i].label] * len(self.cw[j]); f += [self.s[i].family] * len(self.cw[j])
        return np.vstack(X), np.array(y), np.array(f)

    def fit(self, keep):
        X, y, f = self.rows(keep)
        return SoftVote().fit(X, y, sample_weight=E42.weights(f, y))

    def probs(self, excl=()):
        """{sid: window probabilities} from the base model trained without the families in `excl`, for: every scored session of those
        families; their mixed sessions; and, when nothing is excluded, the external labs. Cached on disk (a fit is minutes)."""
        excl = tuple(sorted(excl))
        PCACHE.mkdir(parents=True, exist_ok=True)
        key = PCACHE / f"{self.tag}-t{TREES}-{'+'.join(excl) or 'ALL'}.pkl"
        if key.exists():
            return pickle.load(open(key, "rb"))
        m = self.fit([i for i in self.ok if self.s[i].family not in excl])
        out = {self.s[i].sid: m.predict_proba(self.w[i]).astype(np.float32) for i in self.ok if self.s[i].family in excl}
        for k in ([f"mixed:{f}" for f in excl] if excl else [k for k in self.extra if not k.startswith("mixed:")]):
            for s, w in self.extra.get(k, []):
                out[s.sid] = m.predict_proba(w).astype(np.float32)
        pickle.dump(out, open(key, "wb"))
        print(f"    fit {self.tag} without {excl or 'nothing'}", flush=True)
        return out


def macro(y, p):
    return float(f1_score(y, p, labels=sorted(set(y)), average="macro", zero_division=0))


def per_class(y, p):
    return {c: round(float(v), 3) for c, v in zip(sorted(set(y)), f1_score(y, p, labels=sorted(set(y)), average=None, zero_division=0))}


def s2_row(P, desc):
    return list(P.mean(axis=0)) + list(P.std(axis=0)) + list(desc)


def s2_fit(rows, labels, fams):
    m = RandomForestClassifier(n_estimators=300 if TREES >= 200 else TREES, random_state=0, n_jobs=-1, min_samples_leaf=2) \
        .fit(np.array(rows), np.array(labels), sample_weight=E42.weights(fams, labels))
    assert list(m.classes_) == CLS, m.classes_
    m.n_jobs = 1                                            # it predicts one session at a time
    return m


def s2_train(pool, fams, excl_also=()):
    """Session-stage training rows for the families in `fams`: each family's rows come from the base model without that family
    (and without `excl_also`)."""
    X, y, f = [], [], []
    for g in fams:
        Pg = pool.probs(tuple({g, *excl_also}))
        for i in pool.ok:
            if pool.s[i].family == g:
                X.append(s2_row(Pg[pool.s[i].sid], pool.desc[pool.s[i].sid])); y.append(pool.s[i].label); f.append(g)
    return s2_fit(X, y, f)


def final_probs(spec, pool, P, sid, s2):
    """(class probabilities for the session, window probabilities)."""
    if not spec["stage2"]:
        return P.mean(axis=0), P
    return s2.predict_proba([s2_row(P, pool.desc[sid])])[0], P


# ------------------------------------------------------------------ scoring one candidate
def build_pool(name, base, e_single, e_mixed, h_single, mux, d_ses, f_single, f_mixed, g_all=()):
    spec = CANDIDATES[name]
    sessions = base + e_single + (h_single if spec["lab_h"] else [])
    extra = {"mixed:lab-tgen": mux, "mixed:lab-e": e_mixed, "lab-d": d_ses, "lab-f": f_single + f_mixed}
    if g_all:
        extra["lab-g"] = list(g_all)
    tag = f"{spec['version']}-{spec['aug']}-{'H' if spec['lab_h'] else 'noH'}"
    return Pool(sessions, spec["version"], spec["aug"], tag, extra)


def run_candidate(name, pool):
    spec = CANDIDATES[name]
    lofo, rec = {}, []
    for fam in pool.fams:
        PF = pool.probs((fam,))
        s2 = s2_train(pool, [g for g in pool.fams if g != fam], excl_also=(fam,)) if spec["stage2"] else None
        y, p = [], []
        for i in pool.ok:
            if pool.s[i].family != fam:
                continue
            sid = pool.s[i].sid
            q, P = final_probs(spec, pool, PF[sid], sid, s2)
            y.append(pool.s[i].label); p.append(CLS[int(q.argmax())])
            rec.append({"sid": sid, "fam": fam, "kind": "single", "label": pool.s[i].label, "pred": p[-1], "top": float(q.max()),
                        "agree": float(np.bincount(P.argmax(axis=1)).max() / len(P)), "shape": MX.session_features(P)})
        for s, _ in pool.extra.get(f"mixed:{fam}", []):
            q, P = final_probs(spec, pool, PF[s.sid], s.sid, s2)
            rec.append({"sid": s.sid, "fam": fam, "kind": "mixed", "label": "mixed", "pred": CLS[int(q.argmax())], "top": float(q.max()),
                        "agree": float(np.bincount(P.argmax(axis=1)).max() / len(P)), "shape": MX.session_features(P)})
        lofo[fam] = {"macro_f1": round(macro(y, p), 4), "accuracy": round(float(np.mean([a == b for a, b in zip(y, p)])), 4),
                     "sessions": len(y), "per_class_f1": per_class(y, p)}
        if fam == "usbvpn":
            web = [b for a, b in zip(y, p) if a == "web"]
            lofo[fam]["web_recall"] = round(float(np.mean([b == "web" for b in web])), 4)
            lofo[fam]["web_called"] = dict(Counter(web))
        print(f"  {name} {fam:14} {lofo[fam]['macro_f1']}", flush=True)
    # grouped by session, 5 folds
    ys, ps = [], []
    g = np.arange(len(pool.ok))
    for tr, te in GroupKFold(5).split(g, g, g):
        tr_idx = [pool.ok[j] for j in tr]
        m = pool.fit(tr_idx)
        s2 = None
        if spec["stage2"]:
            X2 = [s2_row(pool.probs((pool.s[i].family,))[pool.s[i].sid], pool.desc[pool.s[i].sid]) for i in tr_idx]
            s2 = s2_fit(X2, [pool.s[i].label for i in tr_idx], [pool.s[i].family for i in tr_idx])
        for j in te:
            i = pool.ok[j]
            q, _ = final_probs(spec, pool, m.predict_proba(pool.w[i]), pool.s[i].sid, s2)
            ys.append(pool.s[i].label); ps.append(CLS[int(q.argmax())])
    # guard: trained on everything, labs D and F ungated
    PA = pool.probs(())
    s2 = s2_train(pool, pool.fams) if spec["stage2"] else None
    guard = {}
    for lab in ("lab-d", "lab-f"):
        y, p = [], []
        for s, _ in pool.extra[lab]:
            if s.label == "mixed":
                continue
            q, _ = final_probs(spec, pool, PA[s.sid], s.sid, s2)
            y.append(s.label); p.append(CLS[int(q.argmax())])
        guard[lab] = {"macro_f1": round(macro(y, p), 4), "sessions": len(y), "per_class_f1": per_class(y, p)}
    eight = [lofo[f]["macro_f1"] for f in EIGHT if f in lofo]
    allf = [v["macro_f1"] for v in lofo.values()]
    return {"lofo": lofo, "lofo_mean_eight": round(float(np.mean(eight)), 4), "lofo_mean_all": round(float(np.mean(allf)), 4),
            "families": pool.fams, "grouped_by_session": round(macro(ys, ps), 4), "guard": guard,
            "scored_sessions": len(pool.ok)}, rec


def choose(R):
    ok = [k for k in CANDIDATES if k in R and R[k]["grouped_by_session"] >= 0.96
          and R[k]["guard"]["lab-d"]["macro_f1"] >= 0.80 and R[k]["guard"]["lab-f"]["macro_f1"] >= 0.70]
    if not ok:
        return None, ok
    best = max(R[k]["lofo_mean_eight"] for k in ok)
    return next(k for k in CANDIDATES if k in ok and R[k]["lofo_mean_eight"] >= best - 0.01), ok


# ------------------------------------------------------------------ the gate, set on held-out families
def nn_bundle(pool, keep):
    rng = np.random.default_rng(0)
    X = np.vstack([pool.w[i] if len(pool.w[i]) <= 30 else pool.w[i][np.sort(rng.choice(len(pool.w[i]), 30, replace=False))] for i in keep])
    sc = StandardScaler().fit(X)
    Xs = sc.transform(X)
    nn = NearestNeighbors(n_neighbors=2).fit(Xs)
    return sc, nn, float(np.percentile(nn.kneighbors(Xs)[0][:, 1], 99))


def ood_share(b, W):
    sc, nn, cut = b
    return float((nn.kneighbors(sc.transform(W), n_neighbors=1)[0][:, 0] > cut).mean())


def det_fit(rows):
    m = RandomForestClassifier(n_estimators=300, random_state=0, min_samples_leaf=2, class_weight="balanced", n_jobs=-1) \
        .fit(np.array([r["shape"] for r in rows]), np.array([r["kind"] for r in rows]))
    m.n_jobs = 1
    return m


def det_score(det, shape):
    if "mixed" not in det.classes_:                         # no mixed session among the training rows: nothing can be flagged
        return 0.0
    return float(det.predict_proba([shape])[0][list(det.classes_).index("mixed")])


TAU_C = [round(x, 2) for x in np.arange(0.30, 0.901, 0.05)]
TAU_M = [round(x, 2) for x in np.arange(0.20, 0.801, 0.05)] + [1.01]
TAU_O = [round(x, 1) for x in np.arange(0.1, 0.91, 0.1)] + [1.0]


def answered(r, tc, tm, to):
    return r["top"] >= tc and r["mixed_score"] < tm and r["ood"] <= to and r["agree"] >= MIN_CONSISTENCY


def set_gate(rec):
    single = [r for r in rec if r["kind"] == "single"]
    mixed = [r for r in rec if r["kind"] == "mixed"]
    fams = sorted({r["fam"] for r in single})
    wt = {f: 1.0 / (len(fams) * sum(1 for r in single if r["fam"] == f)) for f in fams}
    best = None
    for tc in TAU_C:
        for tm in TAU_M:
            for to in TAU_O:
                a = [r for r in single if answered(r, tc, tm, to)]
                share = sum(wt[r["fam"]] for r in a)
                if not a:
                    continue
                acc = sum(wt[r["fam"]] for r in a if r["pred"] == r["label"]) / share
                held = 1 - sum(1 for r in mixed if answered(r, tc, tm, to)) / len(mixed)
                if acc >= 0.90 and held >= 0.80:
                    key = (round(share, 6), tc, -tm, -to)
                    if best is None or key > best[0]:
                        best = (key, {"tau_c": tc, "tau_m": tm, "tau_o": to, "weighted_answered_share": round(share, 4),
                                      "weighted_accuracy_among_answered": round(acc, 4), "mixed_not_answered": round(held, 4),
                                      "answered_by_family": {f: f"{sum(1 for r in a if r['fam'] == f)}/{sum(1 for r in single if r['fam'] == f)}" for f in fams}})
    return best[1] if best else None


def gate_records(pool, rec):
    """Add the leave-one-family-out mixed score and out-of-distribution share to every held-out record."""
    by_sid = {pool.s[i].sid: i for i in pool.ok}
    ex = {s.sid: w for k, v in pool.extra.items() if k.startswith("mixed:") for s, w in v}
    for fam in pool.fams:
        mine = [r for r in rec if r["fam"] == fam]
        det = det_fit([r for r in rec if r["fam"] != fam])
        b = nn_bundle(pool, [i for i in pool.ok if pool.s[i].family != fam])
        for r in mine:
            r["mixed_score"] = det_score(det, r["shape"])
            r["ood"] = ood_share(b, pool.w[by_sid[r["sid"]]] if r["sid"] in by_sid else ex[r["sid"]])
        print(f"    gate scores for {fam}", flush=True)
    return rec


# ------------------------------------------------------------------ stages
def load_all(with_g=False):
    base = corpus.load()
    if "EXP51_FAMILIES" in os.environ:
        base = [s for s in base if s.family in os.environ["EXP51_FAMILIES"].split(",")]
    elif [f for f in EIGHT if not any(s.family == f for s in base)]:
        sys.exit("families missing from the corpus (set TUNNELSCOPE_LAB_A / TUNNELSCOPE_LAB_B and the datasets)")
    e_single, e_mixed = E45.exp45_sessions("E")
    f_single, f_mixed = E45.exp45_sessions("F")
    h_single, _ = exp51_sessions("H")
    g = exp51_sessions("G") if with_g else ([], [])
    return dict(base=base, e_single=e_single, e_mixed=e_mixed, h_single=h_single, mux=E44.mux_sessions(), d_ses=lab_d_sessions(),
                f_single=f_single, f_mixed=f_mixed, g_all=g[0] + g[1]), g


def stage_lofo(names):
    RES.mkdir(parents=True, exist_ok=True)
    D, _ = load_all()
    part = RES / "partial.json"
    R = json.load(open(part)) if part.exists() else {}
    for name in names or list(CANDIDATES):
        if name in R:
            print(f"== {name} (already scored)", flush=True); continue
        if CANDIDATES[name]["lab_h"] and not D["h_single"]:
            print(f"== {name} skipped: no lab-H tables yet", flush=True); continue
        print(f"== {name}", flush=True)
        pool = build_pool(name, **D)
        R[name], rec = run_candidate(name, pool)
        pickle.dump(rec, open(RES / f"heldout_{name}.pkl", "wb"))
        json.dump(R, open(part, "w"), indent=1)
    print({k: (v["lofo_mean_eight"], v["lofo_mean_all"], v["grouped_by_session"], v["guard"]["lab-d"]["macro_f1"],
               v["guard"]["lab-f"]["macro_f1"], v["lofo"].get("usbvpn", {}).get("macro_f1")) for k, v in R.items()})


def stage_choose():
    R = json.load(open(RES / "partial.json"))
    missing = [k for k in CANDIDATES if k not in R]
    if missing and not REHEARSAL:
        sys.exit(f"not scored yet: {missing}")
    chosen, ok = choose(R)
    if REHEARSAL and "EXP51_FORCE" in os.environ:          # rehearsal only: exercise the gate and lab-G code paths
        chosen = os.environ["EXP51_FORCE"]
    C = {"eligible": ok, "chosen": chosen,
         "P51-1": {"R1": R["R1"]["lofo_mean_eight"], "R0": R["R0"]["lofo_mean_eight"],
                   "gain": round(R["R1"]["lofo_mean_eight"] - R["R0"]["lofo_mean_eight"], 4),
                   "pass": R["R1"]["lofo_mean_eight"] - R["R0"]["lofo_mean_eight"] >= 0.03},
         "P51-2": {"R2_usbvpn": R["R2"]["lofo"]["usbvpn"]["macro_f1"], "web_recall": R["R2"]["lofo"]["usbvpn"]["web_recall"],
                   "pass": R["R2"]["lofo"]["usbvpn"]["macro_f1"] >= 0.20 and R["R2"]["lofo"]["usbvpn"]["web_recall"] >= 0.50}}
    if chosen:
        C["P51-3"] = {"chosen_mean_eight": R[chosen]["lofo_mean_eight"], "pass": R[chosen]["lofo_mean_eight"] >= 0.57}
        C["P51-4"] = {"grouped_by_session": R[chosen]["grouped_by_session"], "pass": True}
        C["guard"] = {k: R[chosen]["guard"][k]["macro_f1"] for k in ("lab-d", "lab-f")}
        D, _ = load_all()
        pool = build_pool(chosen, **D)
        rec = gate_records(pool, pickle.load(open(RES / f"heldout_{chosen}.pkl", "rb")))
        pickle.dump(rec, open(RES / f"heldout_{chosen}.pkl", "wb"))
        C["gate"] = set_gate(rec)
        C["gate_inputs"] = {"single": sum(1 for r in rec if r["kind"] == "single"), "mixed": sum(1 for r in rec if r["kind"] == "mixed")}
    json.dump(C, open(RES / "choice.json", "w"), indent=1)
    print(json.dumps(C, indent=1))


def stage_labg():
    C = json.load(open(RES / "choice.json"))
    chosen = C["chosen"]
    if not chosen:
        sys.exit("no candidate was chosen: nothing to test on lab G")
    D, (g_single, g_mixed) = load_all(with_g=True)
    if not g_single:
        sys.exit("no lab-G tables")
    spec = CANDIDATES[chosen]
    pool = build_pool(chosen, **D)
    m = pool.fit(pool.ok)                                   # the model that would ship (lab G is not in the cached ALL probabilities)
    s2 = s2_train(pool, pool.fams) if spec["stage2"] else None
    rec = pickle.load(open(RES / f"heldout_{chosen}.pkl", "rb"))
    det, nnb, gate = det_fit(rec), nn_bundle(pool, pool.ok), C.get("gate")
    ship = E45.shipped_bundle()
    rows = []
    for s in g_single + g_mixed:
        W2 = np.array(features_v2.v2(s.t, s.out, s.size))
        r = {"sid": s.sid, "label": s.label, "variant": s.variant, "suite": s.suite, "profile": s.profile, "windows": len(W2)}
        r["S_stage"], r["S_answer"], r["S_flagged"] = E45.gate(ship, W2, None) if len(W2) else ("insufficient", None, False)
        if len(W2) >= MINW:
            r["S_ungated"] = E45.session_pred(ship["m"], W2)
            W = np.array(v3(s.t, s.out, s.size)) if spec["version"] == "v3" else W2
            P = m.predict_proba(W)
            q = s2.predict_proba([s2_row(P, session_desc(s))])[0] if spec["stage2"] else P.mean(axis=0)
            r["C_ungated"] = CLS[int(q.argmax())]
            g = {"top": float(q.max()), "agree": float(np.bincount(P.argmax(axis=1)).max() / len(P)),
                 "mixed_score": det_score(det, MX.session_features(P)), "ood": ood_share(nnb, W)}
            r.update({f"C_{k}": round(v, 4) for k, v in g.items()})
            ans = bool(gate) and answered(g, gate["tau_c"], gate["tau_m"], gate["tau_o"])
            r["C_stage"], r["C_answer"] = ("answered", r["C_ungated"]) if ans else ("not_answered", None)
        else:
            r["C_stage"], r["C_answer"] = "insufficient", None
        rows.append(r)
    single = [r for r in rows if r["label"] != "mixed"]; mixed = [r for r in rows if r["label"] == "mixed"]
    sc = [r for r in single if r["windows"] >= MINW]
    y = [r["label"] for r in sc]

    def gs(rs, arm):
        a = [r for r in rs if r[f"{arm}_stage"] == "answered"]
        right = sum(1 for r in a if r[f"{arm}_answer"] == r["label"])
        return {"sessions": len(rs), "answered": len(a), "correct": right, "answered_share": round(len(a) / len(rs), 4) if rs else None,
                "accuracy_among_answered": round(right / len(a), 4) if a else None,
                "stages": dict(Counter(r[f"{arm}_stage"] for r in rs))}
    S = {"chosen": chosen, "gate": gate, "candidates": json.load(open(RES / "partial.json")), "choice": C,
         "lab_g": {"single_captured": len(single), "single_scored": len(sc), "mixed_captured": len(mixed),
                   "S_ungated_macro_f1": round(macro(y, [r["S_ungated"] for r in sc]), 4),
                   "C_ungated_macro_f1": round(macro(y, [r["C_ungated"] for r in sc]), 4),
                   "S_per_class_f1": per_class(y, [r["S_ungated"] for r in sc]), "C_per_class_f1": per_class(y, [r["C_ungated"] for r in sc]),
                   "by_profile_C": {p: round(macro([r["label"] for r in sc if r["profile"] == p], [r["C_ungated"] for r in sc if r["profile"] == p]), 4)
                                    for p in sorted({r["profile"] for r in sc})},
                   "gated_single": {a: gs(single, a) for a in ("S", "C")}, "gated_mixed": {a: gs(mixed, a) for a in ("S", "C")}}}
    G = S["lab_g"]
    S["P51-5"] = {"chosen": G["C_ungated_macro_f1"], "shipped": G["S_ungated_macro_f1"],
                  "gain": round(G["C_ungated_macro_f1"] - G["S_ungated_macro_f1"], 4),
                  "pass": G["C_ungated_macro_f1"] - G["S_ungated_macro_f1"] >= 0.10}
    c = G["gated_single"]["C"]
    S["P51-6"] = {**c, "pass": bool(c["accuracy_among_answered"] is not None and c["accuracy_among_answered"] >= 0.90 and c["answered_share"] >= 0.50)}
    cm = G["gated_mixed"]["C"]
    S["P51-7"] = {"not_answered": cm["sessions"] - cm["answered"], "n": cm["sessions"],
                  "pass": bool(cm["sessions"]) and (cm["sessions"] - cm["answered"]) / cm["sessions"] >= 0.80}
    S["ship"] = bool(S["P51-5"]["pass"] and S["P51-6"]["pass"] and S["P51-7"]["pass"])
    with open(RES / "lab_g_sessions.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=sorted({k for r in rows for k in r})); w.writeheader(); w.writerows(rows)
    json.dump(S, open(RES / "summary.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in S.items() if k not in ("candidates", "choice")}, indent=1))


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else ""
    if stage == "lofo":
        stage_lofo(sys.argv[2:])
    elif stage == "choose":
        stage_choose()
    elif stage == "labg":
        stage_labg()
    else:
        sys.exit(__doc__)
