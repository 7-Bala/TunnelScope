"""EXP-52 scorer (pre-registered in PREREG.md, commit 48a8307). Committed before any network is trained or any candidate scored.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp52-sequence-net/analyze.py check
    ... analyze.py lofo           (S0, N1, N2, E1, E2 leave-one-family-out, grouped, guard)
    ... analyze.py choose         (choice rule and the gate for the chosen candidate; BEFORE lab I exists)
    ... analyze.py export DIR     (windows + folds for a Colab GPU; colab_train.py trains every fold there)
    ... analyze.py ingest FILE    (probabilities from Colab -> the cache `lofo` reads; FILE sits next to folds.json)

The forest (S0 = R6) is EXP-51's own code (`experiments/exp51-rate-invariance/analyze.py`, imported, not copied): same sessions, same
windows, same leave-one-family-out models and their cached window probabilities. The network scores exactly the windows the forest
scores: the same 2-s buckets, >= 3 packets, complete windows, and the same seeded choice of at most 60 windows per session
(`build/models/featurize.py`). `check` asserts that row counts agree for every session before anything is trained.

Readings of the PREREG fixed here, before any candidate is scored (each is repeated in the RESULT):
  - "Validation split from the training families": 10% of the training sessions, chosen by a seeded hash of the session id, never a
    held-out family's session; early stopping on the weighted validation loss, best epoch's weights kept.
  - Class weights "as R6": EXP-42's `weights(family, label)` used as per-window loss weights (every family equal, every class equal
    inside a family), on the training windows and the augmented copies alike.
  - The augmented copy: one per training window, all gaps of the window multiplied by one factor drawn log-uniformly from 0.8 to 1.25
    (seeded by session id and window number); sizes and directions unchanged.
  - Three seeds (0, 1, 2) per trained model; their window probabilities are averaged.
  - E1/E2 window probabilities: (1 - w) * forest + w * network, per window; the session is the mean over its windows, as R6.
  - Grouped by session: the same 5 GroupKFold folds over the forest's scored sessions as EXP-51 (the forest re-fitted per fold here,
    and the network trained per fold), so S0's grouped score is recomputed, not copied.
  - Guard: models trained on every family, ungated session macro-F1 on lab D (32) and lab F's singles.
  - The "eight" mean is over EXP-42's original eight families, as EXP-51.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pickle
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupKFold

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "build" / "models")); sys.path.insert(0, str(HERE))


def _load(name, rel):
    s = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m


E51 = _load("exp51", "experiments/exp51-rate-invariance/analyze.py")
corpus, featurize, E42 = E51.corpus, E51.featurize, E51.E42

# Labs A and B (public data sets, not redistributed here). Their pcap clones are gone and GitHub was too slow to clone them again, so
# their sessions are rebuilt from the packet streams EXP-51 extracted and cached (`.corpus_cache/lab-a.pkl`, `lab-b.pkl`: the same
# (t, out, size) arrays the corpus loader builds), with the labels read from the two small files at the pinned commits:
#   lab A: naman9271/ipsec-pcap-lab c0cf256  metadata.csv  ->  ~/Datasets/labs/lab-a-metadata.csv  (column canonical_label)
#   lab B: ashwin02-cyber/SIH_2026 ef0ffe9   manifest.csv  ->  ~/Datasets/labs/lab-b-manifest.csv  (column traffic_class)
# Same session ids, same class mapping (file_transfer -> bulk), same order as `build/models/corpus.py`; the counts are checked
# (175 and 180 sessions, none unlabelled), and `check` still compares every window with the forest's.
LABELS = Path(os.environ.get("EXP52_LABELS", Path.home() / "Datasets" / "labs"))


def _lab_from_cache(name, family, labeller):
    import csv as _csv
    c = pickle.load(open(corpus.CACHE / f"{name}.pkl", "rb"))
    out = []
    for (path, _size), r in zip(c["sig"], c["res"]):
        if "error" in r:
            continue
        out.append(corpus._mk(family, f"{family}:{os.path.basename(path)}", labeller(path), r["t"], r["out"], r["size"]))
    return out


def _lab_a():
    import csv as _csv
    meta = {r["pcap_path"]: r["canonical_label"] for r in _csv.DictReader(open(LABELS / "lab-a-metadata.csv"))}
    m = {"file_transfer": "bulk"}
    cut = "ipsec-pcap-lab/"
    return _lab_from_cache("lab-a", "lab-a", lambda p: m.get(meta[p.split(cut, 1)[1]], meta[p.split(cut, 1)[1]]))


def _lab_b():
    import csv as _csv
    man = {r["filename"]: r["traffic_class"] for r in _csv.DictReader(open(LABELS / "lab-b-manifest.csv"))}
    m = {"file_transfer": "bulk"}
    return _lab_from_cache("lab-b", "lab-b", lambda p: m.get(man[os.path.basename(p)], man[os.path.basename(p)]))


corpus.LOADERS["lab-a"], corpus.LOADERS["lab-b"] = _lab_a, _lab_b

RES = HERE / "results"
NCACHE = corpus.CACHE / "exp52-net"
CLS = E51.CLS
EIGHT = E51.EIGHT
from netlib import L, EPOCHS, PATIENCE, BATCH, LR, SEEDS, encode, make_net, _dev, train_one, predict  # noqa: E402
WEIGHTS = (0.25, 0.5, 0.75)


# ------------------------------------------------------------------ sequences, aligned with the forest's windows
def seq_windows(s) -> tuple[np.ndarray, np.ndarray]:
    """-> (X [n, L, 3] float32: direction, log2(size)/11, raw gap seconds; lengths [n]) for the windows the forest keeps, same order.
    The gap channel is kept raw here and transformed in `encode`, so augmentation can scale it."""
    t = np.asarray(s.t, float); out = np.asarray(s.out, bool); size = np.asarray(s.size, float)
    if len(t) == 0:
        return np.zeros((0, L, 3), np.float32), np.zeros(0, int)
    idx = ((t - t[0]) // E51.WIN).astype(int)
    last_full = int((t[-1] - t[0]) // E51.WIN) - 1
    rows, lens = [], []
    for w in np.unique(idx):
        m = np.flatnonzero(idx == w)
        if len(m) < 3 or w > last_full:
            continue
        if len(m) > L:                                    # evenly spaced, first and last kept
            m = m[np.unique(np.round(np.linspace(0, len(m) - 1, L)).astype(int))]
        tw = t[m]
        gap = np.concatenate([[0.0], np.diff(tw)])
        x = np.zeros((L, 3), np.float32)
        x[:len(m), 0] = np.where(out[m], 1.0, -1.0)
        x[:len(m), 1] = np.log2(np.maximum(size[m], 1)) / 11.0
        x[:len(m), 2] = gap
        rows.append(x); lens.append(len(m))
    if len(rows) > featurize.CAP:                         # featurize._one's seeded choice, same seed, same draw
        rng = np.random.default_rng(int(hashlib.sha256(s.sid.encode()).hexdigest()[:8], 16))
        keep = sorted(rng.choice(len(rows), featurize.CAP, replace=False))
        rows, lens = [rows[j] for j in keep], [lens[j] for j in keep]
    if not rows:
        return np.zeros((0, L, 3), np.float32), np.zeros(0, int)
    return np.stack(rows), np.array(lens)


# ------------------------------------------------------------------ data
class Seqs:
    """Sequences for every session the forest pool scores, plus its extra (mixed, lab D, lab F) sessions."""

    def __init__(self, pool):
        self.pool = pool
        self.by_sid = {}
        for i in pool.ok:
            self.by_sid[pool.s[i].sid] = seq_windows(pool.s[i])
        for v in pool.extra.values():
            for s, _ in v:
                self.by_sid[s.sid] = seq_windows(s)

    def check(self):
        bad = []
        for i in self.pool.ok:
            s = self.pool.s[i]
            if len(self.by_sid[s.sid][0]) != len(self.pool.w[i]):
                bad.append((s.sid, len(self.by_sid[s.sid][0]), len(self.pool.w[i])))
        for v in self.pool.extra.values():
            for s, w in v:
                if len(self.by_sid[s.sid][0]) != len(w):
                    bad.append((s.sid, len(self.by_sid[s.sid][0]), len(w)))
        return bad

    def training(self, idx):
        X, Ln, y, f, sc = [], [], [], [], []
        for i in idx:
            s = self.pool.s[i]
            Xi, Li = self.by_sid[s.sid]
            X.append(Xi); Ln.append(Li); y += [CLS.index(s.label)] * len(Li); f += [s.family] * len(Li)
            for k in range(len(Li)):
                r = np.random.default_rng(int(hashlib.sha256(f"{s.sid}#gap{k}".encode()).hexdigest()[:8], 16))
                sc.append(float(np.exp(r.uniform(np.log(0.8), np.log(1.25)))))
        y = np.array(y)
        w = E42.weights(np.array(f), np.array([CLS[k] for k in y]))
        return np.concatenate(X), np.concatenate(Ln), y, w, np.array(sc, np.float32)


def _is_val(sid):
    return int(hashlib.sha256(f"{sid}#val".encode()).hexdigest()[:8], 16) % 10 == 0


def net_probs(seqs, train_idx, score_sids, tag, use_gap):
    """{sid: window probabilities} from the network trained on `train_idx` (3 seeds averaged). Cached on disk."""
    NCACHE.mkdir(parents=True, exist_ok=True)
    key = NCACHE / f"{tag}-{'gap' if use_gap else 'nogap'}.pkl"
    if key.exists():
        return pickle.load(open(key, "rb"))
    pool = seqs.pool
    tr = [i for i in train_idx if not _is_val(pool.s[i].sid)]
    va = [i for i in train_idx if _is_val(pool.s[i].sid)]
    Xtr, Ltr, ytr, wtr, sc = seqs.training(tr)
    Xva, Lva, yva, wva, _ = seqs.training(va)
    out, info = {sid: 0.0 for sid in score_sids}, []
    t0 = time.time()
    for seed in SEEDS:
        net, inf = train_one(Xtr, Ltr, ytr, wtr, Xva, Lva, yva, wva, seed, use_gap, sc)
        info.append(inf)
        for sid in score_sids:
            X, Ln = seqs.by_sid[sid]
            out[sid] = out[sid] + predict(net, X, Ln, use_gap) / len(SEEDS)
    out = {k: np.asarray(v, np.float32) for k, v in out.items()}
    pickle.dump(out, open(key, "wb"))
    json.dump({"tag": tag, "use_gap": use_gap, "train_windows": int(len(ytr)), "val_windows": int(len(yva)), "seeds": info,
               "seconds": round(time.time() - t0, 1)}, open(key.with_suffix(".json"), "w"))
    print(f"    trained {tag} {'gap' if use_gap else 'nogap'}: {info} in {time.time() - t0:.0f}s", flush=True)
    return out


# ------------------------------------------------------------------ scoring
def session_pred(P):
    q = P.mean(axis=0)
    return CLS[int(q.argmax())], q


def blend(Pf, Pn, w):
    return (1 - w) * Pf + w * Pn


def evaluate(pool, seqs):
    """Window probabilities for every arm (S0, N1, N2) on: held-out families, grouped folds, and the all-family guard models."""
    fams = pool.fams
    held = {"S0": {}, "N1": {}, "N2": {}}
    for fam in fams:
        PF = pool.probs((fam,))                                   # EXP-51's cached R6 out-of-family probabilities
        sids = [pool.s[i].sid for i in pool.ok if pool.s[i].family == fam] + [s.sid for s, _ in pool.extra.get(f"mixed:{fam}", [])]
        tr = [i for i in pool.ok if pool.s[i].family != fam]
        for arm, gap in (("N1", True), ("N2", False)):
            held[arm].update(net_probs(seqs, tr, sids, f"lofo-{fam}", gap))
        held["S0"].update({sid: PF[sid] for sid in sids})
    grouped = {"S0": {}, "N1": {}, "N2": {}}
    g = np.arange(len(pool.ok))
    for k, (tr, te) in enumerate(GroupKFold(5).split(g, g, g)):
        tr_idx = [pool.ok[j] for j in tr]; te_idx = [pool.ok[j] for j in te]
        gkey = corpus.CACHE / "exp52-net" / f"forest-grouped-{k}.pkl"
        if gkey.exists():
            gp = pickle.load(open(gkey, "rb"))
        else:
            m = pool.fit(tr_idx)
            gp = {pool.s[i].sid: m.predict_proba(pool.w[i]).astype(np.float32) for i in te_idx}
            gkey.parent.mkdir(parents=True, exist_ok=True); pickle.dump(gp, open(gkey, "wb"))
        grouped["S0"].update(gp)
        sids = [pool.s[i].sid for i in te_idx]
        for arm, gap in (("N1", True), ("N2", False)):
            grouped[arm].update(net_probs(seqs, tr_idx, sids, f"grouped-{k}", gap))
    allp = {"S0": pool.probs(())}
    ext = [s.sid for k in ("lab-d", "lab-f") for s, _ in pool.extra[k]]
    for arm, gap in (("N1", True), ("N2", False)):
        allp[arm] = net_probs(seqs, list(pool.ok), ext, "all", gap)
    return held, grouped, allp


def arm_probs(name, w, src):
    if name in ("S0", "N1", "N2"):
        return src[name]
    net = "N1" if name == "E1" else "N2"
    return {sid: blend(src["S0"][sid], src[net][sid], w) for sid in src["S0"] if sid in src[net]}


def score(pool, name, w, held, grouped, allp):
    lofo, rec = {}, []
    H = arm_probs(name, w, held)
    for fam in pool.fams:
        y, p = [], []
        for i in pool.ok:
            if pool.s[i].family != fam:
                continue
            sid = pool.s[i].sid; P = H[sid]; lab, q = session_pred(P)
            y.append(pool.s[i].label); p.append(lab)
            rec.append({"sid": sid, "fam": fam, "kind": "single", "label": pool.s[i].label, "pred": lab, "top": float(q.max()),
                        "agree": float(np.bincount(P.argmax(axis=1)).max() / len(P)), "shape": E51.MX.session_features(P)})
        for s, _ in pool.extra.get(f"mixed:{fam}", []):
            P = H[s.sid]; lab, q = session_pred(P)
            rec.append({"sid": s.sid, "fam": fam, "kind": "mixed", "label": "mixed", "pred": lab, "top": float(q.max()),
                        "agree": float(np.bincount(P.argmax(axis=1)).max() / len(P)), "shape": E51.MX.session_features(P)})
        lofo[fam] = {"macro_f1": round(E51.macro(y, p), 4), "sessions": len(y), "per_class_f1": E51.per_class(y, p)}
    G = arm_probs(name, w, grouped)
    ys = [pool.s[i].label for i in pool.ok]; ps = [session_pred(G[pool.s[i].sid])[0] for i in pool.ok]
    A = arm_probs(name, w, allp)
    guard = {}
    for lab in ("lab-d", "lab-f"):
        y = [s.label for s, _ in pool.extra[lab] if s.label != "mixed"]
        p = [session_pred(A[s.sid])[0] for s, _ in pool.extra[lab] if s.label != "mixed"]
        guard[lab] = {"macro_f1": round(E51.macro(y, p), 4), "sessions": len(y), "per_class_f1": E51.per_class(y, p)}
    eight = [lofo[f]["macro_f1"] for f in EIGHT if f in lofo]
    return {"w": w, "lofo": lofo, "lofo_mean_eight": round(float(np.mean(eight)), 4),
            "lofo_mean_all": round(float(np.mean([v["macro_f1"] for v in lofo.values()])), 4),
            "grouped_by_session": round(E51.macro(ys, ps), 4), "guard": guard}, rec


# ------------------------------------------------------------------ stages
def build():
    D, _ = E51.load_all()
    pool = E51.build_pool("R6", **D)
    return pool, Seqs(pool)


def stage_check():
    import netlib
    rng = np.random.default_rng(0)
    f = rng.choice(["a", "b", "c"], 500); y = rng.choice(CLS, 500)
    assert np.allclose(netlib.weights(f, y), E42.weights(f, y)), "netlib.weights differs from EXP-42's"
    assert netlib.CLASSES == CLS
    pool, seqs = build()
    bad = seqs.check()
    n = len(pool.ok) + sum(len(v) for v in pool.extra.values())
    print(f"sessions checked: {n}; windows: {sum(len(pool.w[i]) for i in pool.ok)}; mismatched sessions: {len(bad)}")
    for b in bad[:20]:
        print("  ", b)
    sys.exit(1 if bad else 0)


def stage_lofo():
    RES.mkdir(parents=True, exist_ok=True)
    pool, seqs = build()
    bad = seqs.check()
    if bad:
        sys.exit(f"{len(bad)} sessions whose network windows do not match the forest's; nothing scored")
    held, grouped, allp = evaluate(pool, seqs)
    R, recs = {}, {}
    for name in ("S0", "N1", "N2"):
        R[name], recs[name] = score(pool, name, None, held, grouped, allp)
    for name in ("E1", "E2"):
        for w in WEIGHTS:
            R[f"{name}@{w}"], recs[f"{name}@{w}"] = score(pool, name, w, held, grouped, allp)
    json.dump(R, open(RES / "partial.json", "w"), indent=1)
    pickle.dump(recs, open(RES / "heldout.pkl", "wb"))
    print({k: (v["lofo_mean_eight"], v["grouped_by_session"], v["guard"]["lab-d"]["macro_f1"], v["guard"]["lab-f"]["macro_f1"])
           for k, v in R.items()})


def stage_choose():
    R = json.load(open(RES / "partial.json"))
    s0 = R["S0"]["lofo_mean_eight"]
    C = {"P52-0": {"S0": s0, "R6_exp51": 0.561, "pass": abs(s0 - 0.561) <= 0.005}}
    if not C["P52-0"]["pass"]:
        json.dump(C, open(RES / "choice.json", "w"), indent=1)
        sys.exit("P52-0 failed: the scorer does not reproduce R6; nothing is chosen")
    C["P52-1"] = {"N1": R["N1"]["lofo_mean_eight"], "pass": R["N1"]["lofo_mean_eight"] >= 0.50}
    best_w = {}
    for name in ("E1", "E2"):
        w = max(WEIGHTS, key=lambda x: (R[f"{name}@{x}"]["lofo_mean_eight"], -WEIGHTS.index(x)))
        best_w[name] = w
    C["weights"] = best_w
    ok = [n for n in ("E1", "E2") if R[f"{n}@{best_w[n]}"]["grouped_by_session"] >= 0.96
          and R[f"{n}@{best_w[n]}"]["guard"]["lab-d"]["macro_f1"] >= 0.80 and R[f"{n}@{best_w[n]}"]["guard"]["lab-f"]["macro_f1"] >= 0.70]
    C["eligible"] = ok
    chosen = max(ok, key=lambda n: (R[f"{n}@{best_w[n]}"]["lofo_mean_eight"], -["E1", "E2"].index(n))) if ok else None
    if chosen and R[f"{chosen}@{best_w[chosen]}"]["lofo_mean_eight"] < s0 + 0.01:
        chosen = None
    key = f"{chosen}@{best_w[chosen]}" if chosen else "S0"
    C["chosen"] = key
    C["P52-2"] = {"chosen_eight": R[key]["lofo_mean_eight"], "S0": s0, "gain": round(R[key]["lofo_mean_eight"] - s0, 4),
                  "pass": bool(chosen) and R[key]["lofo_mean_eight"] - s0 >= 0.03}
    C["P52-3"] = {"grouped_by_session": R[key]["grouped_by_session"], "pass": R[key]["grouped_by_session"] >= 0.96}
    C["guard"] = {k: R[key]["guard"][k]["macro_f1"] for k in ("lab-d", "lab-f")}
    pool, seqs = build()
    rec = pickle.load(open(RES / "heldout.pkl", "rb"))[key]
    rec = E51.gate_records(pool, rec)
    C["gate"] = E51.set_gate(rec)
    json.dump(C, open(RES / "choice.json", "w"), indent=1)
    print(json.dumps(C, indent=1))


def _folds(pool):
    """Every training fold `evaluate` uses, as (tag, train session indices into pool.s, score session ids)."""
    out = []
    for fam in pool.fams:
        sids = [pool.s[i].sid for i in pool.ok if pool.s[i].family == fam] + [s.sid for s, _ in pool.extra.get(f"mixed:{fam}", [])]
        out.append((f"lofo-{fam}", [i for i in pool.ok if pool.s[i].family != fam], sids))
    g = np.arange(len(pool.ok))
    for k, (tr, te) in enumerate(GroupKFold(5).split(g, g, g)):
        out.append((f"grouped-{k}", [pool.ok[j] for j in tr], [pool.s[pool.ok[j]].sid for j in te]))
    out.append(("all", list(pool.ok), [s.sid for k in ("lab-d", "lab-f") for s, _ in pool.extra[k]]))
    return out


def stage_export(outdir):
    """Write what a Colab GPU needs to train every fold: the window sequences and the folds. No forest probabilities, no gate,
    no scoring code: those stay here. Raw pcaps and configs are never involved; this is packet direction, size and gap per window."""
    out = Path(outdir); out.mkdir(parents=True, exist_ok=True)
    pool, seqs = build()
    if seqs.check():
        sys.exit("windows do not line up with the forest's; nothing exported")
    sid_list = sorted(seqs.by_sid)
    sid_id = {sid: j for j, sid in enumerate(sid_list)}
    meta_s = {}
    for i in pool.ok:
        meta_s[pool.s[i].sid] = (pool.s[i].label, pool.s[i].family)
    X, Ln, y, fam, sidw, sc = [], [], [], [], [], []
    fams = sorted({f for _, f in meta_s.values()})
    for sid in sid_list:
        Xi, Li = seqs.by_sid[sid]
        lab, fm = meta_s.get(sid, (None, None))
        X.append(Xi); Ln.append(Li)
        y += [CLS.index(lab) if lab else -1] * len(Li)
        fam += [fams.index(fm) if fm else -1] * len(Li)
        sidw += [sid_id[sid]] * len(Li)
        for k in range(len(Li)):
            r = np.random.default_rng(int(hashlib.sha256(f"{sid}#gap{k}".encode()).hexdigest()[:8], 16))
            sc.append(float(np.exp(r.uniform(np.log(0.8), np.log(1.25)))))
    np.savez_compressed(out / "windows.npz", X=np.concatenate(X), lens=np.concatenate(Ln).astype(np.int16), y=np.array(y, np.int8),
                        fam=np.array(fam, np.int8), sid=np.array(sidw, np.int32), scale=np.array(sc, np.float32))
    folds = {tag: {"train": sorted(sid_id[pool.s[i].sid] for i in tr), "score": [sid_id[x] for x in sc_sids]}
             for tag, tr, sc_sids in _folds(pool)}
    is_val = [int(_is_val(sid)) for sid in sid_list]
    json.dump({"classes": CLS, "families": fams, "sids": sid_list, "is_val": is_val, "folds": folds,
               "settings": {"L": L, "epochs": EPOCHS, "patience": PATIENCE, "batch": BATCH, "lr": LR, "seeds": list(SEEDS)}},
              open(out / "folds.json", "w"))
    import shutil
    shutil.copy(HERE / "netlib.py", out / "netlib.py"); shutil.copy(HERE / "colab_train.py", out / "colab_train.py")
    mb = sum(f.stat().st_size for f in out.iterdir()) / 1e6
    print(f"exported {len(sid_list)} sessions, {len(sidw)} windows, {len(folds)} folds, {mb:.1f} MB to {out}")


def stage_ingest(path):
    """Read the probabilities `colab_train.py` wrote and store them where `net_probs` looks, so `lofo` finds every fold cached."""
    z = np.load(path, allow_pickle=False)
    meta = json.load(open(Path(path).parent / "folds.json"))
    sids, sidw = meta["sids"], z["sid"]
    NCACHE.mkdir(parents=True, exist_ok=True)
    n = 0
    for key in [k for k in z.files if k.startswith("P|")]:
        _, tag, variant = key.split("|")
        P, widx = z[key], z[f"I|{tag}"]
        out = {}
        for sid_j in np.unique(sidw[widx]):
            out[sids[sid_j]] = P[sidw[widx] == sid_j].astype(np.float32)
        pickle.dump(out, open(NCACHE / f"{tag}-{variant}.pkl", "wb"))
        n += 1
    print(f"stored {n} (fold, variant) probability files in {NCACHE}")


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else ""
    if stage == "export":
        stage_export(sys.argv[2])
    elif stage == "ingest":
        stage_ingest(sys.argv[2])
    else:
        {"check": stage_check, "lofo": stage_lofo, "choose": stage_choose}.get(stage, lambda: sys.exit(__doc__))()
