"""EXP-52 scorer (pre-registered in PREREG.md, commit 48a8307). Committed before any network is trained or any candidate scored.

    TUNNELSCOPE_LAB_A=... TUNNELSCOPE_LAB_B=... .venv/bin/python experiments/exp52-sequence-net/analyze.py check
    ... analyze.py lofo           (S0, N1, N2, E1, E2 leave-one-family-out, grouped, guard)
    ... analyze.py choose         (choice rule and the gate for the chosen candidate; BEFORE lab I exists)

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
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "build" / "models"))


def _load(name, rel):
    s = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m


E51 = _load("exp51", "experiments/exp51-rate-invariance/analyze.py")
corpus, featurize, E42 = E51.corpus, E51.featurize, E51.E42

RES = HERE / "results"
NCACHE = corpus.CACHE / "exp52-net"
CLS = E51.CLS
EIGHT = E51.EIGHT
L = 256                       # packets per window seen by the network (PREREG section 4)
SEEDS = (0, 1, 2)
EPOCHS, PATIENCE, BATCH, LR = 30, 5, 256, 1e-3
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


def encode(X, lens, use_gap=True, scale=None):
    """Raw windows -> network input [n, 3, L] and mask [n, L]. Gap: log10(max(gap * scale, 1e-6)) / 6, first packet 0."""
    X = X.copy()
    mask = np.arange(L)[None, :] < lens[:, None]
    g = X[:, :, 2] * (scale[:, None] if scale is not None else 1.0)
    first = np.zeros_like(mask); first[:, 0] = True
    X[:, :, 2] = np.where(mask & ~first, np.log10(np.maximum(g, 1e-6)) / 6.0, 0.0) if use_gap else 0.0
    X[~mask] = 0.0
    return np.ascontiguousarray(X.transpose(0, 2, 1)), mask.astype(np.float32)


# ------------------------------------------------------------------ the network (PREREG section 5)
def make_net():
    import torch
    from torch import nn

    class Block(nn.Module):
        def __init__(self, a, b):
            super().__init__()
            self.c, self.n = nn.Conv1d(a, b, 5, padding=2), nn.BatchNorm1d(b)

        def forward(self, x):
            return torch.relu(self.n(self.c(x)))

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            self.b = nn.Sequential(Block(3, 64), Block(64, 64), Block(64, 128))
            self.h, self.o = nn.Linear(256, 64), nn.Linear(64, len(CLS))

        def forward(self, x, m):
            z = self.b(x)                                  # [n, 128, L]
            mm = m[:, None, :]
            mean = (z * mm).sum(-1) / mm.sum(-1).clamp(min=1)
            mx = z.masked_fill(mm == 0, float("-inf")).max(-1).values
            return self.o(torch.relu(self.h(torch.cat([mean, mx], 1))))
    return Net()


def _dev():
    import torch
    return torch.device("mps" if torch.backends.mps.is_available() else "cpu")


def train_one(Xtr, Ltr, ytr, wtr, Xva, Lva, yva, wva, seed, use_gap, aug_scale):
    import torch
    torch.manual_seed(seed); np.random.seed(seed)
    dev = _dev()
    xa, ma = encode(Xtr, Ltr, use_gap)
    xb, mb = encode(Xtr, Ltr, use_gap, scale=aug_scale)               # the one augmented copy per training window
    x = np.concatenate([xa, xb]); m = np.concatenate([ma, mb])
    y = np.concatenate([ytr, ytr]); w = np.concatenate([wtr, wtr]).astype(np.float32)
    xv, mv = encode(Xva, Lva, use_gap)
    T = lambda a, dt=torch.float32: torch.as_tensor(a, dtype=dt)
    x, m, y, w = T(x), T(m), T(y, torch.long), T(w)
    xv, mv, yv, wv = T(xv).to(dev), T(mv).to(dev), T(yva, torch.long).to(dev), T(wva.astype(np.float32)).to(dev)
    net = make_net().to(dev)
    opt = torch.optim.Adam(net.parameters(), lr=LR)
    best, best_state, bad, epochs = float("inf"), None, 0, 0
    g = torch.Generator().manual_seed(seed)
    for ep in range(EPOCHS):
        net.train()
        perm = torch.randperm(len(x), generator=g)
        for i in range(0, len(x), BATCH):
            j = perm[i:i + BATCH]
            loss = (torch.nn.functional.cross_entropy(net(x[j].to(dev), m[j].to(dev)), y[j].to(dev), reduction="none")
                    * w[j].to(dev)).sum() / w[j].sum().to(dev)
            opt.zero_grad(); loss.backward(); opt.step()
        net.eval()
        with torch.no_grad():
            vl = 0.0
            for i in range(0, len(xv), 2048):
                vl += float((torch.nn.functional.cross_entropy(net(xv[i:i + 2048], mv[i:i + 2048]), yv[i:i + 2048], reduction="none")
                             * wv[i:i + 2048]).sum())
            vl /= float(wv.sum())
        epochs = ep + 1
        if vl < best - 1e-4:
            best, bad = vl, 0
            best_state = {k: v.detach().cpu().clone() for k, v in net.state_dict().items()}
        else:
            bad += 1
            if bad >= PATIENCE:
                break
    net.load_state_dict(best_state)
    net.eval()
    return net.cpu(), {"epochs": epochs, "best_val_loss": round(best, 5)}


def predict(net, X, lens, use_gap):
    import torch
    x, m = encode(X, lens, use_gap)
    out = []
    with torch.no_grad():
        for i in range(0, len(x), 4096):
            out.append(torch.softmax(net(torch.as_tensor(x[i:i + 4096]), torch.as_tensor(m[i:i + 4096])), 1).numpy())
    return np.concatenate(out) if out else np.zeros((0, len(CLS)), np.float32)


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


if __name__ == "__main__":
    stage = sys.argv[1] if len(sys.argv) > 1 else ""
    {"check": stage_check, "lofo": stage_lofo, "choose": stage_choose}.get(stage, lambda: sys.exit(__doc__))()
