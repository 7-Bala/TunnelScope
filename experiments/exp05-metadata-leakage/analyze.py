#!/usr/bin/env python3
"""EXP-05 — metadata leakage through ESP: how much can a passive observer
learn about the traffic class, and how much does TFC padding reduce it?

Pre-registration (P5-1..P5-5): research/registers/EXPERIMENT-REGISTER.md
("EXP-05 — PRE-REGISTRATION").

The classifier is a MEASURING INSTRUMENT for adversary capability (CS-01),
not a traffic-identification product. All evaluation is leave-one-repetition-
out: every window from one session sits in the same fold (DEC-009).

Inputs:  testbed/captures/exp05/*.pkts.csv.gz  (t, dir, len — outer ESP packets)
         testbed/captures/exp05/manifest.csv
Outputs: results/exp05_results.json
"""
import csv
import gzip
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

CLASSES = ["voip", "web", "bulk", "interactive", "video"]
WIN = 2.0                         # seconds per window
MIN_PKTS = 3                      # windows with fewer packets carry no usable signal
SIZE_EDGES = [0, 128, 256, 512, 1024, 1600]
L = len(CLASSES)


def load_sessions(capdir: Path):
    rows = list(csv.reader(open(capdir / "manifest.csv")))
    seen, sessions = set(), []
    for tag, arm, cls, rep, seed, npk, sha in rows:
        if tag in seen:                        # tolerate re-runs appending duplicates
            continue
        seen.add(tag)
        pk = []
        with gzip.open(capdir / f"{tag}.pkts.csv.gz", "rt") as f:
            next(f)
            for line in f:
                t, d, n = line.strip().split(",")
                if n:
                    pk.append((float(t), d, int(n)))
        sessions.append(dict(tag=tag, arm=arm, cls=cls, rep=int(rep), seed=int(seed), pkts=pk, sha256=sha))
    return sessions


COMPLETE_ONLY = True


def window_features(pkts, complete_only=None):
    """Split a session into WIN-second windows; one feature vector per window.

    complete_only drops the session's final PARTIAL window. Found after the
    first full run: every misclassification in every fold was window #10, i.e.
    the tail after the generator stopped, containing only TCP teardown
    stragglers. Those windows describe connection shutdown, not the traffic
    class. Both variants are reported in the results (see main())."""
    complete_only = COMPLETE_ONLY if complete_only is None else complete_only
    if not pkts:
        return []
    t0 = pkts[0][0]
    last_full = int((pkts[-1][0] - t0) // WIN) - 1 if complete_only else 10**9
    buckets = defaultdict(list)
    for t, d, n in pkts:
        buckets[int((t - t0) // WIN)].append((t, d, n))
    feats = []
    for idx, w in sorted(buckets.items()):
        if len(w) < MIN_PKTS or idx > last_full:
            continue
        v = []
        for d in ("out", "in"):
            s = np.array([n for _, dd, n in w if dd == d], float)
            ts = np.array([t for t, dd, _ in w if dd == d], float)
            iat = np.diff(ts) if len(ts) > 1 else np.array([0.0])
            hist = np.histogram(s, bins=SIZE_EDGES)[0] / max(len(s), 1) if len(s) else np.zeros(len(SIZE_EDGES) - 1)
            v += [len(s), s.sum() if len(s) else 0,
                  s.mean() if len(s) else 0, s.std() if len(s) else 0,
                  s.min() if len(s) else 0, s.max() if len(s) else 0,
                  np.log10(iat.mean() + 1e-6), np.log10(iat.std() + 1e-6), np.log10(np.median(iat) + 1e-6),
                  float((iat < 0.001).mean())]
            v += list(hist)
        n_out = sum(1 for _, d, _ in w if d == "out")
        v += [n_out / len(w)]
        feats.append(v)
    return feats


def loro_eval(X, y, g, make_model, scaler=False):
    preds = np.empty_like(y)
    fold_f1 = []
    for rep in sorted(set(g)):
        tr, te = g != rep, g == rep
        Xtr, Xte = X[tr], X[te]
        if scaler:
            sc = StandardScaler().fit(Xtr); Xtr, Xte = sc.transform(Xtr), sc.transform(Xte)
        m = make_model().fit(Xtr, y[tr])
        preds[te] = m.predict(Xte)
        fold_f1.append(f1_score(y[te], preds[te], labels=CLASSES, average="macro", zero_division=0))
    return preds, fold_f1


def cover_hart_ber_lower_bound(r_nn, L=L):
    """Asymptotic Cover–Hart: R_nn <= R*(2 - L/(L-1) R*)  =>  R* >= lower bound below."""
    r_nn = min(r_nn, (L - 1) / L)
    return (L - 1) / L * (1 - math.sqrt(max(0.0, 1 - L / (L - 1) * r_nn)))


def mutual_info_uniform_prior(sessions, key):
    """I(class; X) in bits/packet with a UNIFORM class prior (so bulk's packet
    volume doesn't dominate), Miller–Madow bias-corrected. key(pkt, prev_t) -> bin or None."""
    cond = {c: Counter() for c in CLASSES}
    for s in sessions:
        prev = None
        for t, d, n in s["pkts"]:
            b = key(t, d, n, prev)
            prev = t
            if b is not None:
                cond[s["cls"]][b] += 1
    bins = sorted(set().union(*[set(c) for c in cond.values()]))
    if not bins:
        return 0.0
    pxc = {c: np.array([cond[c][b] for b in bins], float) for c in CLASSES}
    pxc = {c: v / v.sum() if v.sum() else v for c, v in pxc.items()}
    px = sum(pxc.values()) / L
    H = lambda p: -sum(q * math.log2(q) for q in p if q > 0)
    mi = H(px) - sum(H(pxc[c]) for c in CLASSES) / L
    n_total = sum(sum(cond[c].values()) for c in CLASSES)
    k_x = int((px > 0).sum())
    k_joint = sum(int((pxc[c] > 0).sum()) for c in CLASSES)
    mm = ((k_x - 1) - (k_joint - L)) / (2 * n_total * math.log(2))  # Miller–Madow on I = H(X)+H(C)-H(X,C)
    return max(0.0, mi + mm)


# Each channel is measured ALONE. An earlier draft keyed size bins on
# (direction, size), which let direction information leak into the "size"
# number (caught in a dry run: 0.053 bits of "size" MI under TFC padding, where
# only ONE ESP length exists and size MI must be exactly 0). Fixed before the
# final analysis; direction is now reported as its own channel.
def size_bin(t, d, n, prev):
    return n // 32


def iat_bin(t, d, n, prev):
    if prev is None:
        return None
    return int(np.floor(np.log2(max(t - prev, 1e-6))))


def dir_bin(t, d, n, prev):
    return d


def main():
    capdir = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures/exp05")
    res = Path(sys.argv[2] if len(sys.argv) > 2 else "results"); res.mkdir(parents=True, exist_ok=True)
    sessions = load_sessions(capdir)
    report = {"n_sessions": len(sessions), "window_s": WIN, "arms": {}}
    rng = np.random.default_rng(0)
    rf = lambda: RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1)

    models_base = None
    for arm in ("base", "tfc"):
        S = [s for s in sessions if s["arm"] == arm]
        X, y, g = [], [], []
        for s in S:
            for v in window_features(s["pkts"]):
                X.append(v); y.append(s["cls"]); g.append(s["rep"])
        X, y, g = np.array(X), np.array(y), np.array(g)
        preds, f1s = loro_eval(X, y, g, rf)
        # Added before the final run (not in the pre-registration): a depth-2 tree as a
        # "trivial rule" baseline, to answer DEVELOP's question of whether a learned
        # model adds anything over a two-threshold rule.
        _, f1s_stump = loro_eval(X, y, g, lambda: DecisionTreeClassifier(max_depth=2, random_state=0))
        nn_pred, _ = loro_eval(X, y, g, lambda: KNeighborsClassifier(n_neighbors=1), scaler=True)
        r_nn = float((nn_pred != y).mean())
        # permutation null: shuffle the session->class mapping, keep windows grouped by session
        null_f1 = []
        sess_ids = np.array([f"{s['cls']}-{s['rep']}" for s in S for _ in window_features(s["pkts"])])
        for _ in range(5):
            keys = sorted(set(sess_ids)); perm = dict(zip(keys, rng.permutation([k.split("-")[0] for k in keys])))
            yp = np.array([perm[k] for k in sess_ids])
            pp, _ = loro_eval(X, yp, g, rf)
            null_f1.append(f1_score(yp, pp, labels=CLASSES, average="macro", zero_division=0))
        lens = Counter(n for s in S for _, _, n in s["pkts"])
        report["arms"][arm] = {
            "n_sessions": len(S), "n_windows": int(len(y)),
            "rf_macro_f1_LORO_mean": round(float(np.mean(f1s)), 4),
            "rf_macro_f1_LORO_std": round(float(np.std(f1s)), 4),
            "rf_macro_f1_per_fold": [round(float(f), 4) for f in f1s],
            "depth2_tree_macro_f1_LORO_mean": round(float(np.mean(f1s_stump)), 4),
            "rf_per_class_f1": {c: round(float(f), 3) for c, f in
                                zip(CLASSES, f1_score(y, preds, labels=CLASSES, average=None, zero_division=0))},
            "one_nn_error_LORO": round(r_nn, 4),
            "bayes_error_lower_bound_cover_hart": round(cover_hart_ber_lower_bound(r_nn), 4),
            "permutation_null_rf_macro_f1_mean": round(float(np.mean(null_f1)), 4),
            "mi_size_bits_per_packet": round(mutual_info_uniform_prior(S, size_bin), 4),
            "mi_timing_bits_per_packet": round(mutual_info_uniform_prior(S, iat_bin), 4),
            "mi_direction_bits_per_packet": round(mutual_info_uniform_prior(S, dir_bin), 4),
            "mi_max_bits": round(math.log2(L), 4),
            "distinct_esp_lengths": len(lens), "top_esp_lengths": lens.most_common(5),
            "total_bytes": int(sum(n for s in S for _, _, n in s["pkts"])),
        }
        if arm == "base":
            models_base = rf().fit(X, y)

    b, t = report["arms"]["base"], report["arms"]["tfc"]
    report["tfc_bandwidth_overhead_ratio"] = round(t["total_bytes"] / b["total_bytes"], 3)

    # multiplexing (G-12): single-class base model applied to two-class mux windows
    M = [s for s in sessions if s["arm"] == "mux"]
    hits, tot, pair_stats = 0, 0, {}
    for s in M:
        present = set(s["cls"].split("+"))
        W = window_features(s["pkts"])
        if not W:
            continue
        p = models_base.predict(np.array(W))
        h = sum(1 for x in p if x in present)
        hits += h; tot += len(p)
        ps = pair_stats.setdefault(s["cls"], {"windows": 0, "hits": 0, "pred_counts": Counter()})
        ps["windows"] += len(p); ps["hits"] += h; ps["pred_counts"].update(p.tolist())
    report["mux"] = {"hit_rate_top1_in_present_pair": round(hits / tot, 4) if tot else None,
                     "chance_hit_rate": round(2 / L, 4), "windows": tot,
                     "per_pair": {k: {"hit_rate": round(v["hits"] / v["windows"], 3),
                                      "predictions": dict(v["pred_counts"])} for k, v in pair_stats.items()}}
    # base single-class accuracy, for the P5-4 comparison
    report["mux"]["base_single_class_rf_f1_for_comparison"] = b["rf_macro_f1_LORO_mean"]

    (res / "exp05_results.json").write_text(json.dumps(report, indent=2, default=str))
    for arm in ("base", "tfc"):
        a = report["arms"][arm]
        print(f"[{arm}] RF F1 {a['rf_macro_f1_LORO_mean']:.3f}±{a['rf_macro_f1_LORO_std']:.3f}  depth2 {a['depth2_tree_macro_f1_LORO_mean']:.3f}  "
              f"null {a['permutation_null_rf_macro_f1_mean']:.3f}  1NN err {a['one_nn_error_LORO']:.3f}  "
              f"BER>= {a['bayes_error_lower_bound_cover_hart']:.3f}  MI size {a['mi_size_bits_per_packet']:.3f}b  "
              f"MI timing {a['mi_timing_bits_per_packet']:.3f}b  MI dir {a['mi_direction_bits_per_packet']:.3f}b  distinct lens {a['distinct_esp_lengths']}")
        print(f"        per-class F1 {a['rf_per_class_f1']}")
    print(f"tfc overhead: x{report['tfc_bandwidth_overhead_ratio']}")
    print(f"mux hit-rate {report['mux']['hit_rate_top1_in_present_pair']} (chance {report['mux']['chance_hit_rate']})",
          {k: v["hit_rate"] for k, v in report["mux"]["per_pair"].items()})


if __name__ == "__main__":
    import copy
    main()                                   # primary: complete windows only
    COMPLETE_ONLY = False                    # secondary: all windows, incl. the partial tail
    _res = Path(sys.argv[2] if len(sys.argv) > 2 else "results")
    primary = json.loads((_res / "exp05_results.json").read_text())
    print("\n--- secondary: ALL windows (incl. partial final window) ---")
    main()
    secondary = json.loads((_res / "exp05_results.json").read_text())
    primary["secondary_all_windows_incl_partial_tail"] = {
        "arms": {a: {k: v for k, v in secondary["arms"][a].items()
                     if k.startswith(("rf_", "depth2", "one_nn", "bayes", "permutation"))}
                 for a in ("base", "tfc")},
        "mux_hit_rate": secondary["mux"]["hit_rate_top1_in_present_pair"]}
    primary["window_definition"] = "complete 2-s windows only (final partial window dropped); secondary block = all windows"
    (_res / "exp05_results.json").write_text(json.dumps(primary, indent=2, default=str))
