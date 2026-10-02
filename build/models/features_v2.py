#!/usr/bin/env python3
"""EXP-42 candidate feature version `v2` = the shipped 31 (v1) + 15 rhythm/shape features, as pre-registered.

Windows are selected exactly as `tunnelscope.leakage.attacker.window_features` selects them (same 2-s buckets, same
"complete windows only", same minimum of 3 packets), so row i of v2 is row i of v1 plus 15 columns. Nothing here uses the
label, the family or the cipher: only times, directions and IP lengths, which the product already reads.
"""
from __future__ import annotations

import numpy as np

WIN = 2.0
MIN_PKTS = 3
NEW = ["pps", "bps", "up_share", "dir_switch", "out_near_max", "in_near_max", "out_iat_cv", "in_iat_cv", "size_entropy",
       "rhythm_peak", "rhythm_lag", "fast_share", "ctx_pps", "ctx_bps", "ctx_up_share"]


def _window_index(t):
    t0 = t[0]
    idx = ((t - t0) // WIN).astype(int)
    last_full = int((t[-1] - t0) // WIN) - 1
    return idx, last_full


def _rhythm(ts):
    if len(ts) < 4:
        return 0.0, 0.0
    c = np.bincount(((ts - ts[0]) / 0.01).astype(int), minlength=200)[:200].astype(float)
    c -= c.mean()
    den = float((c * c).sum())
    if den <= 0:
        return 0.0, 0.0
    ac = np.array([float((c[:-k] * c[k:]).sum()) / den for k in range(1, 21)])
    k = int(ac.argmax())
    return float(ac[k]), (k + 1) * 0.01


def extra(t, out, size):
    """-> the 15 new columns for each window v1 keeps, in v1's order."""
    t = np.asarray(t, float); out = np.asarray(out, bool); size = np.asarray(size, float)
    if len(t) == 0:
        return []
    idx, last_full = _window_index(t)
    smax_out = size[out].max() if out.any() else 0.0
    smax_in = size[~out].max() if (~out).any() else 0.0
    rows = []
    for w in np.unique(idx):
        m = idx == w
        if m.sum() < MIN_PKTS or w > last_full:
            continue
        tw, ow, sw = t[m], out[m], size[m]
        n, b = len(tw), float(sw.sum())
        def cv(x):
            d = np.diff(x)
            return float(d.std() / d.mean()) if len(d) > 1 and d.mean() > 0 else 0.0
        hist = np.histogram(np.clip(sw, 0, 1599), bins=16, range=(0, 1600))[0] / n
        ent = float(-(hist[hist > 0] * np.log2(hist[hist > 0])).sum())
        peak, lag = _rhythm(tw)
        iat = np.diff(tw)
        rows.append([n / WIN, b / WIN, float(sw[ow].sum()) / b if b else 0.0,
                     float((ow[1:] != ow[:-1]).mean()) if n > 1 else 0.0,
                     float((sw[ow] >= smax_out - 8).mean()) if ow.any() else 0.0,
                     float((sw[~ow] >= smax_in - 8).mean()) if (~ow).any() else 0.0,
                     cv(tw[ow]), cv(tw[~ow]), ent, peak, lag,
                     float((iat < 0.005).mean()) if len(iat) else 0.0])
    R = np.asarray(rows, float)
    if len(R):
        ctx = np.array([R[max(0, i - 2):i + 3, :3].mean(axis=0) for i in range(len(R))])
        R = np.hstack([R, ctx])
    return R.tolist()


def v2(t, out, size):
    from tunnelscope.leakage.attacker import window_features
    base = window_features(list(zip(np.asarray(t).tolist(), np.where(out, "out", "in").tolist(), np.asarray(size).tolist())))
    ext = extra(t, out, size)
    assert len(base) == len(ext), (len(base), len(ext))
    return [a + b for a, b in zip(base, ext)]
