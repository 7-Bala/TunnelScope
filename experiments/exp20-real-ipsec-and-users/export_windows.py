#!/usr/bin/env python3
"""EXP-20: turn the converted packet arrays (kept outside the repo) into the window files the
scoreboard and the model build read (plain arrays in build/models/, no pickles):

  build/models/usbvpn_windows.npz  X, y, group (capture record)
  build/models/wg_windows.npz      X, y, group (flow), session, app  (outer, i.e. encrypted, view)

  .venv/bin/python experiments/exp20-real-ipsec-and-users/export_windows.py

Same windowing as the tool (tunnelscope.leakage.attacker.window_features, MIN_WINDOWS), a cap on
windows per capture so long captures do not dominate, and fixed seeds (PREREG.md).
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope.leakage.attacker import MIN_WINDOWS, window_features  # noqa: E402

USBVPN = Path.home() / "Datasets/usbvpn2022/converted/usbvpn_l2tpipsec_packets.npz"
WG = Path.home() / "Datasets/wg-matched/converted/wg_flows_packets.npz"
SEED = 20
CAP_USBVPN = 60          # as EXP-19
CAP_WG = 20              # WireGuard flows are many and long; 20 per flow keeps one flow from dominating
WG_WEB_FLOWS = 3000      # nDPI "Web" has tens of thousands of flows; a seeded sample of flows (PREREG)


def windows(t, out, size, cap, rng):
    pk = list(zip(t.tolist(), np.where(out, "out", "in").tolist(), size.tolist()))
    w = window_features(pk)
    if len(w) < MIN_WINDOWS:
        return []
    if len(w) > cap:
        w = [w[j] for j in sorted(rng.choice(len(w), cap, replace=False))]
    return w


def export_usbvpn() -> None:
    d = np.load(USBVPN, allow_pickle=False)
    rng = np.random.default_rng(SEED)
    off = d["offsets"]
    X, y, g = [], [], []
    for i in range(len(d["label"])):
        a, b = off[i], off[i + 1]
        w = windows(d["t"][a:b], d["out"][a:b], d["size"][a:b], CAP_USBVPN, rng)
        X += w; y += [str(d["label"][i])] * len(w); g += [str(d["capture"][i])] * len(w)
    p = ROOT / "build/models/usbvpn_windows.npz"
    np.savez_compressed(p, X=np.array(X, np.float32), y=np.array(y), group=np.array(g))
    print(f"{p.relative_to(ROOT)}: {len(y)} windows, {len(set(g))} records, {p.stat().st_size} bytes,",
          {c: int((np.array(y) == c).sum()) for c in sorted(set(y))})


def export_wg() -> None:
    d = np.load(WG, allow_pickle=False)
    rng = np.random.default_rng(SEED)
    off, lab = d["offsets"], d["label"]
    flows = np.arange(len(lab))
    web = flows[lab == "web"]
    web_keep = set(rng.choice(web, min(WG_WEB_FLOWS, len(web)), replace=False).tolist())
    X, y, g, s, app = [], [], [], [], []
    for i in flows:
        if lab[i] == "web" and i not in web_keep:
            continue
        a, b = off[i], off[i + 1]
        w = windows(d["t_outer"][a:b], d["out"][a:b], d["size_outer"][a:b], CAP_WG, rng)
        X += w; y += [str(lab[i])] * len(w); g += [str(d["capture"][i])] * len(w)
        s += [int(d["session"][i])] * len(w); app += [str(d["app"][i])] * len(w)
    p = ROOT / "build/models/wg_windows.npz"
    y = np.array(y); s = np.array(s)
    np.savez_compressed(p, X=np.array(X, np.float32), y=y, group=np.array(g), session=s, app=np.array(app))
    print(f"{p.relative_to(ROOT)}: {len(y)} windows, {len(set(g))} flows, {p.stat().st_size} bytes")
    for sess in (1, 2):
        m = s == sess
        print(f"  session {sess}:", {c: int((y[m] == c).sum()) for c in sorted(set(y))},
              "flows", {c: len(set(np.array(g)[m & (y == c)])) for c in sorted(set(y))})


if __name__ == "__main__":
    export_usbvpn()
    export_wg()
