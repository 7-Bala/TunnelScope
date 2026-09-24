#!/usr/bin/env python3
"""Build tunnelscope/models/traffic_windows.npz: the traffic classifier's
training windows (T-083, EXP-15), replacing exp05_windows.npz.

Sources (per-packet tables, tracked):
  EXP-05  testbed/captures/exp05/        arms base, tfc          5 classes
  EXP-15  testbed/captures/exp15/traffic arms tun, tfc, tra, cbc  8 classes
Mixed (mux) sessions are NOT training data: EXP-05 showed a single label on
them is confidently wrong; they are the abstain test instead (analyze.py).
Arrays only (allow_pickle=False on load). Deterministic."""
import csv
import gzip
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tunnelscope.leakage.attacker import window_features  # noqa: E402

SOURCES = [("EXP-05", ROOT / "testbed/captures/exp05", ("base", "tfc")),
           ("EXP-15", ROOT / "testbed/captures/exp15/traffic", ("tun", "tfc", "tra", "cbc")),
           # EXP-16: REAL applications (Chromium, OpenSSH, Postfix, XMPP, RTP) and
           # the same synthetic classes through Libreswan (cross-implementation)
           ("EXP-16", ROOT / "testbed/captures/exp16", ("real", "lsw")),
           ("EXP-17", ROOT / "testbed/captures/exp17", ("wan-syn", "lossy-syn", "wan-real", "lossy-real"))]
ARM_NAME = {"base": "tunnel", "tun": "tunnel", "tfc": "tunnel+tfc", "tra": "transport", "cbc": "tunnel-cbc",
            "real": "real-apps", "lsw": "libreswan",
            "wan-syn": "wan", "lossy-syn": "lossy", "wan-real": "wan-real-apps", "lossy-real": "lossy-real-apps"}


VNAT = ROOT / "build/models/vnat_windows.npz"


def load(include_mux=False, keep=None, include_real_public=False):
    """keep: only these arm names (after ARM_NAME mapping); None = all.
    include_real_public: add the real public VNAT windows (EXP-19). Off by default so every earlier
    experiment's analysis reproduces exactly; the shipped model build turns it on."""
    X, y, arm, rep, sess, src = [], [], [], [], [], []
    for tag, cap, arms in SOURCES:
        seen = set()
        for t, a, cls, r, *_ in csv.reader(open(cap / "manifest.csv")):
            if t in seen or not (a in arms or (include_mux and a == "mux")):
                continue
            seen.add(t)
            with gzip.open(cap / f"{t}.pkts.csv.gz", "rt") as f:
                next(f)
                pk = [(float(a_), d, int(n)) for a_, d, n in (l.strip().split(",") for l in f) if n]
            name = ARM_NAME.get(a, a)
            if keep is not None and name not in keep:
                continue
            for v in window_features(pk):
                X.append(v); y.append(cls); arm.append(name); rep.append(int(r))
                sess.append(t); src.append(tag)
    if include_real_public and (keep is None or "vnat-openvpn" in keep):
        # EXP-19 / DEC-036: real public traffic (MIT VNAT, OpenVPN tunnels), windows built by
        # experiments/exp19-real-public-traffic/export_windows.py. rep 0 is never a lab repetition,
        # so every lab leave-one-repetition-out test keeps these windows in training only.
        v = np.load(VNAT, allow_pickle=False)
        X += v["X"].astype(float).tolist(); y += v["y"].tolist(); arm += ["vnat-openvpn"] * len(v["y"])
        rep += [0] * len(v["y"]); sess += v["capture"].tolist(); src += ["VNAT"] * len(v["y"])
    return (np.array(X, float), np.array(y), np.array(arm), np.array(rep), np.array(sess), np.array(src))


if __name__ == "__main__":
    X, y, arm, rep, sess, src = load(include_real_public=True)
    out = ROOT / "tunnelscope/models/traffic_windows.npz"
    np.savez_compressed(out, X=X, y=y, arm=arm, rep=rep, session=sess, source=src)
    print(f"{out.relative_to(ROOT)}: {len(y)} windows, {len(set(sess))} sessions, classes {sorted(set(y))}")
