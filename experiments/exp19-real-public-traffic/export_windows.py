#!/usr/bin/env python3
"""EXP-19 follow-up (DEC-036, owner decision): write the VNAT windows exactly as analyze.py built them
(same selection, cap and seed) to build/models/vnat_windows.npz, which make_traffic_data.py adds to
the shipped training set. Needs the converted packets from convert_vnat.py (kept outside the repo).

  .venv/bin/python experiments/exp19-real-public-traffic/export_windows.py
"""
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze  # noqa: E402

if __name__ == "__main__":
    X, y, grp, n = analyze.vnat_windows()
    out = HERE.parents[1] / "build/models/vnat_windows.npz"
    np.savez_compressed(out, X=X.astype(np.float32), y=y, capture=grp)
    print(f"{out.relative_to(HERE.parents[1])}: {len(y)} windows from {n} connections, {out.stat().st_size} bytes")
