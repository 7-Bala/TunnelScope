#!/usr/bin/env python3
"""EXP-31 harness (experiments/exp31-no-trade-check/PREREG.md).

EXP-18b's harness (run_exp18b.py), unchanged, with two differences only:
  - results go to experiments/exp31-no-trade-check/results/<backend>/raw.jsonl;
  - test set on arm A1 only (as EXP-30 ADDENDUM B), prompt P0. The intervention is in the code (V6), not here.

  .venv/bin/python testbed/scripts/run_exp31.py groq dev
  .venv/bin/python testbed/scripts/run_exp31.py groq test          (FREEZE-groq.md names P0)
  .venv/bin/python testbed/scripts/run_exp31.py gemini-lite s11
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_exp18b as h  # noqa: E402

h.EXP = h.ROOT / "experiments" / "exp31-no-trade-check"
_done_keys = h.done_keys


def done_keys():
    return _done_keys() | {("test", i, arm, "P0", None) for i in h.base.TEST for arm in ("A0", "A2")}


h.done_keys = done_keys

if __name__ == "__main__":
    if "--prompt" in sys.argv:
        raise SystemExit("EXP-31 runs prompt P0 only (PREREG)")
    h.main()
