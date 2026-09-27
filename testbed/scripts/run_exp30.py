#!/usr/bin/env python3
"""EXP-30 harness (experiments/exp30-other-rules-context/PREREG.md).

EXP-18b's harness (run_exp18b.py), unchanged, with two differences only:
  - results go to experiments/exp30-other-rules-context/results/<backend>/raw.jsonl;
  - prompt P3 = P0 with generate_plan(other_rules=True) (the other active rules on the same line).

  .venv/bin/python testbed/scripts/run_exp30.py groq dev --prompt P3
  .venv/bin/python testbed/scripts/run_exp30.py groq test          (FREEZE-groq.md names P3)
  .venv/bin/python testbed/scripts/run_exp30.py gemini-lite s11
"""
from __future__ import annotations

import functools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_exp18b as h  # noqa: E402

h.EXP = h.ROOT / "experiments" / "exp30-other-rules-context"
h.base.PROMPTS["P3"] = None            # P3 asks through the committed _ask; the difference is other_rules=True
_configure = h.configure


def configure(name, key_purpose=None):
    out = _configure(name, key_purpose)
    inner = h.gen.generate_plan

    @functools.wraps(inner)
    def with_other_rules(*a, **kw):
        return inner(*a, other_rules=True, **kw)
    h.gen.generate_plan = with_other_rules
    return out


h.configure = configure

if __name__ == "__main__":
    if "--prompt" in sys.argv and sys.argv[sys.argv.index("--prompt") + 1] != "P3":
        raise SystemExit("EXP-30 runs prompt P3 only (PREREG)")
    h.main()
