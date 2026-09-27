#!/usr/bin/env python3
"""EXP-18b analysis: EXP-18's own analyze.py, UNCHANGED, applied to each backend's results (PREREG ADDENDUM A
item 5: the bars are EXP-18's, so EXP-18's code scores them). Reads results/<backend>/raw.jsonl, writes
results/<backend>/summary.json. Rows marked `infrastructure: rate_limited_or_overloaded` are excluded and listed
(included=False), exactly like EXP-18's lab-unreachable rows.

  .venv/bin/python experiments/exp18b-gemini-remediation/analyze.py [gemini|groq ...]
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXP18 = HERE.parent / "exp18-generative-remediation" / "analyze.py"


def score(backend: str) -> None:
    spec = importlib.util.spec_from_file_location(f"exp18_analyze_{backend}", EXP18)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.HERE = HERE
    m.RAW = HERE / "results" / backend / "raw.jsonl"
    m.OUT = HERE / "results" / backend / "summary.json"
    if not m.RAW.exists():
        print(f"{backend}: no results yet")
        return
    print(f"== {backend}")
    m.main()


if __name__ == "__main__":
    for b in sys.argv[1:] or ["gemini", "groq"]:
        score(b)
