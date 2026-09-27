#!/usr/bin/env python3
"""EXP-30 analysis (PREREG.md). Two steps, nothing computed anywhere else:
  1. EXP-18's own analyze.py, UNCHANGED, on results/<backend>/raw.jsonl -> results/<backend>/summary.json
     (H1 safety, H2 ship bar), exactly as EXP-18b scored its arms;
  2. the PREREG's outcomes against that backend's EXP-18b A1 result on the same items
     -> results/<backend>/comparison.json: dev gate, O1 regressions, O2 items lost, O3 T9.

  .venv/bin/python experiments/exp30-other-rules-context/analyze.py [groq gemini-lite]
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXP18 = HERE.parent / "exp18-generative-remediation" / "analyze.py"
EXP18B = HERE.parent / "exp18b-gemini-remediation" / "results"


def _exp18(backend: str):
    spec = importlib.util.spec_from_file_location(f"exp18_analyze_{backend}", EXP18)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.HERE = HERE
    m.RAW = HERE / "results" / backend / "raw.jsonl"
    m.OUT = HERE / "results" / backend / "summary.json"
    return m


def score(backend: str) -> None:
    m = _exp18(backend)
    if not m.RAW.exists():
        print(f"{backend}: no results yet")
        return
    print(f"== {backend}")
    m.main()
    rows = [json.loads(line) for line in m.RAW.read_text().splitlines() if line.strip()]
    ref = json.loads((EXP18B / backend / "summary.json").read_text())["table"]

    def items(phase: str) -> dict[str, str]:
        out = {}
        for r in rows:
            if r["phase"] == phase and r.get("included") and r["arm"] == "A1" and r["prompt"] == "P3":
                out[r["item"]] = "confirmed" if m.confirmed(r) else (
                    "regression: " + ", ".join(r["regressions"]) if r.get("regressions") else
                    f"stopped at {r['stopped_at']}" if r.get("stopped_at") else "accepted, not confirmed")
        return out

    dev, test = items("dev"), items("test")
    ref_dev = ref["dev"]["A1|P0"]["items"]
    ref_test = ref["test"]["A1|P0"]["items"]
    ref_dev_k = sum(v == "confirmed" for v in ref_dev.values())
    dev_k = sum(v == "confirmed" for v in dev.values())
    regress = [i for i, v in test.items() if v.startswith("regression")]
    ref_rows = [json.loads(line) for line in (EXP18B / backend / "raw.jsonl").read_text().splitlines() if line.strip()]
    ref_regress = [r["item"] for r in ref_rows
                   if r["phase"] == "test" and r.get("included") and r["arm"] == "A1" and r.get("regressions")]
    lost = sorted(i for i, v in ref_test.items() if v == "confirmed" and test.get(i) != "confirmed")
    out = {
        "dev_gate": {"exp18b_A1_confirmed": ref_dev_k, "exp30_P3_confirmed": dev_k, "items": dev,
                     "passes": bool(dev) and dev_k >= ref_dev_k},
        "O1_regressions": {"exp18b_A1": ref_regress, "exp30_P3": regress,
                           "passes": bool(test) and len(regress) < len(ref_regress)},
        "O2_items_lost": {"lost": lost, "missing_rows": sorted(set(ref_test) - set(test)),
                          "passes": bool(test) and len(lost) <= 1},
        "O3_T9": test.get("T9"),
        "test_items": test,
        "exp18b_A1_test_items": ref_test,
    }
    (HERE / "results" / backend / "comparison.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: out[k] for k in ("dev_gate", "O1_regressions", "O2_items_lost", "O3_T9")}, indent=1))


if __name__ == "__main__":
    for b in sys.argv[1:] or ["groq", "gemini-lite"]:
        score(b)
