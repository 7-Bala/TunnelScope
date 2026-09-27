#!/usr/bin/env python3
"""EXP-18b harness (experiments/exp18b-gemini-remediation/PREREG.md + ADDENDUM A).

Wraps EXP-18's run_exp18.py UNCHANGED (same items, seeding, baseline capture, preview/apply path, arms) and only:
  - passes the backend under test to generate_plan ("cloud" = gemini-3.8-flash alone; "chain" restricted to
    Groq's openai/gpt-oss-120b alone), and routes the dev prompt variants P1/P2 to that backend too;
  - writes to experiments/exp18b-gemini-remediation/results/<backend>/raw.jsonl (EXP-18's results untouched);
  - records a 429/503 model failure as `infrastructure: rate_limited_or_overloaded` (excluded, listed) and re-runs
    that item on the next invocation (ADDENDUM A item 4).

  .venv/bin/python testbed/scripts/run_exp18b.py gemini dev --prompt P0
  .venv/bin/python testbed/scripts/run_exp18b.py gemini test          (after FREEZE-gemini.md is committed)
  .venv/bin/python testbed/scripts/run_exp18b.py groq s11 | robust
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_exp18 as base  # noqa: E402
from tunnelscope.remediate import chain, cloud_client, generate as gen, open_model_client  # noqa: E402

EXP = ROOT / "experiments" / "exp18b-gemini-remediation"
BACKENDS = {"gemini": ("cloud", cloud_client, cloud_client.MODEL_ID),
            "gemini-lite": ("cloud", cloud_client, "gemini-3.1-flash-lite"),        # ADDENDUM D
            "groq": ("chain", chain, "openai/gpt-oss-120b")}
INFRA = "infrastructure: rate_limited_or_overloaded"
_LAST_PLAN: dict = {}


def configure(name: str, key_purpose: str | None = None) -> tuple[str, str]:
    backend, mod, model = BACKENDS[name]
    if name == "groq":
        os.environ["TUNNELSCOPE_GENERATOR_CHAIN"] = f"groq:{model}"   # that one model, no fallback
    if name.startswith("gemini"):
        cloud_client.MODEL_ID = model                                  # the cloud backend's one model
    os.environ.pop("TUNNELSCOPE_KEY_PURPOSE", None)                  # the plain key = the experiment key
    if key_purpose:                                                    # ADDENDUM C: owner's other account key
        os.environ["TUNNELSCOPE_KEY_PURPOSE"] = key_purpose
    base.EXP = EXP
    base.RAW = EXP / "results" / name / "raw.jsonl"
    # dev prompt variants P1/P2 call `runtime.generate_json` in run_exp18: point that at the backend under test
    base.runtime = types.SimpleNamespace(
        generate_json=mod.generate_json, DEFAULT_TIMEOUT_S=30.0, MODEL_REVISION=model,
        model_available=(lambda: cloud_client.available()) if name.startswith("gemini") else (lambda: open_model_client.available()))
    orig = gen.generate_plan

    @functools.wraps(orig)
    def with_backend(*a, **kw):
        r = orig(*a, backend=backend, **kw)
        _LAST_PLAN.clear()
        _LAST_PLAN.update(model_id=(r.get("plan") or {}).get("model_id"), stage=r.get("stage"), reason=r.get("reason"))
        return r
    gen.generate_plan = with_backend
    return backend, model


def infra(rec: dict) -> bool:
    why = str(rec.get("reason") or "")
    return rec.get("stopped_at") == "model" and bool(re.search(r"rate limit|HTTP 503|HTTP 429|high demand|overloaded", why, re.I))


def done_keys() -> set[tuple]:
    if not base.RAW.exists():
        return set()
    rows = [json.loads(line) for line in base.RAW.read_text().splitlines() if line.strip()]
    return {(r["phase"], r["item"], r["arm"], r["prompt"], r.get("seed")) for r in rows if r.get("excluded") != INFRA}


def run(phase, item, rule, lines, arm, prompt, name, model, **kw):
    rec = base.run_one(phase, item, rule, lines, arm, prompt, **kw)
    rec.update(backend=name, model_id=_LAST_PLAN.get("model_id") or model,
               key_purpose=os.environ.get("TUNNELSCOPE_KEY_PURPOSE") or "experiment")
    if rec.get("included") and infra(rec):
        rec.update(included=False, excluded=INFRA)
    base.append(rec)
    return rec


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("backend", choices=list(BACKENDS))
    ap.add_argument("phase", choices=["dev", "test", "s11", "robust"])
    ap.add_argument("--prompt", default=None)
    ap.add_argument("--key-purpose", default=None, help="Gemini only: use TUNNELSCOPE_GEMINI_API_KEY_<PURPOSE>")
    args = ap.parse_args()
    backend, model = configure(args.backend, args.key_purpose)
    if not base.runtime.model_available():
        raise SystemExit(f"{args.backend} is not available (network switch and API key)")
    freeze = EXP / f"FREEZE-{args.backend}.md"
    if args.phase != "dev":
        tracked = subprocess.run(["git", "ls-files", "--error-unmatch", str(freeze)], cwd=ROOT, capture_output=True)
        dirty = subprocess.run(["git", "status", "--porcelain", str(freeze)], cwd=ROOT, capture_output=True, text=True).stdout
        if not freeze.exists() or tracked.returncode != 0 or dirty.strip():
            raise SystemExit(f"{freeze.name} must be committed, unchanged, before test/s11/robust runs")
        prompt = re.search(r"frozen prompt: (P\d)", freeze.read_text()).group(1)
    else:
        prompt = args.prompt or "P0"
    print(json.dumps({"machine_state": base.machine_state(), "backend": args.backend, "model": model,
                      "phase": args.phase, "prompt": prompt}), flush=True)
    done = done_keys()
    n = {"run": 0, "infra": 0}
    try:
        if args.phase in ("dev", "test"):
            items = base.DEV if args.phase == "dev" else base.TEST
            arms = ["A1"] if args.phase == "dev" else ["A0", "A1", "A2"]
            for item, (rule, lines) in items.items():
                for arm in arms:
                    if (args.phase, item, arm, prompt, None) not in done:
                        r = run(args.phase, item, rule, lines, arm, prompt, args.backend, model)
                        n["run"] += 1
                        n["infra"] += r.get("excluded") == INFRA
        elif args.phase == "robust":
            for s in range(1, 4):                                  # 3 seeds (PREREG, stated before any run)
                for item, (rule, lines) in base.TEST.items():
                    if ("robust", item, "R", prompt, s) not in done:
                        r = run("robust", item, rule, lines, "R", prompt, args.backend, model, seed_n=s)
                        n["run"] += 1
                        n["infra"] += r.get("excluded") == INFRA
        else:
            for inj in ("S11a", "S11b"):
                if ("safety", inj, "A1", prompt, None) not in done:
                    r = run("safety", inj, "V-207193", {}, "A1", prompt, args.backend, model, inject_cfg=inj)
                    n["run"] += 1
                    n["infra"] += r.get("excluded") == INFRA
    finally:
        base.seed({})
        print(json.dumps({"done": n, "raw": str(base.RAW.relative_to(ROOT))}), flush=True)


if __name__ == "__main__":
    main()
