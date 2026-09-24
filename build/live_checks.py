#!/usr/bin/env python3
"""Checks that need the real local model (Apple Silicon) or the real Docker lab (build/13 §5.4).

They are not pytest tests on purpose: pytest must be fully green on Linux CI with no skips, and
the guard (build/guard_diff.py) rejects added skips. Each check here exits
  0  PASS     1  FAIL     3  SKIP (the model or the lab is not available; the reason is printed)
and build/check_all.sh shows it as its own row, so a missing lab reads SKIP, never PASS.

Usage: .venv/bin/python build/live_checks.py <name>     names: see CHECKS at the bottom
"""
from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASS, FAIL, SKIP = 0, 1, 3


def _block_network() -> list[str]:
    """Make every outgoing connection fail loudly, and record the attempts."""
    attempts: list[str] = []

    def refuse(*a, **k):
        attempts.append(repr(a[:2]))
        raise OSError("network blocked by build/live_checks.py")
    socket.socket.connect = refuse          # type: ignore[method-assign]
    socket.socket.connect_ex = refuse       # type: ignore[method-assign]
    socket.create_connection = refuse       # type: ignore[assignment]
    socket.getaddrinfo = refuse             # type: ignore[assignment]
    return attempts


def check_model() -> int:
    """The pinned model loads from the local cache with the network blocked, and answers JSON."""
    attempts = _block_network()
    from tunnelscope.rephrase import rephrase as rp
    from tunnelscope.rephrase import runtime
    if not rp.available():
        print("SKIP: no Apple Silicon MLX runtime on this machine")
        return SKIP
    if rp.local_model_path() is None:
        print(f"SKIP: model {rp.MODEL_ID} at revision {rp.MODEL_REVISION} is not in the local cache")
        return SKIP
    t0 = time.monotonic()
    out, meta = runtime.generate_json(
        "Return only a JSON object with one key \"ok\" whose value is true.", {"note": "nothing to do"},
        max_tokens=32, timeout_s=60)
    total = time.monotonic() - t0
    print(json.dumps({**meta, "total_s": round(total, 2), "network_attempts": attempts, "output": out}, indent=1))
    if attempts:
        print("FAIL: the runtime tried to use the network")
        return FAIL
    if out is None or "{" not in out:
        print(f"FAIL: no JSON-looking answer ({meta['reason']})")
        return FAIL
    print(f"PASS: offline load + answer in {total:.2f} s")
    return PASS


def _lab_up() -> bool:
    from tunnelscope.remediate import execute
    return all(execute.is_container_running(c) for c in ("sih26-alice-pq", "sih26-bob-pq"))


def check_generator() -> int:
    """SMOKE, not the evaluation (that is EXP-18): the real model drafts a fix for every
    generatable rule against the real lab config, side by side with the hand-written fix. PASS
    means every draft either passed every check or was refused by a named check, and nothing
    crashed; it says nothing about how often the model is right."""
    from tunnelscope.rephrase import runtime
    if not runtime.model_available():
        print("SKIP: the local model is not available on this machine")
        return SKIP
    if not _lab_up():
        print("SKIP: lab containers sih26-alice-pq / sih26-bob-pq are not running")
        return SKIP
    from tunnelscope.remediate import generate
    from tunnelscope.remediate.plan import GENERATABLE_RULES
    bad = 0
    for rule in sorted(GENERATABLE_RULES):
        r = generate.generate_plan(rule, "sih26-alice-pq", compare_with_handwritten=True, **generate.PRODUCT_SETTINGS)
        p = r.get("plan") or {}
        raw = (p.get("raw_output") or (r.get("revisions") or [{}])[-1].get("raw_output") or "")
        print(json.dumps({"rule": rule, "ok": r["ok"], "stage": r.get("stage"), "reason": r.get("reason"),
                          "change": p.get("change"), "agrees_with_handwritten": p.get("agrees_with_handwritten"),
                          "rounds": len(p.get("revisions") or r.get("revisions") or []),
                          "self_review": (p.get("self_review") or {}).get("verdict"),
                          "latency_s": p.get("latency_s") or r.get("latency_s"), "raw": raw[:300]}))
        if r.get("stage") in ("internal", "model"):
            bad += 1
    if bad:
        print(f"FAIL: {bad} draft(s) crashed or got no model answer")
        return FAIL
    print("PASS: every draft was either fully checked or refused by a named check (smoke only)")
    return PASS


def check_browser() -> int:
    """T-105 B2: the dashboard in a real browser (Playwright) against a real engine, the real local
    model and the real lab. Starts its own engine with drafts switched on for the test only
    (TUNNELSCOPE_GENERATOR=1) and a throwaway history folder, then stops it."""
    import os
    import subprocess
    import tempfile
    import urllib.request
    from tunnelscope.rephrase import runtime
    dash = ROOT / "fleet-dashboard"
    if not runtime.model_available():
        print("SKIP: the local model is not available on this machine")
        return SKIP
    if not _lab_up():
        print("SKIP: lab containers sih26-alice-pq / sih26-bob-pq are not running")
        return SKIP
    if not (dash / "node_modules" / "@playwright" / "test").is_dir() or not (dash / "dist" / "index.html").is_file():
        print("SKIP: dashboard not built or Playwright not installed (cd fleet-dashboard && npm ci && npm run build)")
        return SKIP
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    history = tempfile.mkdtemp(prefix="ts-e2e-history-")
    env = {**os.environ, "TUNNELSCOPE_GENERATOR": "1"}
    eng = subprocess.Popen([str(ROOT / ".venv/bin/python"), "-m", "tunnelscope.cli", "serve", "--no-browser",
                            "--port", str(port), "--history", history], cwd=ROOT, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            print("FAIL: the engine did not start")
            return FAIL
        r = subprocess.run(["npx", "playwright", "test", "--project=live", "--reporter=line"], cwd=dash,
                           env={**os.environ, "E2E_LIVE": "1", "E2E_BASE_URL": f"http://127.0.0.1:{port}",
                                "E2E_HISTORY": history}, capture_output=True, text=True, timeout=1200)
        print(r.stdout[-3000:])
        if r.returncode != 0:
            print(r.stderr[-2000:])
            print("FAIL: live browser tests failed")
            return FAIL
        print("PASS: live browser tests (real engine, model and lab)")
        return PASS
    finally:
        eng.terminate()
        try:
            eng.wait(timeout=10)
        except Exception:
            eng.kill()


CHECKS = {"model": check_model, "generator": check_generator, "browser": check_browser}

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else ""
    if name not in CHECKS:
        print(f"unknown check {name!r}; one of {sorted(CHECKS)}")
        sys.exit(FAIL)
    sys.exit(CHECKS[name]())
