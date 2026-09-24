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


CHECKS = {"model": check_model}

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else ""
    if name not in CHECKS:
        print(f"unknown check {name!r}; one of {sorted(CHECKS)}")
        sys.exit(FAIL)
    sys.exit(CHECKS[name]())
