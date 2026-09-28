#!/usr/bin/env python3
"""EXP-33 harness (experiments/exp33-headers-only/PREREG.md + ADDENDUM A): two dumpcap processes on the router at the
same time, the shipped full capture and the shipped headers-only capture, while t-tun re-keys 10 times (A/B).

  .venv/bin/python testbed/scripts/run_exp33.py
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_exp18 as lab  # noqa: E402
from tunnelscope.live.live import capture_command  # noqa: E402

EXP = ROOT / "experiments" / "exp33-headers-only"
RAW = EXP / "results" / "raw.jsonl"
CAP = ROOT / "testbed" / "captures" / "exp33"            # git-ignored subfolder
A = {"proposals": "aes256-sha384-ecp384-ke1_mlkem768"}
B = {"proposals": "aes256-sha384-ecp384"}
HANDSHAKES, GAP_S, DURATION_S = 10, 15, 190


def event(name, **kw):
    RAW.parent.mkdir(parents=True, exist_ok=True)
    rec = {"event": name, "t": time.time(), **kw}
    with RAW.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print(json.dumps(rec), flush=True)


def main():
    if RAW.exists():
        raise SystemExit("results/raw.jsonl exists: EXP-33 runs once")
    CAP.mkdir(parents=True, exist_ok=True)
    for f in CAP.glob("*.pcapng"):
        f.unlink()
    lab.seed(A)
    cmds = {name: capture_command("dumpcap", "eth0", f"/captures/exp33/{name}.pcapng", 0, hdr)
            + ["-a", f"duration:{DURATION_S}"] for name, hdr in (("reference", False), ("headers", True))}
    for name, cmd in cmds.items():
        lab.docker("exec", "-d", "sih26-router", *cmd)
        event("capture_started", name=name, command=cmd)
    lab.docker("exec", "-d", "sih26-alice-pq", "sh", "-c", f"ping -i 0.5 -w {DURATION_S - 5} -I 10.10.1.210 10.10.2.210 >/dev/null 2>&1")
    time.sleep(3)
    t0 = time.time()
    for i in range(HANDSHAKES):
        state = "A" if i % 2 == 0 else "B"
        lab.seed(A if state == "A" else B)
        event("handshake", n=i + 1, state=state)
        time.sleep(GAP_S)
    left = DURATION_S - (time.time() - t0) + 8
    time.sleep(max(0, left))
    for name in cmds:
        p = CAP / f"{name}.pcapng"
        event("capture_file", name=name, bytes=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    lab.seed({})
    event("end")


if __name__ == "__main__":
    main()
