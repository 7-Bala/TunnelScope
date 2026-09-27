#!/usr/bin/env python3
"""EXP-32 harness (experiments/exp32-site-sensor/PREREG.md): the site sensor and collector as real CLI processes on the
live lab, W = 10 s, 10 post-quantum -> classical changes, one collector outage.

  .venv/bin/python testbed/scripts/run_exp32.py

The router (sees alice <-> bob) rotates IKE/NAT-T/ESP capture files into testbed/captures/exp32-live (git-ignored;
the sensor deletes each file after analysis). Keys, outbox, inbox and states live in a temp directory; the harness
is the "transport": it copies every report into results/reports/ (so every report can be audited) and moves it to
the collector's inbox. Results: results/raw.jsonl (events), results/alerts.jsonl, results/reports/,
results/collector-state/.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_exp18 as lab  # noqa: E402  (EXP-18's seeding: t-tun lines on both ends, reload, re-initiate)
from tunnelscope.sensor.report import write_key  # noqa: E402

W = 10
CYCLES = 10
OUTAGE_CYCLE = 5
A = {"proposals": "aes256-sha384-ecp384-ke1_mlkem768"}
B = {"proposals": "aes256-sha384-ecp384"}
EXP = ROOT / "experiments" / "exp32-site-sensor"
RES = EXP / "results"
LIVE = ROOT / "testbed" / "captures" / "exp32-live"
TS = [str(ROOT / ".venv" / "bin" / "tunnelscope")]
ROUTER, PINGER = "sih26-router", "sih26-alice-pq"
EVENTS = RES / "raw.jsonl"
_lock = threading.Lock()


def event(kind: str, **kw) -> dict:
    rec = {"event": kind, "t": time.time(), **kw}
    with _lock, EVENTS.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print(json.dumps(rec), flush=True)
    return rec


# t_change = the moment EXP-18's seeding calls `swanctl --initiate` (PREREG: "just before B's initiate")
_initiated: list[float] = []
_docker = lab.docker


def _docker_timed(*argv, **kw):
    if "--initiate" in argv:
        _initiated.append(time.time())
    return _docker(*argv, **kw)


lab.docker = _docker_timed


def set_state(name: str, lines: dict) -> float:
    lab.seed(lines)
    t = _initiated[-1]
    event("state", state=name, initiate_t=t)
    return t


class Transport(threading.Thread):
    """outbox -> (copy to results/reports) -> inbox, every 0.5 s: the file transfer a site would use."""

    def __init__(self, outbox: Path, inbox: Path):
        super().__init__(daemon=True)
        self.outbox, self.inbox, self.stop = outbox, inbox, threading.Event()

    def run(self):
        while not self.stop.is_set():
            self.move()
            time.sleep(0.5)

    def move(self):
        for p in sorted(self.outbox.glob("*.json")):
            if p.name.startswith("."):
                continue
            shutil.copy2(p, RES / "reports" / p.name)
            os.replace(p, self.inbox / p.name)


def start_collector(work: Path) -> subprocess.Popen:
    proc = subprocess.Popen(TS + ["collect", "--inbox", str(work / "inbox"), "--state", str(work / "cstate"),
                                  "--keys", str(work / "keys"), "--alerts", str(work / "alerts.jsonl"),
                                  "--json", "--poll", "1"], stdout=subprocess.PIPE, text=True)

    def read():
        for line in proc.stdout:
            event("collector", **json.loads(line))
    threading.Thread(target=read, daemon=True).start()
    event("collector_started")
    return proc


def stop_proc(proc: subprocess.Popen, name: str) -> None:
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
    event(f"{name}_stopped")


def alert_after(work: Path, t: float) -> dict | None:
    f = work / "alerts.jsonl"
    if not f.exists():
        return None
    for line in f.read_text().splitlines():
        a = json.loads(line)
        if a["kind"] in ("downgrade", "new_failure") and a["received"] >= t:
            return a
    return None


def main() -> None:
    if EVENTS.exists():
        raise SystemExit("results/raw.jsonl exists: EXP-32 runs once (move it aside only by a dated addendum)")
    (RES / "reports").mkdir(parents=True, exist_ok=True)
    shutil.rmtree(LIVE, ignore_errors=True)
    LIVE.mkdir(parents=True)
    work = Path(tempfile.mkdtemp(prefix="exp32-"))
    for d in ("outbox", "inbox"):
        (work / d).mkdir()
    write_key(work / "keys" / "lab.key")
    event("start", window_s=W, cycles=CYCLES, git_head=subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                                                       capture_output=True, text=True).stdout.strip())
    set_state("A", A)
    lab.docker("exec", "-d", ROUTER, "tcpdump", "-i", "eth0", "-Z", "root", "-G", str(W), "-w",
               "/captures/exp32-live/w-%s.pcap", "udp port 500 or udp port 4500 or ip proto 50")
    lab.docker("exec", "-d", PINGER, "sh", "-c",
               "ping -i 0.5 -I 10.10.1.210 10.10.2.210 > /tmp/exp32-ping.txt 2>&1")
    sensor = subprocess.Popen(TS + ["sensor", "--site", "lab", "--key", str(work / "keys" / "lab.key"), "--follow",
                                    str(LIVE), "--outbox", str(work / "outbox"), "--state", str(work / "sstate"),
                                    "--window", str(W)], stdout=subprocess.DEVNULL)
    event("sensor_started")
    transport = Transport(work / "outbox", work / "inbox")
    transport.start()
    collector = start_collector(work)
    try:
        time.sleep(2 * W)
        for i in range(1, CYCLES + 1):
            set_state("A", A)
            if i == OUTAGE_CYCLE:
                stop_proc(collector, "collector")
                time.sleep(3 * W)
                collector = start_collector(work)
            else:
                time.sleep(2 * W)
            set_state("A", A)
            time.sleep(2 * W)
            t_change = set_state("B", B)
            deadline, hit = t_change + 6 * W, None
            while time.time() < deadline and hit is None:
                time.sleep(0.5)
                hit = alert_after(work, t_change)
            event("change", cycle=i, t_change=t_change, detected=hit is not None,
                  latency_s=round(hit["received"] - t_change, 2) if hit else None,
                  alert=hit and {k: hit[k] for k in ("kind", "attribute", "usual", "now", "source")})
            if hit is None:
                time.sleep(max(0.0, deadline - time.time()))
        set_state("A", A)
        time.sleep(3 * W)
    finally:
        stop_proc(sensor, "sensor")
        lab.docker("exec", ROUTER, "pkill", "tcpdump")
        lab.docker("exec", PINGER, "pkill", "ping")
        time.sleep(1)
        transport.move()
        transport.stop.set()
        time.sleep(3)
        stop_proc(collector, "collector")
        ping = lab.docker("exec", PINGER, "sh", "-c", "tail -n 3 /tmp/exp32-ping.txt").stdout
        event("ping_summary", text=ping.strip()[-300:])
        if (work / "alerts.jsonl").exists():
            shutil.copy2(work / "alerts.jsonl", RES / "alerts.jsonl")
        shutil.copytree(work / "cstate", RES / "collector-state", dirs_exist_ok=True)
        event("inbox_left", files=sorted(p.name for p in (work / "inbox").iterdir()))
        lab.seed({})
        shutil.rmtree(work)                      # the throwaway key goes with it
        shutil.rmtree(LIVE, ignore_errors=True)
        event("end")


if __name__ == "__main__":
    main()
