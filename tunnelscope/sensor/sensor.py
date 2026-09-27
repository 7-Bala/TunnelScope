"""The site sensor (T-139): the live pipeline at a site, reporting findings only.

It reads what a capture process writes (dumpcap on an interface, or a folder a tap/router rotates files into); it
has no path to the tunnels it watches, so it cannot disturb them. Each analysed window becomes one signed report in
the outbox; if no window was analysed for one window length, a heartbeat report says the sensor is alive but saw
nothing, so the centre never mistakes silence for "all is well". Capture files are deleted after analysis (the live
default); only reports leave the site, by whatever file transfer the operator uses (rsync, scp, a shared folder, a
data diode).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import report as R

STATE_FILE = "sensor-state.json"


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("tunnelscope")
    except Exception:
        return "unknown"


class Sensor:
    def __init__(self, site: str, key_file: str, outbox: str, state_dir: str, window: int = 30,
                 interface: str | None = None, follow: str | None = None, keep: bool = False):
        from ..live.live import LiveMonitor
        self.site, self.key = site, R.read_key(key_file)
        self.outbox, self.state_dir = Path(outbox), Path(state_dir)
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.monitor = LiveMonitor(interface=interface, follow=follow, window=window, keep=keep,
                                   history=str(self.state_dir / "history"))
        self.window = self.monitor.window
        self.version = _version()
        self.last_emit = time.time()
        st = self.state_dir / STATE_FILE
        self.seq = json.loads(st.read_text())["seq"] if st.exists() else 0

    def _next_seq(self) -> int:
        """Persisted before use, so a restart never reuses a number (the collector rejects replays)."""
        self.seq += 1
        tmp = self.state_dir / (STATE_FILE + ".tmp")
        tmp.write_text(json.dumps({"seq": self.seq, "site": self.site}))
        os.replace(tmp, self.state_dir / STATE_FILE)
        return self.seq

    def emit(self, row: dict | None) -> Path:
        rep = R.sign(R.build_report(self.site, self._next_seq(), self.window, row, self.version), self.key)
        name = f"{self.site}-{rep['seq']:010d}.json"
        tmp = self.outbox / f".{name}.tmp"                 # atomic: a transfer never picks up half a file
        tmp.write_text(json.dumps(rep, sort_keys=True))
        os.replace(tmp, self.outbox / name)
        self.last_emit = time.time()
        return self.outbox / name

    def tick(self) -> list[Path]:
        out = [self.emit(row) for row in self.monitor.poll_once()]
        if not out and time.time() - self.last_emit >= self.window:
            out.append(self.emit(None))
        return out

    def run(self, max_reports: int | None = None, on_report=None) -> None:
        self.monitor.start_capture()
        n = 0
        try:
            while True:
                for p in self.tick():
                    n += 1
                    if on_report:
                        on_report(p)
                    if max_reports and n >= max_reports:
                        return
                time.sleep(1.0)
        finally:
            self.monitor.stop()
