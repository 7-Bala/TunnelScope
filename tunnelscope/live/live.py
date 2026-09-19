"""Live analysis (T-083, PS: "captured traffic or live network streams").

Two sources, one pipeline:
  - interface: dumpcap writes a ring buffer of W-second files (capture filter:
    IKE, NAT-T, ESP, AH only), so memory and disk stay bounded;
  - follow:    a directory another sensor rotates files into (a tap or router
    running `tcpdump -G`), which needs no capture privilege here.
Each CLOSED file is one window: analysed with the normal pipeline, fed to the
anomaly history (so a tunnel is compared with its own past windows), then
deleted unless keep=True. The newest file is never read while it may still be
growing: it is only taken once a newer file exists or it has been idle for
two windows.
"""
from __future__ import annotations

import collections
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

from ..errors import DependencyError, InputError

CAPTURE_FILTER = "udp port 500 or udp port 4500 or ip proto 50 or ip proto 51 or ip6 proto 50 or ip6 proto 51"
EXTS = (".pcap", ".pcapng")


class LiveMonitor:
    def __init__(self, interface: str | None = None, follow: str | None = None, window: int = 30,
                 history: str | None = None, keep: bool = False, max_windows: int = 50, workdir: str | None = None):
        if bool(interface) == bool(follow):
            raise InputError("live: give exactly one of --interface or --follow")
        self.interface, self.window, self.history, self.keep = interface, max(5, int(window)), history, keep
        self.dir = Path(follow or workdir or Path.home() / ".tunnelscope-live")
        self.windows: collections.deque = collections.deque(maxlen=max_windows)
        self.errors: collections.deque = collections.deque(maxlen=20)
        self.done: set[str] = set()
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.started = time.time()
        self._stop = threading.Event()

    # ---------------------------------------------------------------- capture
    def start_capture(self) -> None:
        if not self.interface:
            if not self.dir.is_dir():
                raise InputError(f"live --follow: directory not found: {self.dir}")
            return
        dumpcap = shutil.which("dumpcap")
        if not dumpcap:
            raise DependencyError("live --interface needs dumpcap (it ships with Wireshark/tshark)")
        self.dir.mkdir(parents=True, exist_ok=True)
        cmd = [dumpcap, "-q", "-i", self.interface, "-f", CAPTURE_FILTER,
               "-b", f"duration:{self.window}", "-b", "files:20", "-w", str(self.dir / "live.pcapng")]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(1.0)
        if self.proc.poll() is not None:
            err = (self.proc.stderr.read() if self.proc.stderr else "").strip()
            raise DependencyError(
                f"live: cannot capture on '{self.interface}': {err or 'dumpcap exited'}. "
                "Capturing needs permission: on macOS install Wireshark's ChmodBPF, on Linux "
                "`sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)`. Or capture on a sensor "
                "with `tcpdump -G <seconds>` and use --follow DIR.")

    def stop(self) -> None:
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    # ---------------------------------------------------------------- windows
    def ready_files(self) -> list[Path]:
        files = sorted((p for p in self.dir.iterdir() if p.suffix in EXTS and p.name not in self.done),
                       key=lambda p: (p.stat().st_mtime, p.name))
        if not files:
            return []
        newest = files[-1]
        idle = time.time() - newest.stat().st_mtime > 2 * self.window
        return files if idle else files[:-1]

    def process(self, path: Path) -> dict:
        from ..api.server import analysis_json
        from ..report.report import analyze
        from ..anomaly.anomaly import History, observe
        t0 = time.time()
        row = {"file": path.name, "at": path.stat().st_mtime, "ok": True}
        try:
            a = analyze(str(path))
            anomalies = observe(History(self.history), a["sas"], f"live:{path.name}") if self.history else None
            j = analysis_json(a, path.name, anomalies)
            row.update(n_sas=j["n_sas"], sas=j["sas"], seconds=round(time.time() - t0, 2))
        except Exception as e:           # one bad window must not stop the monitor
            row.update(ok=False, error=f"{type(e).__name__}: {e}"[:300])
            self.errors.append(row)
        self.done.add(path.name)
        if not self.keep:
            try:
                path.unlink()
            except OSError:
                pass
        with self.lock:
            self.windows.append(row)
        return row

    def poll_once(self) -> list[dict]:
        return [self.process(p) for p in self.ready_files()]

    def run(self, on_window=None, max_windows: int | None = None) -> None:
        n = 0
        while not self._stop.is_set():
            for row in self.poll_once():
                n += 1
                if on_window:
                    on_window(row)
                if max_windows and n >= max_windows:
                    return
            self._stop.wait(1.0)

    def status(self) -> dict:
        with self.lock:
            ws = list(self.windows)
        last = ws[-1]["at"] if ws else None
        return {"enabled": True, "source": f"interface {self.interface}" if self.interface else f"folder {self.dir}",
                "window_s": self.window, "started": self.started, "windows": ws[::-1],
                "last_at": last, "errors": list(self.errors)[-5:],
                "capturing": bool(self.proc and self.proc.poll() is None) if self.interface else None}
