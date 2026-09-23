"""Local upload dashboard (T-059). Drop a .pcap/.pcapng in a browser tab, see the
same findings `tunnelscope dashboard` would render for it — no CLI command per
file. Stdlib only: no new dependency, and pyproject.toml's fastapi/uvicorn
removal (T-049) stands. Deliberately narrow, per the security-review note in
build/03-USAGE-AND-OPERATIONS-PLAN.md §2/§6:

  - binds to 127.0.0.1 ONLY — never exposed as a flag, so it can't be
    fat-fingered onto a LAN or 0.0.0.0;
  - every upload is checked against pcap/pcapng magic bytes before it ever
    reaches tshark (untrusted bytes must not reach a subprocess unchecked);
  - the file is written to a private temp path (never the client-supplied
    name) and deleted again once the response is sent — nothing persists on
    disk after the request, and nothing is written under the uploaded name;
  - no auth, because it is a single-user localhost tool with no listener on
    any other interface: there is no other party who could reach it;
  - a parse failure on one file is its own error response, never a crash of
    the server or of another in-flight request (mirrors report/fleet.py's
    per-file error handling).

This is NOT the "local-only API" build/03-USAGE-AND-OPERATIONS-PLAN.md §6
describes for role D (SIEM polling) — that's a different, still-open item
(plan §5 P3). This one is a human dropping files into a browser tab.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import webbrowser
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from ..report.report import analyze
from ..report.dashboard import _CSS, render_sas_html
from ..anomaly.anomaly import History, observe
from ..explain.explain import explain_sa
from ..remediate.plan import plan_for
from ..report.labels import label
from ..risk.risk import assess_risk

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB: generous for a capture, not for a DoS

# The React dashboard's production build (T-060). When present, `serve` hosts it
# at / and the dashboard talks to /api/analyze. When absent (e.g. installed
# without Node), the built-in page below still works on its own.
def _dashboard_dir() -> Path:
    """Where the built dashboard is: an explicit override, else the copy shipped
    inside the package (tunnelscope/web/, put there by build/offline/make_bundle.sh
    so an installed copy has it), else a source checkout's fleet-dashboard/dist."""
    if os.environ.get("TUNNELSCOPE_DASHBOARD_DIR"):
        return Path(os.environ["TUNNELSCOPE_DASHBOARD_DIR"])
    packaged = Path(__file__).resolve().parents[1] / "web"
    if (packaged / "index.html").is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "fleet-dashboard" / "dist"


DASHBOARD_DIR = _dashboard_dir()
_TMP_PREFIX = "tunnelscope-upload-"

# Anomaly history (T-082): OFF unless a directory is given (serve --history, or
# TUNNELSCOPE_HISTORY). When on, each analysed tunnel's posture profile (no
# packets, no payload) is appended there, so the tool can learn what is normal.
HISTORY_DIR: str | None = os.environ.get("TUNNELSCOPE_HISTORY") or None
_HISTORY_LOCK = threading.Lock()
LIVE = None        # a live.LiveMonitor when serve runs with --live-follow / --live-interface

# Classic pcap (LE/BE) and pcapng magic numbers (Wireshark wiki, "Development/LibpcapFileFormat").
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "pcap (little-endian)",
    b"\xa1\xb2\xc3\xd4": "pcap (big-endian)",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, little-endian)",
    b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, big-endian)",
    b"\x0a\x0d\x0d\x0a": "pcapng",
}

_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TunnelScope — local dashboard</title><style>{css}
.drop{{border:2px dashed var(--line);border-radius:12px;padding:36px;text-align:center;
color:var(--muted);cursor:pointer;margin-bottom:20px;transition:border-color .15s,color .15s}}
.drop.over{{border-color:var(--accent);color:var(--accent)}}
.drop b{{color:var(--ink)}}
.pending{{color:var(--muted);font-style:italic}}
</style></head><body><div class="wrap">
<h1>TunnelScope — local dashboard</h1>
<div class="sub">Runs only on this machine (127.0.0.1). Files are analyzed in memory and on a
temp path that is deleted right after each response — nothing is kept.</div>
<div class="drop" id="drop"><b>Drop .pcap / .pcapng files here</b><br>or click to choose</div>
<input id="file-input" type="file" multiple accept=".pcap,.pcapng" hidden>
<div id="results"></div>
<div class="foot">Findings are labelled observed / inferred / measured / not-observable /
contradictory. Absence of evidence is never scored as compliance.</div>
</div>
<script>
const drop = document.getElementById('drop');
const input = document.getElementById('file-input');
const results = document.getElementById('results');
const esc = s => String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
drop.addEventListener('click', () => input.click());
drop.addEventListener('dragover', e => {{ e.preventDefault(); drop.classList.add('over'); }});
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', e => {{
  e.preventDefault(); drop.classList.remove('over'); handleFiles(e.dataTransfer.files);
}});
input.addEventListener('change', () => {{ handleFiles(input.files); input.value = ''; }});

async function handleFiles(files) {{
  for (const f of files) {{
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = '<b>' + esc(f.name) + '</b> — <span class="pending">analyzing…</span>';
    results.prepend(card);
    try {{
      const res = await fetch('/api/upload?name=' + encodeURIComponent(f.name),
                              {{method: 'POST', body: f}});
      const data = await res.json();
      if (data.ok) {{
        card.innerHTML = '<div class="sub">Source: ' + esc(data.filename) + ' · ' +
          data.n_sas + ' security association(s)</div>' + data.html;
      }} else {{
        card.innerHTML = '<b>' + esc(f.name) + '</b> — <span class="tag t-fail">error</span> ' + esc(data.error);
      }}
    }} catch (err) {{
      card.innerHTML = '<b>' + esc(f.name) + '</b> — <span class="tag t-fail">error</span> ' + esc(err);
    }}
  }}
}}
</script></body></html>"""


def analysis_json(a: dict, source: str, anomalies: list[dict] | None = None) -> dict:
    """Structured, JSON-safe view of report.analyze() for the React dashboard
    (T-060). Same data the HTML fragment renders, so the two never disagree."""
    summary = a["cbom"]["tunnelscope_sa_summary"]
    sas = []
    for i, sa in enumerate(a["sas"]):
        r = sa["record"]
        verdicts = [{"verdict": v.verdict, "baseline": v.baseline, "authority": v.authority,
                     "rule_id": v.rule_id, "title": v.title, "severity": v.severity,
                     "attribute": v.attribute, "observed": v.observed, "message": v.message}
                    for v in sa["verdicts"]]
        sas.append({
            "id": f"{source}#{i + 1}",
            "source": source,
            "src": r.src, "dst": r.dst,
            "ike_spi": r.key(),
            "posture": summary[i]["quantum_posture"],
            "fails": [{"baseline": v["baseline"], "rule_id": v["rule_id"], "severity": v["severity"],
                       "title": v["title"], "message": v["message"]}
                      for v in verdicts if v["verdict"] == "FAIL"],
            "verdicts": verdicts,
            "findings": [{"attribute": attr, "label": label(attr), "status": f.status.value, "value": f.value,
                          "confidence": f.confidence,
                          "vantage": f.vantage.value, "method": f.method, "note": f.note}
                         for attr, f in r.findings.items()],
            "scores": sa["scores"],
            "score_stability": sa["sensitivity"]["verdict"],
            "gaps": summary[i]["gaps"],
        })
        sas[-1]["anomaly"] = anomalies[i] if anomalies else None
        sas[-1]["risk"] = assess_risk(r, sa["verdicts"], sas[-1]["anomaly"]) if anomalies else sa["risk"]
        sas[-1]["explanation"] = explain_sa(sas[-1], sas[-1]["anomaly"])
    return {"ok": True, "filename": source, "n_sas": len(sas), "sas": sas}


def _sniff(head: bytes) -> str | None:
    for magic, name in _MAGIC.items():
        if head.startswith(magic):
            return name
    return None


class _Handler(BaseHTTPRequestHandler):
    server_version = "TunnelScope/0.2"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path: str) -> bool:
        """Serve a file from the dashboard build. Returns False if there is no
        build. Never serves anything outside DASHBOARD_DIR (resolved-path check,
        so ../ and symlinks can't escape it)."""
        root = DASHBOARD_DIR.resolve()
        if not (root / "index.html").is_file():
            return False
        rel = unquote(path).lstrip("/") or "index.html"
        target = (root / rel).resolve()
        if not target.is_relative_to(root):
            self._json(403, {"ok": False, "error": "forbidden"})
            return True
        if not target.is_file():
            target = root / "index.html"   # single-page app fallback
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._bytes(200, target.read_bytes(), ctype)
        return True

    def do_GET(self):  # noqa: N802 (stdlib method name)
        path = urlparse(self.path).path
        if path == "/health":
            self._json(200, {"ok": True, "dashboard": (DASHBOARD_DIR / "index.html").is_file(),
                             "history": bool(HISTORY_DIR), "live": LIVE is not None})
        elif path == "/api/history":
            self._json(200, history_summary())
        elif path == "/api/live":
            if LIVE is None:
                self._json(200, {"ok": True, "enabled": False})
            else:
                st = LIVE.status()
                st["windows"] = st["windows"][:20]
                self._json(200, {"ok": True, **st})
        elif path.startswith("/api/"):
            self._json(404, {"ok": False, "error": "not found"})
        elif path == "/basic" or not self._static(path):
            # built-in single-file page: always available at /basic, and at / when
            # there is no dashboard build
            self._bytes(200, _PAGE.format(css=_CSS).encode(), "text/html; charset=utf-8")

    def _remediate_plan(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"ok": False, "error": "empty body"})
            return
        if length > 1024 * 1024:
            self._json(413, {"ok": False, "error": "payload too large"})
            return
        try:
            data = self.rfile.read(length)
            body = json.loads(data.decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "error": "invalid json"})
            return
        if not isinstance(body, dict) or "rule_id" not in body:
            self._json(400, {"ok": False, "error": "missing rule_id"})
            return
        plan = plan_for(body.get("rule_id"), observed=body.get("observed"), detailed=bool(body.get("detailed", False)))
        if plan is None:
            self._json(404, {"ok": False, "error": "unknown rule"})
            return
        self._json(200, plan)

    def _remediate_apply(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"ok": False, "stage": "validate", "error": "empty body"})
            return
        if length > 1024 * 1024:
            self._json(413, {"ok": False, "stage": "validate", "error": "payload too large"})
            return
        try:
            data = self.rfile.read(length)
            body = json.loads(data.decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "stage": "validate", "error": "invalid json"})
            return
        if not isinstance(body, dict):
            self._json(400, {"ok": False, "stage": "validate", "error": "body must be an object"})
            return
        rule_id = body.get("rule_id")
        target = body.get("target")
        confirm = body.get("confirm")
        if not isinstance(rule_id, str) or not rule_id:
            self._json(400, {"ok": False, "stage": "validate", "error": "missing or invalid rule_id"})
            return
        if not isinstance(target, str) or not target:
            self._json(400, {"ok": False, "stage": "validate", "error": "missing or invalid target"})
            return
        if confirm is not True:
            self._json(400, {"ok": False, "stage": "validate", "error": "confirm must be literally true"})
            return

        caller = self.address_string()
        try:
            from ..remediate.execute import apply_remediation
            res = apply_remediation(
                rule_id=rule_id,
                target=target,
                confirm=confirm,
                caller=caller,
                history_dir=HISTORY_DIR,
            )
            if not res.get("ok"):
                self._json(400, res)
                return
            self._json(200, res)
        except Exception as e:
            sys.stderr.write(f"[tunnelscope serve] remediate apply error: {e}\n")
            self._json(500, {"ok": False, "stage": "execute", "error": "unexpected server error during remediation"})

    def do_POST(self):  # noqa: N802
        url = urlparse(self.path)
        if url.path == "/api/remediate/plan":
            self._remediate_plan()
            return
        if url.path == "/api/remediate/apply":
            self._remediate_apply()
            return
        if url.path not in ("/api/upload", "/api/analyze"):
            self._json(404, {"ok": False, "error": "not found"})
            return

        name = os.path.basename((parse_qs(url.query).get("name") or ["upload.pcap"])[0]) or "upload.pcap"
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"ok": False, "filename": name, "error": "The file is empty."})
            return
        if length > MAX_UPLOAD_BYTES:
            self._json(413, {"ok": False, "filename": name,
                              "error": f"File is larger than the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit."})
            return
        data = self.rfile.read(length)
        if _sniff(data[:8]) is None:
            self._json(400, {"ok": False, "filename": name,
                              "error": "Not a pcap or pcapng capture (bad magic bytes). Nothing was parsed."})
            return

        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=_TMP_PREFIX, suffix=".pcap")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            t0 = time.monotonic()
            a = analyze(tmp_path)
            print(f"[tunnelscope serve] analysed {name}: {length} bytes, {len(a['sas'])} SA(s), "
                  f"{time.monotonic() - t0:.2f}s", file=sys.stderr, flush=True)
            anomalies = None
            if HISTORY_DIR and url.path == "/api/analyze":
                with _HISTORY_LOCK:
                    anomalies = observe(History(HISTORY_DIR), a["sas"], name)
            if url.path == "/api/analyze":
                self._json(200, analysis_json(a, name, anomalies))
            else:
                self._json(200, {"ok": True, "filename": name, "n_sas": len(a["sas"]),
                                  "html": render_sas_html(a)})
        except Exception as e:  # a bad-but-magic-matching file must not crash the server
            print(f"[tunnelscope serve] {name}: {type(e).__name__}: {e}", file=sys.stderr)
            self._json(200, {"ok": False, "filename": name,
                              "error": f"tshark could not parse this capture ({type(e).__name__})."})
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def log_message(self, fmt, *args):  # keep stderr access logging, just tag it
        if self.path == "/health":  # start.sh polls this; don't drown the log
            return
        sys.stderr.write(f"[tunnelscope serve] {self.address_string()} - {fmt % args}\n")


def history_summary() -> dict:
    if not HISTORY_DIR:
        return {"ok": True, "enabled": False, "tunnels": []}
    rows = History(HISTORY_DIR).load()
    by: dict[str, dict] = {}
    for r in rows:
        t = by.setdefault(r["tunnel"], {"tunnel": r["tunnel"], "observations": 0})
        t["observations"] += 1
        t["last_at"], t["last_source"], t["last_profile"] = r["at"], r["source"], r["profile"]
    return {"ok": True, "enabled": True, "tunnels": sorted(by.values(), key=lambda t: -t["last_at"])}


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), _Handler)


def run_server(port: int = 8765, open_browser: bool = True, history: str | None = None,
               live_follow: str | None = None, live_interface: str | None = None, live_window: int = 30) -> None:
    global HISTORY_DIR, LIVE
    if history:
        HISTORY_DIR = history
    if live_follow or live_interface:
        from ..live.live import LiveMonitor
        LIVE = LiveMonitor(interface=live_interface, follow=live_follow, window=live_window, history=HISTORY_DIR)
        LIVE.start_capture()
        threading.Thread(target=LIVE.run, daemon=True).start()
    server = make_server(port)
    bound_port = server.server_address[1]
    url = f"http://127.0.0.1:{bound_port}/"
    ui = "dashboard" if (DASHBOARD_DIR / "index.html").is_file() else "basic page (no dashboard build found)"
    print(f"TunnelScope local {ui}: {url}")
    print("Local only (127.0.0.1); uploads are deleted after each response.")
    print(f"Anomaly history: {HISTORY_DIR + ' (posture profiles only, no packets)' if HISTORY_DIR else 'off'}")
    print(f"Live analysis: {LIVE.status()['source'] + f', {LIVE.window}s windows' if LIVE else 'off'}")
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        if LIVE:
            LIVE.stop()
        server.server_close()
