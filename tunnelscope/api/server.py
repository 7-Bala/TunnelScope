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
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from ..report.report import analyze
from ..report.dashboard import _CSS, render_sas_html

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB: generous for a capture, not for a DoS
_TMP_PREFIX = "tunnelscope-upload-"

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
    card.innerHTML = '<b>' + f.name + '</b> — <span class="pending">analyzing…</span>';
    results.prepend(card);
    try {{
      const res = await fetch('/api/upload?name=' + encodeURIComponent(f.name),
                              {{method: 'POST', body: f}});
      const data = await res.json();
      if (data.ok) {{
        card.innerHTML = '<div class="sub">Source: ' + data.filename + ' · ' +
          data.n_sas + ' security association(s)</div>' + data.html;
      }} else {{
        card.innerHTML = '<b>' + f.name + '</b> — <span class="tag t-fail">error</span> ' + data.error;
      }}
    }} catch (err) {{
      card.innerHTML = '<b>' + f.name + '</b> — <span class="tag t-fail">error</span> ' + err;
    }}
  }}
}}
</script></body></html>"""


def _sniff(head: bytes) -> str | None:
    for magic, name in _MAGIC.items():
        if head.startswith(magic):
            return name
    return None


class _Handler(BaseHTTPRequestHandler):
    server_version = "TunnelScope/0.2"

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (stdlib method name)
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            body = _PAGE.format(css=_CSS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/health":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/upload":
            self._json(404, {"ok": False, "error": "not found"})
            return
        name = (parse_qs(urlparse(self.path).query).get("name") or ["upload.pcap"])[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            self._json(400, {"ok": False, "filename": name, "error": "empty upload"})
            return
        if length > MAX_UPLOAD_BYTES:
            self._json(413, {"ok": False, "filename": name,
                              "error": f"file exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit"})
            return
        data = self.rfile.read(length)
        if _sniff(data[:8]) is None:
            self._json(400, {"ok": False, "filename": name,
                              "error": "not a pcap/pcapng file (bad magic bytes) — refused before parsing"})
            return

        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix=_TMP_PREFIX, suffix=".pcap")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            a = analyze(tmp_path)
            frag = render_sas_html(a)
            self._json(200, {"ok": True, "filename": name, "n_sas": len(a["sas"]), "html": frag})
        except Exception as e:  # a bad-but-magic-matching file must not crash the server
            print(f"[tunnelscope serve] {name}: {type(e).__name__}: {e}", file=sys.stderr)
            self._json(200, {"ok": False, "filename": name, "error": f"{type(e).__name__}: {e}"})
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def log_message(self, fmt, *args):  # keep stderr access logging, just tag it
        sys.stderr.write(f"[tunnelscope serve] {self.address_string()} - {fmt % args}\n")


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), _Handler)


def run_server(port: int = 8765, open_browser: bool = True) -> None:
    server = make_server(port)
    bound_port = server.server_address[1]
    url = f"http://127.0.0.1:{bound_port}/"
    print(f"TunnelScope local dashboard: {url}")
    print("Local only (127.0.0.1) — nothing leaves this machine; uploads are deleted after each response.")
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
