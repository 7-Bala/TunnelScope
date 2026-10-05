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
# Public demo (the Railway deployment, owner 2026-09-28): set only by the deployment, never by a flag a user can pass.
# The server then listens on all interfaces (the platform's proxy in front), and everything that changes a system
# is refused: fixes (lab or gateway), drafting, live capture, site views, anomaly history. Uploads are smaller and
# at most DEMO_CONCURRENCY analyses run at once. Uploads are deleted after each response, as always.
DEMO_ENV = "TUNNELSCOPE_PUBLIC_DEMO"
DEMO_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
DEMO_CONCURRENCY = 2
_DEMO_SLOTS = threading.BoundedSemaphore(DEMO_CONCURRENCY)
DEMO_REFUSAL = ("disabled in the public demo: it analyses captures only. Fixing gateways, drafting, live capture and "
                "site views run on your own machine (tunnelscope serve).")


def public_demo() -> bool:
    return os.environ.get(DEMO_ENV) == "1"

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
        # DEC-045: known vulnerabilities for the identified software, on every analysis, next to the verdicts
        from ..intel.lookup import known_vulnerabilities
        sas[-1]["known_vulnerabilities"] = known_vulnerabilities(r.findings)
    return {"ok": True, "filename": source, "n_sas": len(sas), "sas": sas}


def _sniff(head: bytes) -> str | None:
    for magic, name in _MAGIC.items():
        if head.startswith(magic):
            return name
    return None


_LOCAL_MODEL: list[bool] = []


def local_model_available() -> bool:
    """Whether the pinned local model can run here (Apple Silicon + mlx_lm + the model on disk).
    Worked out once per process: /health is polled."""
    if not _LOCAL_MODEL:
        try:
            from ..rephrase.runtime import model_available
            _LOCAL_MODEL.append(bool(model_available()))
        except Exception:
            _LOCAL_MODEL.append(False)
    return _LOCAL_MODEL[0]


def generator_enabled() -> bool:
    """DEC-034 D-E: local-model drafts are OFF until EXP-18's H1 and H2 bars pass and a decision
    row turns them on. Only an explicit TUNNELSCOPE_GENERATOR=1 (lab testing) enables them."""
    return os.environ.get("TUNNELSCOPE_GENERATOR") == "1"


_CLOUD_MODEL: list[bool] = []


def cloud_model_available() -> bool:
    """DEC-038: whether the optional cloud backend can be called here (API key set, SDK
    importable — see remediate/cloud_client.py for which provider). Worked out once per process,
    like local_model_available()."""
    if not _CLOUD_MODEL:
        try:
            from ..remediate import cloud_client, open_model_client     # DEC-040: either cloud client counts
            _CLOUD_MODEL.append(bool(cloud_client.available() or open_model_client.available()))
        except Exception:
            _CLOUD_MODEL.append(False)
    return _CLOUD_MODEL[0]


def generator_backend() -> str:
    """DEC-038: which model drafts, chosen only by this server-side setting — never by a client
    request. "local" (default, on-device) unless an operator sets
    TUNNELSCOPE_GENERATOR_BACKEND=cloud (see tunnelscope/remediate/cloud_client.py for which provider)."""
    b = os.environ.get("TUNNELSCOPE_GENERATOR_BACKEND", "local").strip().lower()
    return b if b in ("cloud", "chain") else "local"


# Binding to 127.0.0.1 keeps other MACHINES out, not other web pages in this user's browser: a page can point a
# hostname it controls at 127.0.0.1 (DNS rebinding) and then read and post to this server as "same origin". So a
# request must NAME this server as a local host, and a request sent by a page must come from a local page.
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


def _hostname(hostport: str) -> str:
    h = (hostport or "").strip().lower()
    if h.startswith("["):                       # [::1]:8765
        return h.split("]", 1)[0] + "]"
    return h.rsplit(":", 1)[0] if ":" in h else h


def request_is_local(headers) -> bool:
    """False for a request whose Host is not this machine, or whose Origin is another site. Not applied in the public
    demo (it is served under the platform's own hostname and changes nothing)."""
    if public_demo():
        return True
    if _hostname(headers.get("Host", "")) not in _LOCAL_HOSTS:
        return False
    origin = headers.get("Origin")
    if origin:
        return urlparse(origin).scheme in ("http", "https") and (urlparse(origin).hostname or "") in {"127.0.0.1", "localhost", "::1"}
    return True


class _Handler(BaseHTTPRequestHandler):
    server_version = "TunnelScope/0.2"

    def _refuse_foreign(self) -> bool:
        if request_is_local(self.headers):
            return False
        self._json(403, {"ok": False, "error": "refused: this server answers only requests made to 127.0.0.1 / "
                                               "localhost from a local page"})
        return True

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
        if self._refuse_foreign():
            return
        path = urlparse(self.path).path
        if public_demo() and path in ("/api/remediate/targets", "/api/live", "/api/sites", "/api/history"):
            self._json(403, {"ok": False, "error": DEMO_REFUSAL})
            return
        if path == "/health":
            body = {"ok": True, "dashboard": (DASHBOARD_DIR / "index.html").is_file(),
                    "history": bool(HISTORY_DIR), "live": LIVE is not None}
            self._json(200, body | ({"public_demo": True} if public_demo() else {}))
        elif path == "/api/remediate/capabilities":
            backend = generator_backend()
            if public_demo():
                self._json(200, {"ok": True, "local_model": False, "cloud_model": False, "backend": "local",
                                 "generator_enabled": False, "public_demo": True})
                return
            self._json(200, {"ok": True, "local_model": local_model_available(),
                             "cloud_model": cloud_model_available(), "backend": backend,
                             "generator_enabled": generator_enabled()})
        elif path == "/api/history":
            self._json(200, history_summary())
        elif path == "/api/live":
            if LIVE is None:
                self._json(200, {"ok": True, "enabled": False})
            else:
                st = LIVE.status()
                st["windows"] = st["windows"][:20]
                self._json(200, {"ok": True, **st})
        elif path == "/api/sites":
            # T-139: per-site freshness from a collector's state directory (server-side setting only; a stale site
            # is shown with posture UNKNOWN, never its last posture)
            state = os.environ.get("TUNNELSCOPE_COLLECTOR_STATE")
            if not state:
                self._json(200, {"ok": True, "enabled": False})
            else:
                from ..sensor.collector import STALE_WINDOWS, sites_status
                self._json(200, {"ok": True, "enabled": True, "stale_after_windows": STALE_WINDOWS,
                                 "sites": sites_status(state)})
        elif path == "/api/intel":
            # T-130 part 2: known vulnerabilities for a fingerprinted implementation, only when the dashboard asks
            # (a button, never automatic). Online unless TUNNELSCOPE_NETWORK=off (on by default, DEC-045); then the cache/bundle.
            from ..intel.lookup import lookup
            from ..intel.sources import PRODUCTS
            impl = (parse_qs(urlparse(self.path).query).get("implementation") or [""])[0]
            if impl not in PRODUCTS:
                self._json(400, {"ok": False, "error": f"unknown implementation; one of {sorted(PRODUCTS)}"})
            else:
                self._json(200, {"ok": True, **lookup(impl)})
        elif path == "/api/remediate/targets":
            from ..remediate.execute import lab_targets
            self._json(200, {"ok": True, "targets": lab_targets(), "recommended": "sih26-alice-pq"})
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
                plan_id=body.get("plan_id"),
                digest=body.get("digest"),
                require_digest=True,   # T-104: the dashboard applies only what it previewed
            )
            # A refusal is the caller's to fix (400). A change that ran and was rolled back
            # is a real outcome, reported with 200 like a successful one.
            self._json(400 if res.get("decision") == "refused" else 200, res)
        except Exception as e:
            sys.stderr.write(f"[tunnelscope serve] remediate apply error: {e}\n")
            # The exception may come after the lab was changed, so the outcome is NOT "nothing changed":
            # say it is unknown, and that the in-container watchdog restores an unconfirmed change.
            from ..remediate.execute import WATCHDOG_TIMEOUT_S
            self._json(500, {"ok": False, "stage": "execute", "decision": "unknown",
                             "error": "unexpected server error during remediation",
                             "watchdog_timeout_s": WATCHDOG_TIMEOUT_S})

    def _remediate_preview(self) -> None:
        """Dry run only: the real diff for a rule on a lab container, shown before approval."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1024 * 1024:
            self._json(400 if length <= 0 else 413, {"ok": False, "stage": "validate", "error": "empty or oversized body"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "stage": "validate", "error": "invalid json"})
            return
        if not isinstance(body, dict) or not isinstance(body.get("rule_id"), str) or not isinstance(body.get("target"), str):
            self._json(400, {"ok": False, "stage": "validate", "error": "rule_id and target are required strings"})
            return
        try:
            from ..remediate.execute import preview_remediation
            res = preview_remediation(body["rule_id"], body["target"], caller=self.address_string(), history_dir=HISTORY_DIR,
                                      plan_id=body.get("plan_id"))
            self._json(200 if res.get("ok") else 400, res)
        except Exception as e:
            sys.stderr.write(f"[tunnelscope serve] remediate preview error: {e}\n")
            self._json(500, {"ok": False, "stage": "dry_run", "error": "unexpected server error during the dry run"})

    def _read_json_body(self) -> dict | None:
        """Parse a JSON object body, answering 400/413 itself on failure (then returns None)."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1024 * 1024:
            self._json(400 if length <= 0 else 413, {"ok": False, "stage": "validate", "error": "empty or oversized body"})
            return None
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(400, {"ok": False, "stage": "validate", "error": "invalid json"})
            return None
        if not isinstance(body, dict):
            self._json(400, {"ok": False, "stage": "validate", "error": "body must be an object"})
            return None
        return body

    def _remediate_generate(self) -> None:
        """A local-model draft, checked by code and dry-run, shown next to the hand-written fix
        (DEC-034). Never applies anything; a checked draft is stored and gets a plan_id."""
        body = self._read_json_body()
        if body is None:
            return
        if not isinstance(body.get("rule_id"), str) or not isinstance(body.get("target"), str):
            self._json(400, {"ok": False, "stage": "validate", "error": "rule_id and target are required strings"})
            return
        if not generator_enabled():
            self._json(403, {"ok": False, "stage": "disabled",
                             "error": "local-model drafts are off until the EXP-18 evaluation passes (DEC-034)"})
            return
        try:
            from ..remediate import execute, generate
            backend = generator_backend()
            res = generate.generate_plan(body["rule_id"], body["target"], body.get("observed"),
                                         compare_with_handwritten=True, backend=backend,
                                         **generate.shipped_settings(backend))
            if res.get("ok"):
                res["plan_id"] = execute.store_generated_plan(res["plan"], body["target"], HISTORY_DIR)
            plan = res.get("plan") or {}
            execute.record_audit({"timestamp": time.time(), "at": time.time(), "decision": "generate",
                                  "caller": self.address_string(), "rule_id": body["rule_id"], "target": body["target"],
                                  "ok": bool(res.get("ok")), "stage": res.get("stage"), "reason": res.get("reason"),
                                  "plan_id": res.get("plan_id"), "model_revision": plan.get("model_revision"),
                                  "backend": plan.get("backend"), "prompt_sha256": plan.get("prompt_sha256"),
                                  "rounds": len(plan.get("revisions") or res.get("revisions") or [])}, HISTORY_DIR)
            self._json(200, res)
        except Exception as e:
            sys.stderr.write(f"[tunnelscope serve] remediate generate error: {e}\n")
            self._json(500, {"ok": False, "stage": "internal", "error": "unexpected server error while drafting"})

    def do_POST(self):  # noqa: N802
        if self._refuse_foreign():
            return
        url = urlparse(self.path)
        if public_demo() and url.path.startswith("/api/remediate/"):
            self._json(403, {"ok": False, "error": DEMO_REFUSAL})
            return
        if public_demo():
            if not _DEMO_SLOTS.acquire(blocking=False):
                self._json(503, {"ok": False, "error": "The public demo is busy; try again in a few seconds."})
                return
            try:
                self._upload(url)
            finally:
                _DEMO_SLOTS.release()
            return
        self._upload(url)

    def _upload(self, url) -> None:
        if url.path == "/api/remediate/plan":
            self._remediate_plan()
            return
        if url.path == "/api/remediate/apply":
            self._remediate_apply()
            return
        if url.path == "/api/remediate/preview":
            self._remediate_preview()
            return
        if url.path == "/api/remediate/generate":
            self._remediate_generate()
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
        limit = DEMO_MAX_UPLOAD_BYTES if public_demo() else MAX_UPLOAD_BYTES
        if length > limit:
            self._json(413, {"ok": False, "filename": name,
                              "error": f"File is larger than the {limit // (1024*1024)} MB limit."})
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
            if HISTORY_DIR and url.path == "/api/analyze" and not public_demo():
                with _HISTORY_LOCK:
                    anomalies = observe(History(HISTORY_DIR), a["sas"], name)
            if url.path == "/api/analyze":
                self._json(200, analysis_json(a, name, anomalies))
            else:
                self._json(200, {"ok": True, "filename": name, "n_sas": len(a["sas"]),
                                  "html": render_sas_html(a)})
        except Exception as e:  # a bad-but-magic-matching file must not crash the server
            print(f"[tunnelscope serve] {name}: {type(e).__name__}: {e}", file=sys.stderr)
            # Only an input/dependency error is the capture's fault; anything else is a fault in TunnelScope and
            # must not be reported to the analyst as a bad file.
            from ..errors import TunnelScopeError
            msg = (f"tshark could not parse this capture ({type(e).__name__})." if isinstance(e, TunnelScopeError)
                   else f"TunnelScope hit an internal error analysing this capture ({type(e).__name__}); "
                        "the capture itself may be fine.")
            self._json(200, {"ok": False, "filename": name, "error": msg})
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def log_message(self, fmt, *args):  # keep stderr access logging, just tag it
        # http.server logs a malformed request line BEFORE it sets self.path
        if getattr(self, "path", "") == "/health":  # start.sh polls this; don't drown the log
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
    """127.0.0.1 only; all interfaces only in the public demo (TUNNELSCOPE_PUBLIC_DEMO=1, set by the deployment)."""
    return ThreadingHTTPServer(("0.0.0.0" if public_demo() else "127.0.0.1", port), _Handler)


def run_server(port: int = 8765, open_browser: bool = True, history: str | None = None,
               live_follow: str | None = None, live_interface: str | None = None, live_window: int = 30) -> None:
    global HISTORY_DIR, LIVE
    if public_demo():                    # the platform assigns the port; nothing that changes a system runs
        port = int(os.environ.get("PORT", port))
        open_browser, history, live_follow, live_interface = False, None, None, None
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
    if public_demo():
        print(f"TunnelScope PUBLIC DEMO {ui} on port {bound_port} (all interfaces); captures only, uploads <= "
              f"{DEMO_MAX_UPLOAD_BYTES // (1024 * 1024)} MB, deleted after each response; fixing, drafting, live "
              "and site views are disabled.")
    else:
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
