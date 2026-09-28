"""The public demo (Railway deployment, owner 2026-09-28): only with TUNNELSCOPE_PUBLIC_DEMO=1, set by the deployment.
It analyses captures and nothing else: every endpoint that changes a system, drafts with a model, captures live or
reads local state is refused, uploads are capped, and at most DEMO_CONCURRENCY analyses run at once. Without the
variable the server is exactly the local-only one."""
import http.client
import json
import threading
from pathlib import Path

import pytest

from tunnelscope.api import server as S

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures" / "pq-downgrade.pcap"


@pytest.fixture
def demo(monkeypatch):
    monkeypatch.setenv(S.DEMO_ENV, "1")
    calls = []
    import tunnelscope.remediate.execute as ex
    for name in ("apply_remediation", "preview_remediation", "lab_targets"):
        monkeypatch.setattr(ex, name, lambda *a, _n=name, **k: calls.append(_n) or {"ok": True})
    srv = S.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, calls
    srv.shutdown()


def _req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def test_without_the_variable_the_server_is_local_only(monkeypatch):
    monkeypatch.delenv(S.DEMO_ENV, raising=False)
    srv = S.make_server(0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()


def test_the_demo_listens_publicly_and_says_so(demo):
    srv, _ = demo
    assert srv.server_address[0] == "0.0.0.0"
    st, body = _req(srv.server_address[1], "GET", "/health")
    assert st == 200 and body["public_demo"] is True


@pytest.mark.parametrize("method,path", [("GET", "/api/remediate/targets"), ("GET", "/api/live"), ("GET", "/api/sites"),
                                         ("GET", "/api/history"), ("POST", "/api/remediate/plan"),
                                         ("POST", "/api/remediate/preview"), ("POST", "/api/remediate/apply"),
                                         ("POST", "/api/remediate/generate")])
def test_everything_that_changes_a_system_is_refused(demo, method, path):
    srv, calls = demo
    st, body = _req(srv.server_address[1], method, path, body=b"{}" if method == "POST" else None,
                    headers={"Content-Type": "application/json"})
    assert st == 403 and "public demo" in body["error"]
    assert calls == []                                             # nothing behind the endpoint ran


def test_drafting_is_off_and_uploads_are_capped(demo):
    srv, _ = demo
    port = srv.server_address[1]
    st, caps = _req(port, "GET", "/api/remediate/capabilities")
    assert caps["generator_enabled"] is False and caps["public_demo"] is True
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    c.putrequest("POST", "/api/analyze?name=big.pcap")
    c.putheader("Content-Length", str(S.DEMO_MAX_UPLOAD_BYTES + 1))
    c.endheaders()                                                  # refused on the header, before reading a byte
    r = c.getresponse()
    assert r.status == 413 and "25 MB" in json.loads(r.read())["error"]


def test_a_real_capture_is_analysed_with_its_known_vulnerabilities(demo):
    srv, _ = demo
    st, body = _req(srv.server_address[1], "POST", "/api/analyze?name=pq-downgrade.pcap", body=CAP.read_bytes())
    assert st == 200 and body["ok"] and body["n_sas"] == 1
    assert "known_vulnerabilities" in body["sas"][0]


def test_a_third_simultaneous_analysis_is_told_to_retry(demo):
    srv, _ = demo
    for _ in range(S.DEMO_CONCURRENCY):
        assert S._DEMO_SLOTS.acquire(blocking=False)
    try:
        st, body = _req(srv.server_address[1], "POST", "/api/analyze?name=x.pcap", body=CAP.read_bytes())
        assert st == 503 and "busy" in body["error"]
    finally:
        for _ in range(S.DEMO_CONCURRENCY):
            S._DEMO_SLOTS.release()
