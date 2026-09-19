"""T-059: the local upload dashboard. Spins up a real server on an OS-assigned
port (127.0.0.1 only), hits it over HTTP, and shuts it down — no mocking of
http.server, so a real socket/threading bug would actually fail this."""
import glob
import http.client
import os
import tempfile
import threading

import pytest

from tunnelscope.api.server import make_server

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")


@pytest.fixture
def server(tmp_path, monkeypatch):
    # no dashboard build: "/" serves the built-in page, whatever is on disk
    import tunnelscope.api.server as srvmod
    monkeypatch.setattr(srvmod, "DASHBOARD_DIR", tmp_path / "no-build")
    srv = make_server(port=0)  # 0 = OS picks a free port
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()
    srv.server_close()
    t.join(timeout=5)


def _upload(port, name, body):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", f"/api/upload?name={name}", body=body)
    resp = conn.getresponse()
    import json
    return resp.status, json.loads(resp.read())


def test_binds_to_localhost_only():
    srv = make_server(port=0)
    try:
        assert srv.server_address[0] == "127.0.0.1"
    finally:
        srv.server_close()


def test_index_page_serves(server):
    conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
    conn.request("GET", "/")
    resp = conn.getresponse()
    body = resp.read().decode()
    assert resp.status == 200
    assert "TunnelScope" in body and "drop" in body.lower()


def test_health(server):
    conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    import json
    assert resp.status == 200
    assert json.loads(resp.read()) == {"ok": True, "dashboard": False, "history": False, "live": False}


def test_real_pcap_upload_returns_findings(server):
    with open(os.path.join(CAP, "classical-baseline.pcap"), "rb") as f:
        body = f.read()
    status, data = _upload(server, "classical-baseline.pcap", body)
    assert status == 200
    assert data["ok"] is True
    assert data["filename"] == "classical-baseline.pcap"
    assert data["n_sas"] >= 1
    # the fragment is the same per-SA rendering the CLI dashboard uses (shared
    # render_sas_html) - it must contain real finding markup, not a stub
    assert "MODP-2048" in data["html"] or "ike_dh_group" in data["html"]
    assert "<table" in data["html"]


def test_non_pcap_upload_is_refused_before_parsing(server):
    status, data = _upload(server, "not-a-pcap.txt", b"hello, this is not a capture file")
    assert status == 400
    assert data["ok"] is False
    assert "magic bytes" in data["error"]


def test_corrupt_but_magic_matching_file_is_a_clean_error_not_a_crash(server):
    # real pcap magic, garbage after it - tshark will fail to parse this
    status, data = _upload(server, "corrupt.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    assert data["ok"] is False
    assert "error" in data
    # server must still be alive for the next request
    status2, data2 = _upload(server, "corrupt2.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    assert "error" in data2


def test_upload_leaves_no_temp_file_behind(server):
    pattern = os.path.join(tempfile.gettempdir(), "tunnelscope-upload-*")
    before = set(glob.glob(pattern))
    with open(os.path.join(CAP, "classical-baseline.pcap"), "rb") as f:
        _upload(server, "classical-baseline.pcap", f.read())
    after = set(glob.glob(pattern))
    assert after == before, f"upload left temp files behind: {after - before}"


# --------------------------------------------------------------------------- #
# T-060: JSON endpoint for the React dashboard + serving its build.            #
# --------------------------------------------------------------------------- #
def _get(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    return resp.status, resp.getheader("Content-Type") or "", resp.read()


def _analyze(port, name, body):
    import json
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    conn.request("POST", f"/api/analyze?name={name}", body=body)
    resp = conn.getresponse()
    return resp.status, json.loads(resp.read())


def test_analyze_json_matches_the_pipeline(server):
    """The dashboard must show exactly what the pipeline found - same posture,
    same FAILs, same finding statuses - for a capture with known ground truth."""
    from tunnelscope.report.report import analyze
    path = os.path.join(CAP, "pq-downgrade.pcap")
    with open(path, "rb") as f:
        status, data = _analyze(server, "pq-downgrade.pcap", f.read())
    assert status == 200 and data["ok"] is True
    sa = data["sas"][0]
    a = analyze(path)
    assert sa["posture"] == a["cbom"]["tunnelscope_sa_summary"][0]["quantum_posture"]
    assert {f["rule_id"] for f in sa["fails"]} == {v.rule_id for v in a["sas"][0]["verdicts"] if v.verdict == "FAIL"}
    pq = next(f for f in sa["findings"] if f["attribute"] == "pq_key_exchange")
    assert (pq["status"], pq["value"]) == ("OBSERVED", "offered-but-not-used")
    assert sa["id"] == "pq-downgrade.pcap#1" and sa["source"] == "pq-downgrade.pcap"


def test_analyze_strips_path_from_client_filename(server):
    with open(os.path.join(CAP, "classical-baseline.pcap"), "rb") as f:
        _, data = _analyze(server, "..%2F..%2Fetc%2Fpasswd.pcap", f.read())
    assert data["filename"] == "passwd.pcap"


def test_serves_dashboard_build_with_spa_fallback(tmp_path, monkeypatch):
    import tunnelscope.api.server as srvmod
    (tmp_path / "index.html").write_text("<!doctype html><div id=root>DASH</div>")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setattr(srvmod, "DASHBOARD_DIR", tmp_path)
    srv = srvmod.make_server(port=0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        st, ct, body = _get(port, "/")
        assert st == 200 and b"DASH" in body and "text/html" in ct
        st, ct, body = _get(port, "/assets/app.js")
        assert st == 200 and "javascript" in ct
        st, _, body = _get(port, "/some/client/route")   # SPA fallback
        assert st == 200 and b"DASH" in body
        st, _, body = _get(port, "/basic")               # built-in page stays reachable
        assert st == 200 and b"local dashboard" in body
    finally:
        srv.shutdown(); srv.server_close(); t.join(timeout=5)


def test_static_serving_cannot_escape_the_build_dir(tmp_path, monkeypatch):
    import tunnelscope.api.server as srvmod
    build = tmp_path / "dist"; build.mkdir()
    (build / "index.html").write_text("DASH")
    (tmp_path / "secret.txt").write_text("TOP-SECRET")
    monkeypatch.setattr(srvmod, "DASHBOARD_DIR", build)
    srv = srvmod.make_server(port=0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    try:
        for p in ("/../secret.txt", "/%2e%2e/secret.txt", "/assets/..%2F..%2Fsecret.txt"):
            st, _, body = _get(port, p)
            assert b"TOP-SECRET" not in body, p
    finally:
        srv.shutdown(); srv.server_close(); t.join(timeout=5)
