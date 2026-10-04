"""Regression tests for the bugs found in the 2026-10-04 code review. Each one failed before its fix."""
import json
import socket
import subprocess
import threading

import pytest

from tunnelscope.evidence import extract as X
from tunnelscope.evidence.record import EvidenceRecord, Status

CLASSICAL = "testbed/captures/classical-baseline-6.1.0.pcap"
AH = "testbed/captures/exp15/a-tra-sha1.pcap"


def _msg(exchange, response, frame, ip_len=300):
    return dict(exchange=exchange, is_response=response, frame=frame, t=float(frame), notify_types=[], ip_len=ip_len,
                transform_types=[1], exchange_name="x", message_id=0, src="a", dst="b")


def _esp(n=7, t=100.0, content=92):
    return [dict(frame=i, t=t + i, src="203.0.113.1", dst="203.0.113.2", ip_len=120, esp_content=content,
                 esp_content_known=True, spi="0x1", seq=i) for i in range(1, n + 1)]


def test_esp_only_record_never_takes_another_tunnels_ike_suite():
    """An ESP-only flow in a capture that holds some OTHER tunnel's handshake has no IKE findings of its own."""
    r = EvidenceRecord(src="203.0.113.1", dst="203.0.113.2", source_pcap=CLASSICAL)
    r._ike, r._esp, r._ah, r._esp_only = [], _esp(), [], True
    X.extract_ike_meta(r)
    X.extract_ike_crypto(r)
    for attr in ("ike_encr", "ike_integ", "ike_dh_group"):
        assert r.findings[attr].status is Status.UNKNOWN, attr
        assert r.findings[attr].value is None
    assert "ike_prf" not in r.findings


def test_esp_without_ike_auth_is_not_an_observed_success():
    r = EvidenceRecord(ike_spi_i="aa", src="a", dst="b", source_pcap=CLASSICAL)
    r._ike, r._esp, r._truncated = [_msg(34, False, 10), _msg(34, True, 11)], _esp(), False
    X.extract_failure(r)
    f = r.findings["negotiation_outcome"]
    assert f.status is Status.UNKNOWN and "IKE_AUTH" in f.note


def test_esp_only_before_the_handshake_is_not_an_observed_success():
    r = EvidenceRecord(ike_spi_i="aa", src="a", dst="b", source_pcap=CLASSICAL)
    r._ike = [_msg(34, False, 10), _msg(34, True, 11), _msg(35, False, 12), _msg(35, True, 13)]
    r._esp, r._truncated = _esp(t=0.0, n=5), False        # all ESP at t=1..5, the handshake starts at t=10
    X.extract_failure(r)
    assert r.findings["negotiation_outcome"].status is Status.UNKNOWN


def test_ike_auth_and_esp_after_it_is_still_an_observed_success():
    r = EvidenceRecord(ike_spi_i="aa", src="a", dst="b", source_pcap=CLASSICAL)
    r._ike = [_msg(34, False, 10), _msg(34, True, 11), _msg(35, False, 12), _msg(35, True, 13)]
    r._esp, r._truncated = _esp(), False
    X.extract_failure(r)
    f = r.findings["negotiation_outcome"]
    assert (f.status, f.value) == (Status.OBSERVED, "success")


def test_sieve_with_no_surviving_family_is_unknown_not_cbc():
    r = EvidenceRecord(src="a", dst="b", source_pcap=CLASSICAL)
    r._esp = [dict(frame=i, esp_content=c) for i, c in enumerate([21, 37, 53, 22, 38, 70])]
    X.extract_cipher_sieve(r)
    f = r.findings["esp_cipher_family"]
    assert f.status is Status.UNKNOWN and "CBC-mode" not in f.note


@pytest.fixture()
def ah_only(tmp_path):
    out = tmp_path / "ah-only.pcap"
    subprocess.run(["tshark", "-n", "-r", AH, "-Y", "ah", "-w", str(out)], check=True, capture_output=True)
    return str(out)


def test_ah_only_capture_reports_instead_of_crashing(ah_only, capsys):
    from tunnelscope.api.server import analysis_json
    from tunnelscope.cli import main
    from tunnelscope.report.dashboard import render_sas_html
    from tunnelscope.report.report import analyze, executive_report, technical_report
    a = analyze(ah_only)
    assert len(a["sas"]) >= 1
    assert len(a["cbom"]["tunnelscope_sa_summary"]) == len(a["sas"])
    assert "AH-only" in a["cbom"]["tunnelscope_sa_summary"][0]["quantum_posture"]
    executive_report(a), technical_report(a), render_sas_html(a)
    assert analysis_json(a, "ah-only.pcap")["n_sas"] == len(a["sas"])
    assert main(["analyze", ah_only]) == 0
    assert "ipsec_protocols" in capsys.readouterr().out           # the CLI used to print no SA at all


def test_ledger_reanalyse_without_capture_is_refused(tmp_path, capsys):
    from tunnelscope.cli import main
    from tunnelscope.ledger import build_ledger, verify_ledger
    led = build_ledger(CLASSICAL)
    r = verify_ledger(led, pcap=None, reanalyse=True)
    assert r["ok"] is False and "without the capture" in r["reason"]
    p = tmp_path / "led.json"
    p.write_text(json.dumps(led))
    assert main(["ledger-verify", str(p), "--reanalyse"]) == 2
    assert "re-analysis matches" not in capsys.readouterr().out
    assert main(["ledger-verify", str(p)]) == 0
    assert "internally consistent" in capsys.readouterr().out     # a plain check says what it does not prove
    assert main(["ledger-verify", str(p), "--pcap", CLASSICAL, "--reanalyse"]) == 0
    assert "re-analysis matches" in capsys.readouterr().out


@pytest.fixture()
def local_server():
    from tunnelscope.api import server
    srv = server.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


def _raw(port, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(request)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


def test_malformed_request_gets_an_error_reply(local_server):
    assert b" 400 " in _raw(local_server, b"GARBAGE\r\n\r\n").split(b"\r\n", 1)[0]


@pytest.mark.parametrize("host,origin,status", [
    ("127.0.0.1:{p}", None, b" 200 "),
    ("localhost:{p}", "http://localhost:5173", b" 200 "),          # the Vite dev server's proxy
    ("[::1]:{p}", None, b" 200 "),
    ("evil.example:{p}", None, b" 403 "),                          # DNS rebinding: a foreign name for 127.0.0.1
    ("127.0.0.1:{p}", "http://evil.example", b" 403 "),            # a cross-site request from another page
    ("127.0.0.1:{p}", "null", b" 403 "),
])
def test_server_answers_only_local_host_and_origin(local_server, host, origin, status):
    body = b'{"rule_id":"V-207193"}'
    head = f"Host: {host.format(p=local_server)}\r\n" + (f"Origin: {origin}\r\n" if origin else "")
    get = _raw(local_server, f"GET /health HTTP/1.1\r\n{head}\r\n".encode())
    post = _raw(local_server, f"POST /api/remediate/plan HTTP/1.1\r\n{head}Content-Type: text/plain\r\n"
                              f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    assert status in get.split(b"\r\n", 1)[0]
    assert status in post.split(b"\r\n", 1)[0]


def test_public_demo_is_not_host_checked(local_server, monkeypatch):
    from tunnelscope.api import server
    monkeypatch.setenv(server.DEMO_ENV, "1")
    assert b" 200 " in _raw(local_server, b"GET /health HTTP/1.1\r\nHost: demo.example.app\r\n\r\n").split(b"\r\n", 1)[0]


def _report(**over):
    from tunnelscope.sensor import report as R
    rep = R.build_report("site-a", 1, 30, None, "0.0", now=1.0)
    rep.update(over)
    return rep


@pytest.mark.parametrize("over", [
    {"window_s": "30"}, {"window_s": 0}, {"window_s": True}, {"tunnels": "x"}, {"alerts": 5}, {"sent_at": "now"},
    {"tunnels": [{"dst": "b", "posture": "p", "fails": []}]},                       # no src
    {"tunnels": [{"src": "a", "dst": "b", "posture": "p", "fails": [{"baseline": "x"}]}]},   # a fail without rule_id
])
def test_sensor_report_with_wrong_types_is_rejected(over):
    from tunnelscope.sensor import report as R
    with pytest.raises(R.ReportError):
        R.validate(_report(**over), signed=False)


def test_cbom_flags_every_classical_group_quantum_vulnerable():
    from tunnelscope.ingest.tshark import KE_METHOD
    from tunnelscope.pq.cbom import _ALGO
    classical = [n for i, n in KE_METHOD.items() if i and not n.startswith("ML-KEM")]
    assert [n for n in classical if _ALGO.get(n, (None, None))[:2] != ("key-agree", True)] == []


def test_live_monitor_survives_a_file_removed_during_listing(tmp_path, monkeypatch):
    from pathlib import Path
    from tunnelscope.live.live import LiveMonitor
    for n in ("a.pcap", "b.pcap", "c.pcap"):
        (tmp_path / n).write_bytes(b"x")
    mon = LiveMonitor(follow=str(tmp_path), window=5)
    real = Path.stat

    def stat(self, *a, **k):
        if self.name == "b.pcap":
            raise FileNotFoundError(self)
        return real(self, *a, **k)
    monkeypatch.setattr(Path, "stat", stat)
    assert "b.pcap" not in [p.name for p in mon.ready_files()]


def _answered(mixed_checked):
    alt = [{"class": c, "label": c, "probability": pr} for c, pr in (("web", 0.9), ("bulk", 0.06), ("voip", 0.04))]
    return {"status": "measured", "windows": 4, "consistency": 1.0, "level": "high", "score": 90, "confidence": 0.9,
            "note": "n", "traffic": {"answered": True, "class": "bulk", "label": "File transfer", "probability": 0.9,
                                     "alternatives": alt, "mixed": False, "mixed_checked": mixed_checked}}


@pytest.mark.parametrize("ran", [True, False])
def test_mixed_check_is_only_claimed_when_it_ran(monkeypatch, ran):
    """With too few in-distribution windows is_mixed() returns None; the note must then not say the check ran."""
    from tunnelscope.leakage import attacker
    monkeypatch.setattr(attacker, "assess_exposure", lambda esp, src=None: _answered(ran))
    rec = EvidenceRecord(src="203.0.113.1", dst="203.0.113.2", source_pcap=CLASSICAL)
    rec._esp = _esp()
    attacker.extract_attacker(rec)
    note = rec.findings["traffic_type"].note
    assert ("found one kind of traffic" in note) is ran
    assert ("could not run" in note) is (not ran)


def test_assess_exposure_says_whether_the_mixed_check_ran(monkeypatch):
    import numpy as np
    from tunnelscope.leakage import attacker, mixed
    monkeypatch.setattr(mixed, "is_mixed", lambda P: None)
    monkeypatch.setattr(attacker, "window_features_v2", lambda pk: np.load(attacker.DATA)["X"][:6].tolist())
    res = attacker.assess_exposure(_esp(), "203.0.113.1")
    assert res["status"] == "measured" and res["traffic"]["mixed_checked"] is False
