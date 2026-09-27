"""T-139 / EXP-32 H5-H6: the site sensor sends findings only (strict allow-list), signed; the collector rejects
changed, foreign and replayed reports, counts missing ones, forwards alerts with the site, and shows a silent site
as stale with posture UNKNOWN. Real lab captures of one tunnel, replayed as live windows."""
import json
import os
import shutil
import time
from pathlib import Path

import pytest

from tunnelscope.sensor import report as R
from tunnelscope.sensor.collector import STALE_WINDOWS, Collector, sites_status
from tunnelscope.sensor.sensor import Sensor

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
SEQUENCE = ["pq-mlkem768.pcap", "pq-mlkem768.pcap", "pq-downgrade.pcap"]     # learn, learn, PQ downgrade


def _site(tmp_path, names=SEQUENCE, site="lab1"):
    follow, keys = tmp_path / "follow", tmp_path / "keys"
    follow.mkdir()
    R.write_key(keys / f"{site}.key")
    old = time.time() - 3600
    for i, n in enumerate(names):                    # closed, old files: all ready, in this order
        dst = follow / f"w-{i:03d}.pcap"
        shutil.copy(CAP / n, dst)
        os.utime(dst, (old + i, old + i))
    s = Sensor(site, str(keys / f"{site}.key"), str(tmp_path / "inbox"), str(tmp_path / "sstate"), window=5,
               follow=str(follow))
    c = Collector(str(tmp_path / "inbox"), str(tmp_path / "cstate"), str(keys), alerts=str(tmp_path / "alerts.jsonl"))
    return s, c


def test_reports_carry_findings_only_and_the_downgrade_reaches_the_centre(tmp_path):
    s, c = _site(tmp_path)
    files = s.tick()
    assert [p.name for p in files] == ["lab1-0000000001.json", "lab1-0000000002.json", "lab1-0000000003.json"]
    for p in files:
        raw = p.read_bytes()
        assert b"\xd4\xc3\xb2\xa1" not in raw and b"\xa1\xb2\xc3\xd4" not in raw   # no pcap bytes
        rep = json.loads(raw)
        R.validate(rep)                                                # strict allow-list
        assert set(rep["tunnels"][0]) <= R.TUNNEL_KEYS
        assert "verdicts" not in rep["tunnels"][0] and "explanation" not in rep["tunnels"][0]
    res = c.process_once()
    assert [r["accepted"] for r in res] == [True, True, True]
    alerts = [json.loads(line) for line in (tmp_path / "alerts.jsonl").read_text().splitlines()]
    assert {(a["kind"], a["attribute"]) for a in alerts} >= {("downgrade", "pq")}
    assert all(a["site"] == "lab1" for a in alerts)
    assert not list((tmp_path / "follow").iterdir())                   # captures deleted after analysis


def test_a_changed_byte_a_foreign_site_and_a_replay_are_rejected(tmp_path):
    s, c = _site(tmp_path, names=["pq-mlkem768.pcap"])
    p = s.tick()[0]
    good = p.read_text()
    p.write_text(good.replace('"posture": "post-quantum', '"posture": "Post-quantum'))
    assert c.process_once()[0]["reason"].startswith("signature does not match")
    p.write_text(good)
    assert c.process_once()[0]["accepted"] is True
    p.write_text(good)                                                 # the same report again
    assert "replayed" in c.process_once()[0]["reason"]
    rep = json.loads(good)
    rep["site"] = "elsewhere"
    p.write_text(json.dumps(rep))
    assert "unknown site" in c.process_once()[0]["reason"]
    assert len(list((tmp_path / "cstate" / "quarantine").glob("*.reason"))) >= 1


def test_the_allow_list_refuses_extra_fields_and_long_strings():
    rep = R.build_report("lab1", 1, 30, None, "t")
    with pytest.raises(R.ReportError, match="not allowed"):
        R.validate({**rep, "pcap": "AAAA"}, signed=False)
    t = {"src": "a", "dst": "b", "ike_spi": None, "posture": "x" * (R.MAX_STRING + 1), "fails": [], "verdict_counts": {},
         "gaps": [], "findings": [], "anomaly": None, "risk": {}}
    with pytest.raises(R.ReportError, match="longer than"):
        R.validate({**rep, "tunnels": [t]}, signed=False)
    with pytest.raises(R.ReportError, match="not allowed"):
        R.validate({**rep, "tunnels": [{**t, "posture": "ok", "payload": "x"}]}, signed=False)


def test_silence_is_a_heartbeat_and_the_sequence_survives_a_restart(tmp_path):
    s, c = _site(tmp_path, names=[])
    s.last_emit = time.time() - s.window
    hb = s.tick()
    assert len(hb) == 1 and json.loads(hb[0].read_text())["kind"] == "heartbeat"
    again = Sensor("lab1", str(tmp_path / "keys" / "lab1.key"), str(tmp_path / "inbox"), str(tmp_path / "sstate"),
                   window=5, follow=str(tmp_path / "follow"))
    again.last_emit = time.time() - again.window
    assert json.loads(again.tick()[0].read_text())["seq"] == 2          # never reuses 1


def test_a_missing_report_is_counted_and_a_silent_site_is_unknown(tmp_path):
    s, c = _site(tmp_path, names=["pq-mlkem768.pcap", "pq-mlkem768.pcap"])
    first, second = s.tick()
    first.unlink()                                                     # lost in transfer
    c.process_once(now=1000.0)
    st = sites_status(str(tmp_path / "cstate"), now=1001.0)[0]
    assert st["status"] == "reporting" and st["missing_reports"] == 1 and st["tunnels"]
    late = sites_status(str(tmp_path / "cstate"), now=1000.0 + STALE_WINDOWS * 5 + 1)[0]
    assert late["status"] == "stale" and late["tunnels"] == [] and "UNKNOWN" in late["note"]


def test_api_sites_is_off_without_a_collector_and_shows_stale_sites(tmp_path, monkeypatch):
    import threading
    import urllib.request
    from tunnelscope.api import server
    s, c = _site(tmp_path, names=["pq-mlkem768.pcap"])
    s.tick()
    c.process_once(now=time.time() - 3600)                             # reported an hour ago, 5 s windows
    srv = server.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/api/sites"
    try:
        monkeypatch.delenv("TUNNELSCOPE_COLLECTOR_STATE", raising=False)
        assert json.load(urllib.request.urlopen(url)) == {"ok": True, "enabled": False}
        monkeypatch.setenv("TUNNELSCOPE_COLLECTOR_STATE", str(tmp_path / "cstate"))
        site = json.load(urllib.request.urlopen(url))["sites"][0]
        assert site["site"] == "lab1" and site["status"] == "stale" and site["tunnels"] == []
    finally:
        srv.shutdown()


def test_a_quiet_window_keeps_the_last_handshake_and_the_alert_visible(tmp_path):
    """Found in the end-to-end run: after a downgrade the next windows hold only ESP (posture unknown), and the
    Sites view lost the downgrade. The last observed handshake and recent alerts are kept, with their times."""
    import subprocess
    from tunnelscope.ingest.tshark import tshark_bin
    esp = tmp_path / "esp-only.pcap"                                   # the same tunnel, no handshake: a quiet window
    subprocess.run([tshark_bin(), "-r", str(CAP / "pq-downgrade.pcap"), "-Y", "esp", "-w", str(esp)], check=True,
                   capture_output=True)
    s, c = _site(tmp_path, names=SEQUENCE + [str(esp)])
    assert len(s.tick()) == 4
    c.process_once(now=2000.0)
    st = sites_status(str(tmp_path / "cstate"), now=2001.0)[0]
    assert st["recent_alerts"] and st["recent_alerts"][0]["attribute"] in ("pq", "fails")
    assert any(a["kind"] == "downgrade" and a["attribute"] == "pq" for a in st["recent_alerts"])
    rep = json.loads((tmp_path / "cstate" / "sites" / "lab1.json").read_text())
    assert rep["tunnels"][0]["posture"].startswith("unknown")          # now: the quiet window says unknown
    hs = rep["last_handshake"]["10.10.1.20 <-> 10.10.2.20"]
    assert hs["posture"].startswith("DOWNGRADED")                     # the last handshake seen, with its time
    assert st["tunnels"][0]["last_handshake"]["posture"].startswith("DOWNGRADED")
