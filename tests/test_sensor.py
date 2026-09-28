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


def test_headers_only_capture_opens_the_interface_twice_ike_whole_esp_truncated():
    from tunnelscope.live.live import ESP_SNAPLEN, ESP_FILTER, IKE_FILTER, capture_command
    full = capture_command("dumpcap", "eth0", "/w.pcapng", 10, False)
    assert full.count("-i") == 1 and "-s" not in full
    cmd = capture_command("dumpcap", "eth0", "/w.pcapng", 10, True)
    assert cmd.count("-i") == 2
    ike, esp = cmd.index(IKE_FILTER), cmd.index(ESP_FILTER)
    assert cmd[ike + 1:ike + 3] == ["-s", "0"] and cmd[esp + 1:esp + 3] == ["-s", str(ESP_SNAPLEN)]
    assert "udp[8:4] = 0" in IKE_FILTER and "udp[8:4] != 0" in ESP_FILTER    # IKE vs ESP on port 4500


def test_the_sensor_stores_headers_only_by_default(tmp_path):
    """DEC-044 (EXP-33: 0 finding differences over 11 SAs): --interface sensors truncate ESP/AH unless told not to."""
    R.write_key(tmp_path / "k.key")
    (tmp_path / "f").mkdir()
    s = Sensor("lab1", str(tmp_path / "k.key"), str(tmp_path / "o"), str(tmp_path / "s"), follow=str(tmp_path / "f"))
    assert s.monitor.headers_only is True


# ------------------------------------------------------------------ T-142 address masking

IPV4 = __import__("re").compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")


def _masked_site(tmp_path, names=SEQUENCE):
    s, c = _site(tmp_path, names=names)
    s.mask_key = __import__("tunnelscope.sensor.sensor", fromlist=["mask_key"]).mask_key(s.state_dir)
    return s, c


def test_a_masked_report_carries_no_address_and_the_same_findings(tmp_path):
    s, c = _masked_site(tmp_path)
    files = s.tick()
    key = (tmp_path / "sstate" / "mask.key").read_text().strip()
    for p in files:
        raw = p.read_text()
        assert not IPV4.search(raw), IPV4.search(raw).group(0)
        assert key not in raw                                          # the mask key never leaves the site
        rep = json.loads(raw)
        assert rep["addresses"] == "masked"
        t = rep["tunnels"][0]
        assert t["src"] == R.pseudonym(s.mask_key, "10.10.1.20") and t["dst"] == R.pseudonym(s.mask_key, "10.10.2.20")
    alerts = [a for p in files for a in json.loads(p.read_text())["alerts"]]
    assert alerts and all(R.pseudonym(s.mask_key, "10.10.1.20") in a["tunnel"] for a in alerts)
    assert oct((tmp_path / "sstate" / "mask.key").stat().st_mode & 0o777) == "0o600"
    assert [r["accepted"] for r in c.process_once()] == [True, True, True]
    st = sites_status(str(tmp_path / "cstate"))[0]
    assert st["addresses"] == "masked" and not IPV4.search(json.dumps(st))


def test_masking_changes_addresses_only(tmp_path):
    s, _ = _site(tmp_path, names=["pq-downgrade.pcap"])
    row = s.monitor.poll_once()[0]
    key = b"k" * 64
    clear = R.build_report("lab1", 1, 5, row, "t", now=1.0)
    masked = R.build_report("lab1", 1, 5, row, "t", now=1.0, mask_key=key)
    assert R.mask_addresses(clear["tunnels"], key) == masked["tunnels"]
    assert clear["tunnels"][0]["findings"] == masked["tunnels"][0]["findings"]
    assert clear["tunnels"][0]["fails"] == masked["tunnels"][0]["fails"]


def test_pseudonyms_are_stable_across_restarts_and_differ_between_sites(tmp_path):
    from tunnelscope.sensor.sensor import mask_key
    k1, k1_again, k2 = mask_key(tmp_path / "a"), mask_key(tmp_path / "a"), mask_key(tmp_path / "b")
    assert k1 == k1_again and k1 != k2
    assert R.pseudonym(k1, "10.10.1.20") == R.pseudonym(k1_again, "10.10.1.20") != R.pseudonym(k2, "10.10.1.20")
    assert R.pseudonym(k1, "2001:db8::1") == R.pseudonym(k1, "2001:0db8:0:0:0:0:0:1")   # one address, one name


def test_masking_leaves_everything_that_is_not_an_address():
    key = b"k" * 64
    text = ("strongSwan 5.9.8 SPI ca882116 at 2026-09-28T10:00:00 AES-GCM-16 MODP-2048 "
            "10.10.1.20 <-> 2001:db8::7 port 4500")
    out = R.mask_addresses(text, key)
    for kept in ("5.9.8", "ca882116", "2026-09-28T10:00:00", "AES-GCM-16", "MODP-2048", "4500"):
        assert kept in out
    assert "10.10.1.20" not in out and "2001:db8::7" not in out
    assert R.pseudonym(key, "10.10.1.20") in out and R.pseudonym(key, "2001:db8::7") in out


def test_the_sensor_option_creates_the_key_and_sensor_mask_shows_the_pseudonym(tmp_path, capsys):
    from tunnelscope import cli
    R.write_key(tmp_path / "k.key")
    (tmp_path / "f").mkdir()
    s = Sensor("lab1", str(tmp_path / "k.key"), str(tmp_path / "o"), str(tmp_path / "s"), follow=str(tmp_path / "f"),
               mask_addresses=True)
    assert s.mask_key is not None and (tmp_path / "s" / "mask.key").exists()
    assert cli.main(["sensor-mask", "--state", str(tmp_path / "s"), "10.10.1.20"]) == 0
    assert capsys.readouterr().out.strip() == f"10.10.1.20\t{R.pseudonym(s.mask_key, '10.10.1.20')}"
    unmasked = Sensor("lab2", str(tmp_path / "k.key"), str(tmp_path / "o2"), str(tmp_path / "s2"), follow=str(tmp_path / "f"))
    assert unmasked.mask_key is None and not (tmp_path / "s2" / "mask.key").exists()
