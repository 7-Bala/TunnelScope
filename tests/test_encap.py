"""T-057 — ESP length offsets for UDP-encapsulated ESP and IPv6 (plan ING-6).

Four real captures from testbed/docker-compose.encap.yml (strongSwan 5.9.8,
keyless router vantage): UDP-encapsulated ESP (RFC 3948) and native ESP over
IPv6, each with a CBC and a GCM tunnel. Ground truth is the endpoint's own
`swanctl --list-sas` (T2) in the matching groundtruth.json, never the analyzer.

Before T-057 every ESP packet was sized as ip.len - 20 - 8: on the UDP-encap
CBC tunnel that eliminated CBC (the true suite), and on IPv6 the records had
no addresses and no lengths at all.
"""
import json
import os
import re
import shutil
import subprocess

import pytest

from tunnelscope.ingest import tshark

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENC = os.path.join(ROOT, "testbed", "captures", "encap")
ARMS = ["encap-udp-aes256gcm16", "encap-udp-aes128cbc-sha256",
        "ipv6-aes256gcm16", "ipv6-aes128cbc-sha256"]

needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")


def _gt(arm):
    """(ESP suite, TUNNEL-in-UDP?) for this arm from alice's swanctl output."""
    text = json.load(open(os.path.join(ENC, f"{arm}.groundtruth.json")))["alice_list_sas"]
    m = re.search(rf"^  {re.escape(arm)}: #\d+, reqid \d+, INSTALLED, (\S+), ESP:(\S+)$", text, re.M)
    assert m, f"no installed child SA for {arm} in ground truth"
    return m.group(2), m.group(1) == "TUNNEL-in-UDP"


def _independent_content(pcap):
    """ESP content length computed straight from the outer header fields."""
    out = subprocess.run(["tshark", "-r", pcap, "-Y", "esp", "-T", "fields",
                          "-e", "udp.length", "-e", "ipv6.plen"],
                         capture_output=True, text=True, check=True).stdout
    lens = []
    for line in out.splitlines():
        udp, plen = (line.split("\t") + [""])[:2]
        lens.append(int(udp) - 16 if udp else int(plen) - 8)
    return lens


@needs_tshark
@pytest.mark.parametrize("arm", ARMS)
def test_esp_content_offsets(arm):
    pcap = os.path.join(ENC, f"{arm}.pcap")
    _, in_udp = _gt(arm)
    pkts = tshark.esp_packets(pcap)
    assert pkts and all(p["esp_content_known"] for p in pkts)
    assert [p["esp_content"] for p in pkts] == _independent_content(pcap)
    assert all(p["encap"] == ("udp" if in_udp else "native") for p in pkts)
    assert all(p["src"] and p["dst"] for p in pkts)


@needs_tshark
@pytest.mark.parametrize("arm", ARMS)
def test_cipher_sieve_never_eliminates_the_true_suite(arm):
    from tunnelscope.evidence.extract import build_records
    suite, _ = _gt(arm)
    recs = build_records(os.path.join(ENC, f"{arm}.pcap"))
    assert len(recs) == 1
    r = recs[0]
    fam = r.findings["esp_cipher_family"].value
    if suite.startswith("AES_CBC"):
        assert "AES-CBC+HMAC-SHA256-128" in fam
    else:   # AES_GCM_16: AEAD, so the CBC families must be excluded
        assert "AES-GCM-16" in fam and not any("CBC" in f for f in fam)
    assert r.findings["negotiation_outcome"].value == "success"
    assert r.findings["ike_dh_group"].value == "MODP-2048"
    if arm.startswith("ipv6"):
        assert r.src == "fd00:20:1::10" and r.dst == "fd00:20:2::10"


def test_ipv6_extension_header_length_is_unknown(monkeypatch):
    """An IPv6 packet whose first next-header is not ESP (extension headers
    in between) has no reliable offset: the length must be marked unknown and
    kept out of the sieve, not guessed."""
    row = ["1", "0.1", "", "", "", "", "fd00::1", "fd00::2", "120", "0,50", "", "0x1", "1"]
    monkeypatch.setattr(tshark, "_run_fields", lambda *a, **k: [row])
    (p,) = tshark.esp_packets("unused.pcap")
    assert p["esp_content_known"] is False and p["esp_content"] == 0
    assert p["src"] == "fd00::1" and p["ip_version"] == 6


def test_ipv4_options_use_header_length(monkeypatch):
    """IPv4 with options: the IHL, not a fixed 20 B, sets the offset."""
    row = ["1", "0.1", "10.0.0.1", "10.0.0.2", "124", "24", "", "", "", "", "", "0x1", "1"]
    monkeypatch.setattr(tshark, "_run_fields", lambda *a, **k: [row])
    (p,) = tshark.esp_packets("unused.pcap")
    assert p["esp_content"] == 124 - 24 - 8
