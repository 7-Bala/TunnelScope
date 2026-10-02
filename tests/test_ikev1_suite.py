"""IKEv1 phase-1 suite (EXP-40): the responder's SA payload names the transform it selected, in the clear.

Fixtures are our own Libreswan 5.4 <-> Libreswan 5.4 captures (testbed/captures/exp40) whose expected suite comes from
pluto's own "ISAKMP SA established" log line, not from our reader.
"""
import json
import re
import struct
from pathlib import Path

import pytest

from tunnelscope.assess.engine import assess_record, load_baselines
from tunnelscope.evidence.extract import build_records
from tunnelscope.ingest import tshark

CAPS = Path(__file__).resolve().parent.parent / "testbed" / "captures" / "exp40"
IKEV2 = Path(__file__).resolve().parent.parent / "testbed" / "captures" / "classical-baseline-6.1.0.pcap"
CIPHER = {"AES_CBC_128": "AES-CBC-128", "AES_CBC_256": "AES-CBC-256", "3DES_CBC_192": "3DES"}
HASH = {"HMAC_SHA1": "PRF-HMAC-SHA1", "HMAC_SHA2_256": "PRF-HMAC-SHA2-256", "HMAC_SHA2_384": "PRF-HMAC-SHA2-384"}
GROUP = {"MODP1536": "MODP-1536", "MODP2048": "MODP-2048", "MODP3072": "MODP-3072", "DH19": "ECP-256"}
ARMS = ["e40-m-aes256-sha256-g14", "e40-m-aes128-sha1-g5", "e40-m-3des-sha1-g5", "e40-m-aes256-sha384-g15",
        "e40-m-aes128-sha256-g19", "e40-a-aes256-sha256-g14", "e40-a-aes128-sha1-g5", "e40-m-multi"]


@pytest.fixture(autouse=True)
def _fresh():
    tshark.clear_cache()
    yield
    tshark.clear_cache()


def _truth(arm):
    for line in json.loads((CAPS / f"{arm}.groundtruth.json").read_text())["pluto_log_T2"]:
        m = re.search(r'ISAKMP SA established \{auth=\S+ cipher=(\S+) integ=(\S+) group=(\S+)\}', line)
        if m and f'"{arm}"' in line:
            return {"ike_encr": CIPHER[m[1]], "ike_prf": HASH[m[2]], "ike_dh_group": GROUP[m[3]]}
    raise AssertionError(f"no established line for {arm}")


def _rec(path):
    recs = [r for r in build_records(str(path)) if getattr(r, "_ike", [])]
    assert recs
    return recs[0]


@pytest.mark.parametrize("arm", ARMS)
def test_each_arm_reports_exactly_what_pluto_negotiated(arm):
    f = _rec(CAPS / f"{arm}.pcap").findings
    for k, want in _truth(arm).items():
        assert f[k].status.value == "OBSERVED" and f[k].value == want, (arm, k, f[k].value, want)


def test_the_selection_is_read_not_the_first_offer():
    """The responder accepts only the second of the initiator's two offers; the first is AES-256/SHA2-256/MODP-2048."""
    f = _rec(CAPS / "e40-m-multi.pcap").findings
    assert (f["ike_encr"].value, f["ike_prf"].value, f["ike_dh_group"].value) == ("AES-CBC-128", "PRF-HMAC-SHA1", "MODP-1536")


def test_the_key_length_is_part_of_the_cipher_name():
    assert _rec(CAPS / "e40-m-aes256-sha256-g14.pcap").findings["ike_encr"].value == "AES-CBC-256"
    assert _rec(CAPS / "e40-m-aes128-sha1-g5.pcap").findings["ike_encr"].value == "AES-CBC-128"
    assert _rec(CAPS / "e40-m-3des-sha1-g5.pcap").findings["ike_encr"].value == "3DES"


def _cut_before_responder(src, dst):
    rows = tshark._run_fields(str(src), "ip", ["ip.src"])
    first = rows[0][0]
    n = next(i for i, r in enumerate(rows) if r[0] != first)
    raw = Path(src).read_bytes()
    pos = 24
    for _ in range(n):
        pos += 16 + struct.unpack("<I", raw[pos + 8:pos + 12])[0]
    Path(dst).write_bytes(raw[:pos])
    tshark.clear_cache()


@pytest.mark.parametrize("arm", ["e40-m-multi", "e40-m-aes256-sha256-g14", "e40-a-aes128-sha1-g5"])
def test_with_only_the_initiators_offer_nothing_is_asserted(arm, tmp_path):
    cut = tmp_path / "offer_only.pcap"
    _cut_before_responder(CAPS / f"{arm}.pcap", cut)
    f = _rec(cut).findings
    for k in ("ike_encr", "ike_prf", "ike_dh_group"):
        assert f[k].status.value == "UNKNOWN" and f[k].value is None, (k, f[k].value)
        assert "offer is not used" in f[k].note


def test_ike_integ_stays_unknown_for_ikev1_and_says_why():
    f = _rec(CAPS / "e40-m-aes256-sha256-g14.pcap").findings["ike_integ"]
    assert f.status.value == "UNKNOWN" and "no separate integrity transform" in f.note


def _verdicts(path):
    return assess_record(_rec(path), load_baselines())


def test_rfc8247_gives_no_verdict_on_an_ikev1_session_but_disa_still_judges_it():
    v = {x.rule_id: x.verdict for x in _verdicts(CAPS / "e40-m-3des-sha1-g5.pcap")}
    assert not [r for r in v if r.startswith("RFC8247-")]
    assert v["V-207193"] == "FAIL" and v["V-207205"] == "FAIL"           # MODP-1536 is below group 16; IKEv1 is not IKEv2
    assert {x.rule_id: x.verdict for x in _verdicts(CAPS / "e40-m-aes128-sha256-g19.pcap")}["V-207193"] == "PASS"


def test_rfc8247_still_judges_ikev2_sessions():
    v = {x.rule_id for x in _verdicts(IKEV2)}
    assert {"RFC8247-DH-MUST", "RFC8247-ENCR"} <= v


def _rows(monkeypatch, tmp_path, rows):
    """Feed the reader crafted tshark rows (frame, ispi, rspi, encr, hash, group, keylen) for a dummy file."""
    p = tmp_path / "x.pcap"
    p.write_bytes(b"")
    monkeypatch.setattr(tshark, "_run_fields", lambda *a, **k: rows)
    tshark.clear_cache()
    return tshark._ike1_responder_sas(str(p))


def test_a_payload_with_several_transforms_is_an_offer_not_a_selection(monkeypatch, tmp_path):
    offer = ["9", "aa", "bb", "7,7", "4,2", "14,5", "256,128"]       # a responder-side packet that lists two transforms
    one = ["10", "aa", "bb", "7", "2", "5", "128"]
    assert _rows(monkeypatch, tmp_path, [offer]) == []
    got = _rows(monkeypatch, tmp_path, [offer, one])
    assert [g["frame"] for g in got] == [10] and got[0]["suite"]["encr"] == "AES-CBC-128"


def test_a_packet_without_an_sa_payload_or_with_a_zero_responder_spi_yields_nothing(monkeypatch, tmp_path):
    no_sa = ["11", "aa", "bb", "", "", "", ""]                         # a later, encrypted Main Mode message
    first = ["1", "aa", "0000000000000000", "7", "4", "14", "256"]     # the initiator's message 1
    assert _rows(monkeypatch, tmp_path, [no_sa, first]) == []
