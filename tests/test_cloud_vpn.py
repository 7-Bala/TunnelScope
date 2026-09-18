"""EXP-13 — cloud-VPN-style proposal sets (mentor follow-up C1).

Real captures from testbed/captures/cloud/: strongSwan configured with the AWS
Site-to-Site VPN default proposal set as the "cloud" peer. Each test here locks
in a defect the experiment found (see experiments/exp13-cloud-vpn-proposals/).
"""
import os
import shutil

import pytest

from tunnelscope.assess.engine import _assert, assess_record, load_baselines
from tunnelscope.evidence.record import EvidenceRecord, Finding, Status, Vantage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLOUD = os.path.join(ROOT, "testbed", "captures", "cloud")
needs_tshark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")
DISCOURAGED = [1, 2, 5, 22, 23, 24]


def _verdicts(arm):
    from tunnelscope.evidence.extract import build_records
    (r,) = [r for r in build_records(os.path.join(CLOUD, f"{arm}.pcap")) if getattr(r, "_ike", [])]
    return r, {v.rule_id: v.verdict for v in assess_record(r, load_baselines())}


# --- engine: DH groups judged by IANA identity, never by an unknown name ---

def test_strong_groups_the_old_table_did_not_name_pass_disa():
    """MODP-6144/8192 (17, 18) were unnamed and scored -1 = FAIL."""
    assert _assert("dh_group_ge", 16, "MODP-6144") is True
    assert _assert("dh_group_ge", 16, "MODP-8192") is True


def test_rfc8247_uses_the_rfcs_status_table_not_group_numbers():
    """Group 22 is numerically >= 14 but RFC 8247 says MUST NOT."""
    assert _assert("dh_group_not_in", DISCOURAGED, "MODP-1024-S160") is False
    assert _assert("dh_group_not_in", DISCOURAGED, "MODP-2048-S256") is False
    assert _assert("dh_group_not_in", DISCOURAGED, "ECP-384") is True


def test_an_unrecognised_group_is_unknown_not_fail():
    r = EvidenceRecord(src="a", dst="b", source_pcap="unit")
    r.add(Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "unit", value="some-new-group"))
    v = {x.rule_id: x.verdict for x in assess_record(r, load_baselines())}
    assert v["V-207193"] == "UNKNOWN" and v["RFC8247-DH-MUST"] == "UNKNOWN"


def test_offer_with_any_discouraged_group_fails_and_unknown_members_do_not_pass():
    assert _assert("dh_groups_none_in", DISCOURAGED, ["MODP-2048", "MODP-1024-S160"]) is False
    assert _assert("dh_groups_none_in", DISCOURAGED, ["MODP-2048", "ECP-384"]) is True
    assert _assert("dh_groups_none_in", DISCOURAGED, ["MODP-2048", "dh-99x"]) is None


# --- captures ---

@needs_tshark
def test_suite_survives_an_invalid_ke_retry():
    """A-START: the cloud's first KE guess (group 2) was refused with
    INVALID_KE_PAYLOAD; the suite is in the SECOND response. Taking the first
    (error-only) response reported 'no suite selected'."""
    r, v = _verdicts("a-start")
    assert r.findings["ike_dh_group"].value == "MODP-2048"
    assert r.findings["ike_encr"].value == "AES-CBC-256"
    assert v["RFC8247-DH-MUST"] == "PASS"


@needs_tshark
def test_cloud_offer_exposes_groups_rfc8247_forbids():
    """P5: the tunnel negotiated MODP-2048, but the cloud endpoint offered its
    whole default set, including group 22 (MUST NOT) and group 2."""
    r, v = _verdicts("a-start")
    offered = r.findings["ike_offered_dh"].value
    assert "MODP-1024-S160" in offered and "MODP-1024" in offered and "MODP-2048" in offered
    assert v["RFC8247-DH-OFFER"] == "FAIL"


@needs_tshark
def test_legacy_customer_fails_for_the_right_reason():
    r, v = _verdicts("c-w")
    assert r.findings["ike_dh_group"].value == "MODP-1024"   # was "dh-2"
    assert v["RFC8247-DH-MUST"] == "FAIL" and v["V-207193"] == "FAIL" and v["V-207223"] == "FAIL"


@needs_tshark
def test_aead_suite_integrity_is_explained_not_misreported():
    r, v = _verdicts("c-s")
    f = r.findings["ike_integ"]
    assert f.status == Status.UNKNOWN and "AEAD" in f.note and "no IKE SA suite selected" not in f.note
    assert r.findings["ike_prf"].value == "PRF-HMAC-SHA2-384"
    assert v["V-207223"] == "UNKNOWN" and v["V-207193"] == "PASS"


@needs_tshark
def test_ikev1_fails_disa_and_is_never_passed():
    r, v = _verdicts("c-v1")
    assert r.findings["ike_version"].value == "IKEv1"
    assert v["V-207205"] == "FAIL"
    assert "PASS" not in {v["V-207193"], v["V-207223"], v["RFC8247-DH-MUST"]}
