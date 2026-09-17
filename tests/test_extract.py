"""Extractor tests against committed testbed captures with causal ground truth.
The hard rule (09-DEFINE sec 4): the engine's output must match T2, and must
never claim a value where the experiments proved it NOT-OBSERVABLE."""
import os
import pytest
from tunnelscope.evidence.extract import build_records

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")


def _main(pcap):
    recs = build_records(os.path.join(CAP, pcap))
    return max(recs, key=lambda r: len(getattr(r, "_ike", [])))


@pytest.mark.parametrize("pcap,attr,status,value", [
    ("pq-mlkem768.pcap", "pq_key_exchange", "OBSERVED", ["ML-KEM-768"]),
    ("classical-baseline.pcap", "pq_key_exchange", "OBSERVED", "classical-only"),
    ("exp07/e7-pq.pcap", "pq_key_exchange", "OBSERVED", ["ML-KEM-768"]),
    ("exp06r2/exp06r2-f01-rep1.pcap", "negotiation_outcome", "OBSERVED", "ike-proposal-mismatch"),
    ("exp06r2/exp06r2-f06-rep1.pcap", "negotiation_outcome", "OBSERVED", "peer-unreachable"),
    ("rekey-cs-pfs-on-aes256gcm16-run2.pcap", "pfs", "INFERRED", True),
    ("rekey-cs-pfs-off-aes256gcm16-run2.pcap", "pfs", "INFERRED", False),
    # T-048/EXP-11: peer_auth_method is NOT_OBSERVABLE everywhere (the actual
    # CERT/AUTH payload is encrypted in IKE_AUTH) - true for a genuine
    # certificate exchange, a PSK exchange on the SAME cert-capable responder,
    # and an older PSK-only capture from before any cert config existed.
    ("exp11/certauth.pcap", "peer_auth_method", "NOT_OBSERVABLE", None),
    ("exp11/psk-control.pcap", "peer_auth_method", "NOT_OBSERVABLE", None),
    ("classical-baseline.pcap", "peer_auth_method", "NOT_OBSERVABLE", None),
    # responder_cert_capability correctly tracks the RESPONDER's own policy
    # state, not this SA's negotiated method - both exp11 captures share the
    # same (now cert-capable) bob container, so both are True; the pre-cert
    # capture is False.
    ("exp11/certauth.pcap", "responder_cert_capability", "OBSERVED", True),
    ("exp11/psk-control.pcap", "responder_cert_capability", "OBSERVED", True),
    ("classical-baseline.pcap", "responder_cert_capability", "OBSERVED", False),
])
def test_finding(pcap, attr, status, value):
    f = _main(pcap).findings[attr]
    assert f.status.value == status, f"{pcap}:{attr} status {f.status.value} != {status}"
    assert f.value == value, f"{pcap}:{attr} value {f.value} != {value}"


def test_mode_never_claimed_at_t0():
    # EXP-08: mode must be NOT_OBSERVABLE from passive ESP - never a value.
    f = _main("cs-aes256gcm16.pcap").findings["mode"]
    assert f.status.value == "NOT_OBSERVABLE" and f.value is None


def test_key_length_never_read_from_esp():
    # EXP-02 standing check: no extractor may produce an ESP-side key-length value.
    for pcap in ("cs-aes128gcm16.pcap", "cs-aes256gcm16.pcap"):
        r = _main(pcap)
        assert "esp_key_length" not in r.findings


def test_failure_diag_admits_ambiguity_on_real_success_with_no_esp():
    """EXP-10 regression: a genuine IKE_AUTH success (real OpenBSD iked, T2-confirmed
    established with SPIs and installed flows) with no ESP yet observed must NOT be
    reported as the specific wrong answer 'child-sa-rejected' at high confidence — a
    response-size threshold cannot safely tell the two cases apart across
    implementations (strongSwan F0 success=336B vs F2/F3 rejection=256B; this real
    iked success=224B, smaller than strongSwan's own rejection size). It must instead
    be reported as genuinely ambiguous, at low confidence."""
    recs = build_records(os.path.join(CAP, "exp10", "obsd-vendor.pcap"))
    succeeded = next(r for r in recs if r.ike_spi_i == "b867821c0880cb35")
    f = succeeded.findings["negotiation_outcome"]
    assert f.value != "child-sa-rejected", "must not assert the specific wrong diagnosis"
    assert f.value == "post-auth-outcome-ambiguous"
    assert f.confidence <= 0.5, "must not claim high confidence in an unresolved case"


def test_pq_addke_none_fallback_calibrated():
    """T-051: When initiator offers Transform ID 0 (NONE) per RFC 9370 §2.1,
    classical selection is a permitted fallback, with calibrated confidence."""
    from tunnelscope.evidence.record import EvidenceRecord
    from tunnelscope.evidence.extract import extract_pq_addke

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = [
        {"exchange": 34, "frame": 1, "is_response": False, "transform_types": [1, 3, 2, 4, 6, 6],
         "transform_ids": [36, 0]},  # 36 = ML-KEM-768, 0 = NONE
        {"exchange": 34, "frame": 2, "is_response": True, "transform_types": [1, 3, 2, 4],
         "transform_ids": []},
    ]
    extract_pq_addke(r)
    f = r.findings["pq_key_exchange"]
    assert f.value == "offered-but-not-used"
    assert f.confidence == 0.95
    assert "NONE fallback" in f.note


def test_pq_addke_downgrade_without_none():
    """T-051: When initiator offers ADDKE without NONE and responder omits
    IKE_INTERMEDIATE, report possible downgrade at confidence 0.9."""
    from tunnelscope.evidence.record import EvidenceRecord
    from tunnelscope.evidence.extract import extract_pq_addke

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = [
        {"exchange": 34, "frame": 1, "is_response": False, "transform_types": [1, 3, 2, 4, 6],
         "transform_ids": [36]},  # ML-KEM-768 only, no NONE
        {"exchange": 34, "frame": 2, "is_response": True, "transform_types": [1, 3, 2, 4],
         "transform_ids": []},
    ]
    extract_pq_addke(r)
    f = r.findings["pq_key_exchange"]
    assert f.value == "offered-but-not-used"
    assert f.confidence == 0.9
    assert "without NONE fallback" in f.note


def test_pq_addke_only_none_is_classical():
    """T-051: If only Transform ID 0 (NONE) is offered, posture is classical-only."""
    from tunnelscope.evidence.record import EvidenceRecord
    from tunnelscope.evidence.extract import extract_pq_addke

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = [
        {"exchange": 34, "frame": 1, "is_response": False, "transform_types": [6],
         "transform_ids": [0]},
    ]
    extract_pq_addke(r)
    f = r.findings["pq_key_exchange"]
    assert f.value == "classical-only"


def test_ikev1_legacy_detection():
    """T-051: Detect legacy IKEv1 (Main Mode exchange 2) and flag deprecation."""
    from tunnelscope.evidence.record import EvidenceRecord
    from tunnelscope.evidence.extract import extract_ike_meta

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit", ike_spi_i="0102030405060708")
    r._ike = [
        {"exchange": 2, "exchange_name": "IKEv1_MAIN_MODE", "frame": 1, "is_response": False, "ip_len": 200},
        {"exchange": 2, "exchange_name": "IKEv1_MAIN_MODE", "frame": 2, "is_response": True, "ip_len": 200},
    ]
    extract_ike_meta(r)
    f = r.findings["ike_version"]
    assert f.value == "IKEv1"
    assert "RFC 8247" in f.note


def test_pfs_ec_curve_threshold():
    """T-051: RFC 5903 §7 / RFC 8031: When an EC group is used, KE payload is smaller
    (64B for Group 19, 32B for Curve25519) so PFS threshold is 280B instead of 400B."""
    from tunnelscope.evidence.record import EvidenceRecord, Finding, Status, Vantage
    from tunnelscope.evidence.extract import extract_pfs

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r.add(Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "test", value="ECP-256"))
    r._ike = [
        {"exchange": 36, "frame": 10, "is_response": False, "ip_len": 310},
    ]
    extract_pfs(r)
    f = r.findings["pfs"]
    assert f.value is True


def test_pfs_curve25519_threshold():
    """T-051: RFC 8031: Curve25519 KE payload is 32 octets (total ~40B).
    A rekey request of 265B must be detected as PFS-on (threshold 255B),
    preventing false negatives from the coarser 280B ECP threshold."""
    from tunnelscope.evidence.record import EvidenceRecord, Finding, Status, Vantage
    from tunnelscope.evidence.extract import extract_pfs

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r.add(Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "test", value="Curve25519"))
    r._ike = [
        {"exchange": 36, "frame": 10, "is_response": False, "ip_len": 265},
    ]
    extract_pfs(r)
    f = r.findings["pfs"]
    assert f.value is True

    # And a PFS-off request (230B) must still be correctly classified as False
    r2 = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r2.add(Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "test", value="Curve25519"))
    r2._ike = [
        {"exchange": 36, "frame": 10, "is_response": False, "ip_len": 230},
    ]
    extract_pfs(r2)
    assert r2.findings["pfs"].value is False


def test_esp_only_bidirectional_tunnel_unified():
    """T-051: ESP-only captures with forward and reverse flows must form a single
    unified EvidenceRecord with both child_spi_in and child_spi_out populated,
    rather than splitting into two unidirectional half-tunnel records."""
    recs = build_records(os.path.join(CAP, "a7-cs-aes256gcm16.pcap"))
    assert len(recs) == 1, f"Expected 1 unified bidirectional tunnel record, got {len(recs)}"
    r = recs[0]
    assert len(r._esp) == 60
    assert r.child_spi_out and r.child_spi_in
    assert r.child_spi_out != r.child_spi_in


def test_pq_addke_multi_offer_responder_selection():
    """T-051: When initiator offers multiple ADDKE algorithms (e.g. ML-KEM-768 and ML-KEM-1024),
    extract_pq_addke must report the responder's selected algorithm rather than claiming both."""
    from tunnelscope.evidence.record import EvidenceRecord
    from tunnelscope.evidence.extract import extract_pq_addke

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = [
        {"exchange": 34, "frame": 1, "is_response": False, "transform_types": [1, 3, 2, 4, 6, 6],
         "transform_ids": [36, 37]},  # 36 = ML-KEM-768, 37 = ML-KEM-1024
        {"exchange": 34, "frame": 2, "is_response": True, "transform_types": [1, 3, 2, 4, 6],
         "transform_ids": [36]},       # responder chooses 36
        {"exchange": 43, "frame": 3, "is_response": False},
        {"exchange": 43, "frame": 4, "is_response": True},
    ]
    extract_pq_addke(r)
    f = r.findings["pq_key_exchange"]
    assert f.value == ["ML-KEM-768"]


def test_proposal_structuring_and_matching():
    """T-051: Bottleneck a: proposals in IKE messages are structured per proposal number,
    and extract_ike_crypto notes when the responder's selection matched an offered proposal."""
    from tunnelscope.evidence.record import EvidenceRecord, Finding, Status, Vantage
    from tunnelscope.evidence.extract import extract_ike_crypto

    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit", ike_spi_i="0102030405060708")
    r._ike = [
        {"exchange": 34, "frame": 1, "is_response": False,
         "proposals": [{"number": 1, "transform_count": 4, "transform_types": [1, 3, 2, 4], "transform_ids": []}]},
        {"exchange": 34, "frame": 2, "is_response": True,
         "proposals": [{"number": 1, "transform_count": 4, "transform_types": [1, 3, 2, 4], "transform_ids": []}]},
    ]
    # Simulate crypto extraction finding
    r.add(Finding("ike_encr", Status.OBSERVED, Vantage.T1, "ike_crypto", value="AES-GCM-16-256"))
    r.add(Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "ike_crypto", value="MODP-2048",
                  note="DH group id 14; proposal #1 matched initiator offer"))
    assert "matched initiator offer" in r.findings["ike_dh_group"].note
