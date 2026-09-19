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


def test_mode_never_claimed_without_proof():
    # EXP-08/14: a tunnel capture with no packet below the tunnel-mode size floor
    # gets NO mode value (never "tunnel" from traffic alone); the transport capture
    # of the same traffic is proven transport by its sub-floor packets.
    f = _main("cs-aes256gcm16.pcap").findings["mode"]
    assert f.status.value == "UNKNOWN" and f.value is None
    t = _main("cs-transport-aes256gcm16.pcap").findings["mode"]
    assert t.status.value == "INFERRED" and t.value == "transport" and "size" in t.method


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


# --------------------------------------------------------------------------- #
# T-051/T-053: PQ selection is read from the responder's plaintext proposal.   #
# --------------------------------------------------------------------------- #
def _sa(msgs):
    from tunnelscope.evidence.record import EvidenceRecord
    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = [dict({"exchange": 34, "frame": i + 1, "transform_types": [], "transform_ids": []}, **m)
              for i, m in enumerate(msgs)]
    return r


def _pq(msgs):
    from tunnelscope.evidence.extract import extract_pq_addke
    r = _sa(msgs)
    extract_pq_addke(r)
    return r.findings["pq_key_exchange"]


def test_pq_downgrade_capture_selection_is_observed():
    """pq-downgrade.pcap: the initiator offers ADDKE [ML-KEM-768, NONE]; the responder's
    SA carries no Transform Type 6 at all. That is plaintext, so OBSERVED - not the
    old INFERRED guess from IKE_INTERMEDIATE being absent."""
    f = _main("pq-downgrade.pcap").findings["pq_key_exchange"]
    assert f.status.value == "OBSERVED"
    assert f.value == "offered-but-not-used"
    assert f.confidence == 1.0
    assert "ML-KEM-768" in f.note


def test_pq_two_proposal_offer_classical_selection_is_not_called_a_downgrade():
    """T-052 stress case: proposal 1 = classical + ML-KEM (no NONE), proposal 2 =
    classical only; the responder picks proposal 2. That is legitimate selection."""
    f = _pq([{"is_response": False, "transform_types": [1, 3, 2, 4, 6, 1, 3, 2, 4], "transform_ids": [36]},
             {"is_response": True, "transform_types": [1, 3, 2, 4]}])
    assert f.status.value == "OBSERVED" and f.value == "offered-but-not-used"
    assert "downgrade" not in f.note.lower()


def test_pq_responder_explicitly_selects_none():
    f = _pq([{"is_response": False, "transform_types": [1, 3, 2, 4, 6, 6], "transform_ids": [36, 0]},
             {"is_response": True, "transform_types": [1, 3, 2, 4, 6], "transform_ids": [0]}])
    assert f.status.value == "OBSERVED" and f.value == "offered-but-not-used"


def test_pq_responder_selection_named_from_its_own_proposal():
    """Offer ML-KEM-768 and ML-KEM-1024; the responder picks 768 - report only that."""
    f = _pq([{"is_response": False, "transform_types": [1, 3, 2, 4, 6, 6], "transform_ids": [36, 37]},
             {"is_response": True, "transform_types": [1, 3, 2, 4, 6], "transform_ids": [36]}])
    assert f.status.value == "OBSERVED" and f.value == ["ML-KEM-768"]


def test_pq_error_only_response_is_unknown_not_a_verdict():
    """A NO_PROPOSAL_CHOSEN / INVALID_KE_PAYLOAD response selects nothing: the PQ
    outcome is UNKNOWN, never 'offered-but-not-used'."""
    f = _pq([{"is_response": False, "transform_types": [1, 3, 2, 4, 6], "transform_ids": [36]},
             {"is_response": True, "notify_types": [14]}])
    assert f.status.value == "UNKNOWN" and f.value is None


def test_pq_only_none_offered_is_classical():
    f = _pq([{"is_response": False, "transform_types": [6], "transform_ids": [0]}])
    assert f.status.value == "OBSERVED" and f.value == "classical-only"


# --------------------------------------------------------------------------- #
# PFS: the 400 B rule is only calibrated for MODP groups.                      #
# --------------------------------------------------------------------------- #
def _pfs(group, req_len):
    from tunnelscope.evidence.record import Finding, Status, Vantage
    from tunnelscope.evidence.extract import extract_pfs
    r = _sa([])
    if group:
        r.add(Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "test", value=group))
    r._ike = [{"exchange": 36, "frame": 10, "is_response": False, "ip_len": req_len}]
    extract_pfs(r)
    return r.findings["pfs"]


@pytest.mark.parametrize("group,req_len,value", [
    ("MODP-2048", 508, True),    # measured PFS-on (exp07/e7-pfs-on.pcap)
    ("MODP-2048", 236, False),   # measured PFS-off (exp07/e7-pfs-off.pcap)
])
def test_pfs_modp_rule(group, req_len, value):
    f = _pfs(group, req_len)
    assert f.status.value == "INFERRED" and f.value is value


@pytest.mark.parametrize("group", ["Curve25519", "ECP-256", "ECP-384", "dh-2"])
def test_pfs_uncalibrated_group_is_unknown(group):
    """T-052: no capture calibrates a size gap for these groups (Curve25519 adds ~40 B,
    ECP-256 ~72 B - within one traffic selector's variance). Must not guess."""
    f = _pfs(group, 290)
    assert f.status.value == "UNKNOWN" and f.value is None
    assert "uncalibrated" in f.note


# --------------------------------------------------------------------------- #
# IKEv1, per-SA crypto, ESP attribution - against real captures where we have them. #
# --------------------------------------------------------------------------- #
def test_ikev1_legacy_detection():
    """No IKEv1 capture exists in the testbed yet, so this is header-level only."""
    from tunnelscope.evidence.extract import extract_ike_meta
    r = _sa([{"exchange": 2, "exchange_name": "IKEv1_MAIN_MODE", "is_response": False},
             {"exchange": 2, "exchange_name": "IKEv1_MAIN_MODE", "is_response": True}])
    extract_ike_meta(r)
    f = r.findings["ike_version"]
    assert f.value == "IKEv1" and "RFC 9395" in f.note


def test_ike_crypto_is_per_sa():
    """cs-aes256gcm16-a7.pcap starts with two NO_PROPOSAL_CHOSEN negotiations. Reading
    the pcap's first IKE_SA_INIT response for every SA made all four UNKNOWN; each SA
    must get its own responder's selection."""
    recs = {r.ike_spi_i[:8]: r for r in build_records(os.path.join(CAP, "cs-aes256gcm16-a7.pcap"))}
    assert recs["d262af62"].findings["ike_dh_group"].status.value == "UNKNOWN"
    ok = recs["370f59f1"].findings
    assert ok["ike_dh_group"].status.value == "OBSERVED" and ok["ike_dh_group"].value == "MODP-2048"
    assert ok["ike_encr"].value == "AES-CBC-256"


def test_esp_credited_to_the_sa_that_carried_it():
    """fail-ts-mismatch.pcap: a failed negotiation, then a working one; ESP starts only
    after the second. The failed SA must not be credited with that traffic."""
    recs = {r.ike_spi_i[:8]: r for r in build_records(os.path.join(CAP, "fail-ts-mismatch.pcap"))}
    assert len(recs["01efa12e"]._esp) == 0
    assert len(recs["978d2ed7"]._esp) == 132


def test_esp_only_tunnel_directional_spis():
    recs = build_records(os.path.join(CAP, "a7-cs-aes256gcm16.pcap"))
    assert len(recs) == 1
    r = recs[0]
    assert len(r._esp) == 60
    assert (r.src, r.child_spi_out, r.child_spi_in) == ("10.10.1.10", "0xc33f04de", "0xc3951ee3")


def test_esp_only_rekey_stays_one_tunnel(monkeypatch):
    """T-052 regression: an ESP-only capture whose SPIs change (a rekey) is ONE tunnel.
    Built from real ESP packets of two captures between the same hosts, the second
    shifted to start after the first ends, as a rekey would."""
    from tunnelscope.evidence import extract
    from tunnelscope.ingest import tshark
    first = tshark.esp_packets(os.path.join(CAP, "cs-aes256gcm16-success-baseline.pcap"))
    second = tshark.esp_packets(os.path.join(CAP, "a7-cs-aes256gcm16.pcap"))
    t0 = max(p["t"] for p in first) + 5.0
    merged = first + [dict(p, t=p["t"] + t0, frame=p["frame"] + len(first)) for p in second]
    monkeypatch.setattr(extract.tshark, "ike_messages", lambda pcap: [])
    monkeypatch.setattr(extract.tshark, "esp_packets", lambda pcap: merged)
    monkeypatch.setattr(extract.tshark, "ah_packets", lambda pcap: [])
    recs = extract.group_sas("merged-rekey")
    assert len(recs) == 1, "a rekeying ESP-only tunnel must not be split per SPI"
    r = recs[0]
    assert len(r._esp) == len(merged) == 192
    assert {(p["src"], p["dst"]) for p in r._esp} == {("10.10.1.10", "10.10.2.10"), ("10.10.2.10", "10.10.1.10")}
    assert r.child_spi_out != r.child_spi_in
    assert all(p["src"] == r.src for p in r._esp if p["spi"] == r.child_spi_out)
    assert all(p["src"] == r.dst for p in r._esp if p["spi"] == r.child_spi_in)
