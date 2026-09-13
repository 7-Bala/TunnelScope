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
