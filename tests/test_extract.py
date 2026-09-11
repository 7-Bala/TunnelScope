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
