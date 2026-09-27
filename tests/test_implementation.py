"""T-127 / EXP-29: IKE implementation fingerprint per end, from plaintext only. An implementation never seen,
or one whose message does not match exactly one fingerprint, is UNKNOWN; a wrong name is the failure."""
from pathlib import Path

import pytest

from tunnelscope.evidence.extract import build_records, extract_implementation
from tunnelscope.evidence.record import EvidenceRecord

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"


def _impl(path):
    r = next(r for r in build_records(str(CAP / path)) if getattr(r, "_ike", []))
    return r.findings["implementation"]


@pytest.mark.parametrize("path,want", [
    ("cs-aes256gcm16.pcap", "strongSwan"),                  # train
    ("exp27/ppk-k1.pcap", "strongSwan"),                    # test: strongSwan 6.1.0, never trained on
    ("exp29/e7-gcm256.pcap", "Libreswan"),                  # test: a Libreswan session captured after the freeze
    ("exp26/mt-m7.pcap", "MikroTik RouterOS"),              # test
])
def test_both_ends_named(path, want):
    f = _impl(path)
    assert f.status.value == "INFERRED" and f.value == {"initiator": want, "responder": want}, (f.value, f.note)


def test_openbsd_iked_is_unknown_not_a_lookalike():
    """EXP-10: no iked training data; its end must never be given another implementation's name."""
    f = _impl("exp10/obsd-vendor.pcap")
    assert f.value["initiator"] == "strongSwan" and f.value["responder"] is None


def test_an_end_whose_notifies_match_no_rule_is_unknown():
    f = _impl("exp29/e7-pq.pcap")        # Libreswan adds INTERMEDIATE_EXCHANGE_SUPPORTED after FRAG
    assert f.status.value == "UNKNOWN"


def test_mikrotik_needs_the_padding_evidence_too():
    """The three-notify pattern alone is not enough (another stack could send just NAT_D, NAT_D, FRAG)."""
    r = EvidenceRecord(source_pcap="x.pcap")
    r._ike = [{"exchange": 34, "is_response": False, "notify_types": [16388, 16389, 16430], "src": "a", "dst": "b",
               "frame": 1, "transform_types": [1]}]
    extract_implementation(r)
    assert r.findings["implementation"].status.value == "UNKNOWN"


def test_error_only_response_is_not_fingerprinted():
    r = EvidenceRecord(source_pcap="x.pcap")
    r._ike = [{"exchange": 34, "is_response": False, "notify_types": [16388, 16389, 16430, 16431], "src": "a",
               "dst": "b", "frame": 1, "transform_types": [1]},
              {"exchange": 34, "is_response": True, "notify_types": [14], "src": "b", "dst": "a", "frame": 2,
               "transform_types": []}]
    extract_implementation(r)
    assert r.findings["implementation"].value == {"initiator": "strongSwan", "responder": None}


def test_two_matching_fingerprints_give_unknown_not_the_first(monkeypatch):
    """Today's rules never overlap; a future rule that does must not let the first one win."""
    import tunnelscope.evidence.extract as ex
    monkeypatch.setattr(ex, "IMPL_RULES", ex.IMPL_RULES + (("Lookalike", "same notifies", lambda seq, m, pad: seq[:1] == [16388]),))
    f = _impl("cs-aes256gcm16.pcap")
    assert f.status.value == "UNKNOWN", f.value
