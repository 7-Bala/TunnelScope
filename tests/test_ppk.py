"""T-136 / EXP-27: RFC 8784 PPK. USE_PPK in IKE_SA_INIT is plaintext, so PPK negotiation is visible; whether
the PPK was actually used is decided in encrypted IKE_AUTH (K5: both sides announce it, the tunnel comes up
without it). The finding must say "negotiated", never "used"."""
import os

import pytest

from tunnelscope.evidence.extract import build_records, extract_ppk
from tunnelscope.evidence.record import EvidenceRecord

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures", "exp27")
USE_PPK = 16435


def _f(arm, attr="pq_ppk"):
    (r,) = [r for r in build_records(os.path.join(CAP, f"ppk-{arm}.pcap")) if getattr(r, "_ike", [])]
    return r.findings[attr]


@pytest.mark.parametrize("arm,want", [("k0", "not-offered"), ("k1", "negotiated"), ("k2", "negotiated"),
                                      ("k3", "offered-not-negotiated"), ("k4", "negotiated"),
                                      ("k5", "negotiated")])
def test_ppk_negotiation_read_from_the_wire(arm, want):
    f = _f(arm)
    assert f.status.value == "OBSERVED" and f.value == want, (f.status, f.value)


@pytest.mark.parametrize("arm", ["k1", "k2", "k4", "k5"])
def test_negotiated_never_claims_the_ppk_was_used(arm):
    """K5 is the proof: USE_PPK both ways, tunnel up, PPK not used (strongSwan: 'using NO_PPK_AUTH')."""
    f = _f(arm)
    assert "IKE_AUTH" in f.note and "not visible" in f.note, f.note


@pytest.mark.parametrize("arm", ["k0", "k1", "k2", "k3", "k4", "k5"])
def test_ppk_notifies_do_not_disturb_the_rfc9370_finding(arm):
    assert _f(arm, "pq_key_exchange").value == "classical-only"


def _rec(*msgs):
    r = EvidenceRecord(source_pcap="x.pcap")
    r._ike = list(msgs)
    return r


def _init(response, notifies, frame=1):
    return {"exchange": 34, "is_response": response, "notify_types": notifies, "frame": frame}


def test_no_ike_sa_init_is_unknown():
    r = _rec()
    extract_ppk(r)
    assert r.findings["pq_ppk"].status.value == "UNKNOWN"


def test_offer_without_a_visible_response_is_unknown_not_a_refusal():
    r = _rec(_init(False, [USE_PPK]))
    extract_ppk(r)
    assert r.findings["pq_ppk"].status.value == "UNKNOWN"


def test_error_only_response_before_a_retry_does_not_count_as_refusal():
    """INVALID_KE_PAYLOAD (17) makes the initiator retry; only the last answering response stands."""
    r = _rec(_init(False, [USE_PPK]), _init(True, [17], 2), _init(False, [USE_PPK], 3), _init(True, [USE_PPK], 4))
    extract_ppk(r)
    assert r.findings["pq_ppk"].value == "negotiated"
