"""T-022 — CVE-2026-78135 early-Child-SA detector (EXP-09).

Locks in both sides of the detector:
  - SENSITIVITY: fires OBSERVED 'early-child-sa-before-auth' on the synthetic
    plaintext-structural positive (testbed/captures/synthetic/...).
  - SPECIFICITY + vantage guard: never fires on a normal handshake, and returns
    UNKNOWN (not a detection) when the SA was not seen from IKE_SA_INIT.
The synthetic positive is header-only by construction; see the generator's
honesty note. These tests exercise the extractor's logic directly with
message dicts so they do not depend on tshark being installed.
"""
import os

from tunnelscope.evidence.extract import extract_early_childsa_cve
from tunnelscope.evidence.record import EvidenceRecord, Status

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _rec(msgs):
    r = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = msgs
    return r


def _m(exch, mid):
    return {"exchange": exch, "message_id": mid, "is_response": False}


def test_fires_on_child_before_auth():
    r = _rec([_m(34, 0), _m(36, 1)])  # IKE_SA_INIT then CREATE_CHILD_SA, no IKE_AUTH
    extract_early_childsa_cve(r)
    f = r.findings["early_childsa_cve"]
    assert f.status == Status.OBSERVED
    assert f.value == "early-child-sa-before-auth"


def test_fires_when_child_msgid_precedes_auth():
    r = _rec([_m(34, 0), _m(36, 1), _m(35, 2)])  # child at 1, auth only at 2
    extract_early_childsa_cve(r)
    assert r.findings["early_childsa_cve"].value == "early-child-sa-before-auth"


def test_normal_handshake_not_detected():
    r = _rec([_m(34, 0), _m(35, 1), _m(36, 2)])  # auth precedes the rekey
    extract_early_childsa_cve(r)
    f = r.findings["early_childsa_cve"]
    assert f.status == Status.OBSERVED and f.value == "not-detected"


def test_no_child_is_not_applicable():
    r = _rec([_m(34, 0), _m(35, 1)])
    extract_early_childsa_cve(r)
    assert r.findings["early_childsa_cve"].value == "not-applicable"


def test_unknown_when_sa_not_seen_from_birth():
    r = _rec([_m(36, 5)])  # capture starts mid-tunnel: CREATE_CHILD_SA, no IKE_SA_INIT
    extract_early_childsa_cve(r)
    f = r.findings["early_childsa_cve"]
    assert f.status == Status.UNKNOWN and f.value is None  # never a false alarm


def test_synthetic_positive_capture_if_present():
    """End-to-end on the committed synthetic positive (skips if tshark absent)."""
    import shutil
    pcap = os.path.join(ROOT, "testbed", "captures", "synthetic",
                        "cve-2026-78135-plaintext-positive.pcap")
    if not (shutil.which("tshark") and os.path.exists(pcap)):
        return
    from tunnelscope.evidence.extract import build_records
    hit = any(r.findings.get("early_childsa_cve") and
              r.findings["early_childsa_cve"].value == "early-child-sa-before-auth"
              for r in build_records(pcap))
    assert hit
