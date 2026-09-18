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


def _m(exch, mid, frame=None):
    # frame defaults to mid: every existing fixture here already chose msgid
    # values to reflect intended chronological order, so this keeps them
    # unchanged. Pass frame= explicitly (as the new regression test does) when
    # a fixture needs message-id and frame order to actually differ.
    return {"exchange": exch, "message_id": mid, "is_response": False,
            "frame": frame if frame is not None else mid}


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


def test_responder_initiated_rekey_is_not_a_false_positive():
    """Regression for the real false positive EXP-12 found (2026-09-13):
    message IDs are per-ORIGINATOR (RFC 7296 sec 2.1). Once the peer that
    answered IKE_AUTH independently initiates its own exchange, its own
    message-id counter restarts at 0 - comparing that against the other
    side's message ids (the original bug) makes a routine responder-initiated
    rekey look like CREATE_CHILD_SA-before-auth. Minimal repro: IKE_AUTH at
    msgid 1 (initiator's sequence), then a responder-initiated CREATE_CHILD_SA
    at msgid 0 (responder's OWN, freshly-started sequence) - frame order still
    correctly shows auth first."""
    r = _rec([
        _m(34, 0),                                   # IKE_SA_INIT
        {"exchange": 35, "message_id": 1, "is_response": False, "frame": 3},
        {"exchange": 36, "message_id": 0, "is_response": False, "frame": 10},  # responder's own rekey, own counter
    ])
    extract_early_childsa_cve(r)
    assert r.findings["early_childsa_cve"].value == "not-detected"


def test_live_exploitlab_capture_if_present():
    """End-to-end on the LIVE fault-injected reproduction (genuine strongSwan
    traffic, not synthetic headers — see testbed/images/strongswan-exploitlab/
    and testbed/captures/exploitlab/*.groundtruth.json). Skips if absent/no
    tshark: this capture is produced by a one-time lab run, not regenerated
    per test run."""
    import shutil
    pcap = os.path.join(ROOT, "testbed", "captures", "exploitlab",
                        "cve-2026-78135-live.pcap")
    if not (shutil.which("tshark") and os.path.exists(pcap)):
        return
    from tunnelscope.evidence.extract import build_records
    hit = any(r.findings.get("early_childsa_cve") and
              r.findings["early_childsa_cve"].value == "early-child-sa-before-auth"
              for r in build_records(pcap))
    assert hit


# --- T-055: message-ID guard for captures that lost IKE_AUTH (plan CVE-2b) ---

def test_msgid_gap_without_auth_is_unknown():
    """IKE_AUTH (msgid 1) was sent but not captured: the rekey's msgid 2 does
    not directly follow IKE_SA_INIT's 0, so the pattern is not proven."""
    r = _rec([_m(34, 0), _m(36, 2, frame=5)])
    extract_early_childsa_cve(r)
    f = r.findings["early_childsa_cve"]
    assert f.status == Status.UNKNOWN and f.value is None


def test_child_directly_after_intermediate_fires():
    """PQ handshakes add IKE_INTERMEDIATE exchanges before IKE_AUTH; a child
    at the next msgid after the last one is still proven early."""
    r = _rec([_m(34, 0), _m(43, 1), _m(36, 2)])
    extract_early_childsa_cve(r)
    assert r.findings["early_childsa_cve"].value == "early-child-sa-before-auth"


def test_responder_originated_child_without_auth_is_unknown():
    """The responder's own msgid counter never counts the initiator's
    IKE_AUTH, so it cannot prove IKE_AUTH absent."""
    r = _rec([_m(34, 0),
              {"exchange": 36, "message_id": 0, "is_response": False,
               "is_initiator": False, "frame": 4}])
    extract_early_childsa_cve(r)
    assert r.findings["early_childsa_cve"].status == Status.UNKNOWN


def test_benign_capture_with_ike_auth_deleted_is_unknown(tmp_path):
    """Plan acceptance: a real benign capture with a rekey, its IKE_AUTH
    frames deleted, must read UNKNOWN (before T-055 it fired)."""
    import shutil
    import subprocess
    src = os.path.join(ROOT, "testbed", "captures", "exp12", "rekey-cadence.pcap")
    if not (shutil.which("tshark") and shutil.which("editcap") and os.path.exists(src)):
        return
    frames = subprocess.run(["tshark", "-r", src, "-Y", "isakmp.exchangetype==35",
                             "-T", "fields", "-e", "frame.number"],
                            capture_output=True, text=True, check=True).stdout.split()
    assert frames, "fixture must contain IKE_AUTH"
    out = str(tmp_path / "no-auth.pcap")
    subprocess.run(["editcap", src, out, *frames], check=True)
    from tunnelscope.evidence.extract import build_records
    vals = [(r.findings["early_childsa_cve"].status, r.findings["early_childsa_cve"].value)
            for r in build_records(out) if "early_childsa_cve" in r.findings]
    assert vals and all(v != "early-child-sa-before-auth" for _, v in vals)
    assert any(s == Status.UNKNOWN for s, _ in vals)
