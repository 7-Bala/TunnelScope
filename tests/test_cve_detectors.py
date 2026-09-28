"""T-131 / EXP-34: the three plaintext-IKEv2 attack-pattern detectors. Specificity (0 detections on the real corpus)
is EXP-34's analyze.py; here are sensitivity (each detector fires on the pattern's parsed-message shape -- ADDENDUM A:
decision-function tests, no crafted packets) and vantage (UNKNOWN, never PASS, without the handshake)."""
from tunnelscope.evidence.extract import (
    _KE_FIXED_LEN,
    detect_informational_before_auth,
    detect_init_missing_payloads,
    detect_ke_anomaly,
)


def init(frame=1, groups=(14,), datas=None, payloads=(33, 34, 40), response=False):
    """A parsed IKE_SA_INIT message dict of the shape ingest.tshark.ike_messages produces."""
    if datas is None:
        datas = ["ab" * _KE_FIXED_LEN[g] for g in groups]              # well-formed data for each group
    return {"exchange": 34, "frame": frame, "is_response": response,
            "ke_groups": list(groups), "ke_data": list(datas), "payloads": sorted(payloads)}


def msg(exchange, frame):
    return {"exchange": exchange, "frame": frame, "is_response": False,
            "ke_groups": [], "ke_data": [], "payloads": []}


# ---- D1: malformed KE ----------------------------------------------------------------

def test_all_zero_ke_data_is_detected():
    v, note = detect_ke_anomaly([init(datas=["00" * 256])])
    assert v == "malformed-ke" and "all-zero" in note


def test_wrong_length_ke_for_its_group_is_detected():
    v, _ = detect_ke_anomaly([init(groups=(14,), datas=["ab" * 200])])   # MODP-2048 must be 256 bytes
    assert v == "malformed-ke"


def test_a_wellformed_ke_is_clean_and_an_unknown_group_is_not_guessed():
    assert detect_ke_anomaly([init()])[0] == "clean"
    assert detect_ke_anomaly([init(groups=(1000,), datas=["ab" * 99])])[0] == "clean"   # group not in table: not judged


def test_ke_anomaly_without_an_init_is_unknown_not_pass():
    v, _ = detect_ke_anomaly([])
    assert v is None


# ---- D2: INFORMATIONAL before IKE_AUTH -----------------------------------------------

def test_informational_before_auth_is_detected():
    ike = [msg(34, 1), msg(37, 2), msg(35, 3)]                          # INIT, INFORMATIONAL, then AUTH
    v, note = detect_informational_before_auth(ike)
    assert v == "informational-before-auth" and "before IKE_AUTH" in note


def test_informational_after_auth_is_clean():
    ike = [msg(34, 1), msg(35, 2), msg(37, 3)]                          # the normal order
    assert detect_informational_before_auth(ike)[0] == "clean"


def test_informational_without_the_handshake_is_unknown_not_pass():
    ike = [msg(37, 1), msg(37, 2)]                                      # no IKE_SA_INIT in the capture
    assert detect_informational_before_auth(ike)[0] is None


# ---- D3: IKE_SA_INIT missing a required payload ---------------------------------------

def test_init_missing_ke_is_detected():
    v, note = detect_init_missing_payloads([init(payloads=(33, 40))])   # no KE
    assert v == "init-missing-required-payload" and "KE" in note


def test_init_missing_nonce_is_detected():
    assert detect_init_missing_payloads([init(payloads=(33, 34))])[0] == "init-missing-required-payload"


def test_full_init_is_clean():
    assert detect_init_missing_payloads([init(payloads=(33, 34, 40, 41))])[0] == "clean"


def test_unparsed_payloads_are_not_a_false_detection():
    assert detect_init_missing_payloads([init(payloads=())])[0] == "clean"   # empty = not parsed, never guess


def test_init_missing_without_an_init_is_unknown_not_pass():
    assert detect_init_missing_payloads([])[0] is None


# ---- end to end through the pipeline (real handshakes stay clean) ---------------------

def test_real_handshakes_are_clean_through_the_engine():
    import os
    from pathlib import Path
    from tunnelscope.assess.engine import assess_record, load_baselines
    from tunnelscope.evidence.extract import build_records
    cap = Path(__file__).resolve().parents[1] / "testbed" / "captures" / "pq-downgrade.pcap"
    os.environ["TUNNELSCOPE_NETWORK"] = "off"
    rec = build_records(str(cap))[0]
    by = {v.rule_id: v.verdict for v in assess_record(rec, load_baselines())}
    for rid in ("CVE-WATCH-KE-MALFORMED", "CVE-WATCH-INFO-BEFORE-AUTH", "CVE-WATCH-INIT-PAYLOADS"):
        assert by[rid] == "PASS", (rid, by[rid])
