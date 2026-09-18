"""Assessment-engine tests. The hard criterion (09-DEFINE sec 4): NEVER a false
PASS where evidence is absent, and multi-baseline verdicts must name their authority."""
import os
from tunnelscope.evidence.extract import build_records
from tunnelscope.assess.engine import assess_record, load_baselines

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")
BL = load_baselines()


def _verdicts(pcap):
    r = max(build_records(os.path.join(CAP, pcap)), key=lambda x: len(getattr(x, "_ike", [])))
    return {(v.baseline, v.rule_id): v for v in assess_record(r, BL)}


def test_no_false_pass_when_evidence_absent():
    # rekey captures have no IKE_SA_INIT -> DH/version/PQ unobserved -> never PASS/FAIL.
    for pcap in ("rekey-cs-pfs-on-aes256gcm16-run2.pcap", "rekey-cs-pfs-off-aes256gcm16-run2.pcap"):
        for (b, rid), v in _verdicts(pcap).items():
            if v.attribute in ("ike_version", "ike_dh_group", "pq_key_exchange", "ike_integ"):
                assert v.verdict in ("UNKNOWN", "NOT_OBSERVABLE"), \
                    f"{pcap} {b}/{rid}: {v.verdict} on unobserved {v.attribute} (false assurance!)"


def test_multi_baseline_dh_contradiction():
    # MODP-2048: PASS under RFC 8247 (group 14 baseline), FAIL under DISA (>=16).
    v = _verdicts("cs-aes256gcm16.pcap")
    assert v[("RFC-8247", "RFC8247-DH-MUST")].verdict == "PASS"
    assert v[("DISA-VPN-SRG-V2R6", "V-207193")].verdict == "FAIL"
    # both must name their authority
    assert "RFC 8247" in v[("RFC-8247", "RFC8247-DH-MUST")].authority
    assert "DISA" in v[("DISA-VPN-SRG-V2R6", "V-207193")].authority


def test_pq_downgrade_detected():
    # classical capture: no PQ -> DST-PQ-KE FAIL; PQ capture: PASS.
    assert _verdicts("classical-baseline.pcap")[("DST-NQM-2026", "DST-PQ-KE")].verdict == "FAIL"
    assert _verdicts("pq-mlkem768.pcap")[("DST-NQM-2026", "DST-PQ-KE")].verdict == "PASS"


def test_every_verdict_cites_authority():
    for (b, rid), v in _verdicts("cs-aes256gcm16.pcap").items():
        assert v.authority and v.rule_id, f"{b}/{rid} missing citation"


def test_no_baselines_is_an_error_not_an_empty_pass(tmp_path):
    """An assessment against zero baselines has no verdicts, which reads as
    'nothing wrong'. Found for real (2026-09-18): an installed wheel resolved
    the rules directory relative to a source checkout that wasn't there and
    assessed every capture against nothing, exit 0. Must refuse instead."""
    import pytest
    from tunnelscope.errors import DependencyError
    with pytest.raises(DependencyError):
        load_baselines(str(tmp_path))


def test_baselines_ship_inside_the_package():
    """The rules live in tunnelscope/rules/ (package data), not the repo root."""
    import os
    import tunnelscope
    rules = os.path.join(os.path.dirname(tunnelscope.__file__), "rules")
    assert len([f for f in os.listdir(rules) if f.endswith(".yaml")]) >= 4
    assert len(load_baselines(rules)) >= 4
