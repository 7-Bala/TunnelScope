"""Regressions found in the 2026-09-25 end-to-end browser test. Each is a place where the tool said
more than its evidence showed (DEC-008: absence of evidence is never a pass, nor a verdict)."""
import os
from types import SimpleNamespace as NS

from tunnelscope.anomaly.anomaly import _traffic_layer
from tunnelscope.evidence.extract import build_records
from tunnelscope.pq.cbom import build_cbom, record_to_components
from tunnelscope.risk.risk import threats

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")


def test_posture_is_unknown_when_the_key_exchange_was_not_seen():
    """A capture holding only rekeys (no IKE_SA_INIT) used to be labelled "classical"."""
    recs = build_records(os.path.join(CAP, "rekey-cs-pfs-off-aes256gcm16-run2.pcap"))
    postures = {record_to_components(r)[2] for r in recs if not getattr(r, "_esp_only", False)}
    assert postures and all(p.startswith("unknown") for p in postures), postures


def test_esp_only_posture_stays_unknown():
    recs = build_records(os.path.join(CAP, "tfc-sample.pcap"))
    for sa in build_cbom(recs)["tunnelscope_sa_summary"]:
        assert not sa["quantum_posture"].startswith("classical"), sa


def test_ikev1_is_classical_by_protocol_and_says_why():
    """IKEv1 has no post-quantum key exchange, so classical is certain even without the KE payload."""
    recs = build_records(os.path.join(CAP, "cloud", "c-v1.pcap"))
    postures = {record_to_components(r)[2] for r in recs}
    assert any(p.startswith("classical (IKEv1") for p in postures), postures


def test_observed_postures_unchanged():
    for f, want in (("pq-mlkem768.pcap", "post-quantum"), ("pq-downgrade.pcap", "DOWNGRADED")):
        assert build_cbom(build_records(os.path.join(CAP, f)))["tunnelscope_sa_summary"][0]["quantum_posture"].startswith(want)


def test_downgrade_threat_never_cites_passing_rules_as_evidence():
    """TH-03 raised by the anomaly layer used to list the rules that PASSED as its evidence and say
    "the rules that test for it pass; this tunnel was stronger before"."""
    V = [NS(rule_id="DST-PQ-DOWNGRADE", verdict="PASS", message="", title="t"),
         NS(rule_id="RFC8247-DH-OFFER", verdict="PASS", message="", title="t")]
    anom = {"status": "anomalous", "anomalies": [{"kind": "downgrade", "severity": "high", "message": "m"}]}
    t3 = next(t for t in threats(NS(findings={}), V, anom) if t.id == "TH-03")
    assert t3.status == "present" and t3.likelihood == 3
    assert "DST-PQ-DOWNGRADE" not in t3.evidence and "RFC8247-DH-OFFER" not in t3.evidence
    assert "pass" not in t3.reason and "stronger before" in t3.reason


def test_downgrade_threat_keeps_failing_rules_as_evidence():
    V = [NS(rule_id="DST-PQ-DOWNGRADE", verdict="FAIL", message="PQ offered, classical selected", title="t")]
    anom = {"status": "anomalous", "anomalies": [{"kind": "downgrade", "severity": "high", "message": "m"}]}
    t3 = next(t for t in threats(NS(findings={}), V, anom) if t.id == "TH-03")
    assert "DST-PQ-DOWNGRADE" in t3.evidence and t3.reason.startswith("PQ offered")


def test_steady_history_shift_reports_no_fake_z():
    """A history that was exactly 0 every time used to report "robust z +2773544.0"."""
    past = [{"size_bits": 0.0} for _ in range(6)]
    out = _traffic_layer({"size_bits": 4.112}, past)
    assert len(out) == 1 and out[0]["z"] is None
    assert "exactly 0 in all 6 earlier captures, now 4.112" in out[0]["message"]
    assert "robust z" not in out[0]["message"]


def test_varied_history_still_reports_z():
    past = [{"esp_rate": v} for v in (2.0, 2.5, 3.0, 3.5, 2.8, 3.1)]
    out = _traffic_layer({"esp_rate": 38.0}, past)
    assert len(out) == 1 and isinstance(out[0]["z"], float) and "robust z" in out[0]["message"]
