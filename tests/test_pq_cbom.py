"""PQ downgrade detection + CBOM (CS-05, T-033)."""
import os
from tunnelscope.evidence.extract import build_records
from tunnelscope.assess.engine import assess_record, load_baselines
from tunnelscope.pq.cbom import build_cbom

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")


def _main(p):
    return max(build_records(os.path.join(CAP, p)), key=lambda r: len(getattr(r, "_ike", [])))


def test_downgrade_detected():
    r = _main("pq-downgrade.pcap")
    assert r.findings["pq_key_exchange"].value == "offered-but-not-used"
    v = {x.rule_id: x for x in assess_record(r, load_baselines())}
    assert v["DST-PQ-DOWNGRADE"].verdict == "FAIL"


def test_cbom_posture():
    assert "post-quantum" in build_cbom(build_records(os.path.join(CAP, "pq-mlkem768.pcap")))["tunnelscope_sa_summary"][0]["quantum_posture"]
    assert "DOWNGRADED" in build_cbom(build_records(os.path.join(CAP, "pq-downgrade.pcap")))["tunnelscope_sa_summary"][0]["quantum_posture"]
    assert build_cbom(build_records(os.path.join(CAP, "classical-baseline.pcap")))["bomFormat"] == "CycloneDX"


def test_cbom_never_overstates():
    # gaps must be recorded, not silently dropped; classical KE flagged vulnerable
    cb = build_cbom(build_records(os.path.join(CAP, "classical-baseline.pcap")))
    names = [c["name"] for c in cb["components"]]
    assert "MODP-2048" in names and "ML-KEM-768" not in names
