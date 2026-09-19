import os
from tunnelscope.report.report import analyze, executive_report, technical_report
CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")

def test_reports_generate_and_separate_statuses():
    a = analyze(os.path.join(CAP, "pq-downgrade.pcap"))
    ex, tech = executive_report(a), technical_report(a)
    assert "DOWNGRADED" in ex and "DST-PQ-DOWNGRADE" in ex
    # technical report keeps observed vs inferred distinct and cites authority
    assert "not observable" in tech.lower() or "not-observable" in tech.lower()
    assert "DISA" in tech and "RFC 8247" in tech
    # an undeterminable finding (mode) must never render as a value
    assert "| Tunnel / transport mode | unknown | — |" in tech
    assert "### Threat matrix" in tech and "Risk score" in ex

def test_exec_flags_high_severity():
    a = analyze(os.path.join(CAP, "classical-baseline.pcap"))
    assert "high-severity" in executive_report(a)
