import os
from tunnelscope.evidence.extract import build_records
from tunnelscope.assess.engine import assess_record, load_baselines
from tunnelscope.score.score import score_record, score_baseline
CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")
BL = load_baselines()

def _v(p): return assess_record(max(build_records(os.path.join(CAP,p)),key=lambda r:len(getattr(r,'_ike',[]))), BL)

def test_no_score_when_nothing_assessable():
    # mid-SA rekey: everything UNKNOWN -> score None, coverage 0, never a number
    for b,s in score_record(_v("rekey-cs-pfs-on-aes256gcm16-run2.pcap")).items():
        assert s["score"] is None and s["coverage"] == 0.0

def test_unknown_never_inflates():
    # a FAIL must lower the score below 100; UNKNOWN must not raise it
    s = score_record(_v("classical-baseline.pcap"))["DISA-VPN-SRG-V2R6"]
    assert s["score"] < 100 and s["counts"]["fail"] >= 1

def test_per_baseline_split():
    s = score_record(_v("cs-aes256gcm16.pcap"))
    assert s["RFC-8247"]["score"] == 100.0
    assert s["DISA-VPN-SRG-V2R6"]["score"] < 100.0
