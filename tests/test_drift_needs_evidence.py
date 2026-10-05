"""An SA that shows nothing (no key exchange read, no traffic measured, no rule failed) is not judged for drift.

Found on 2026-10-05: restarting a tunnel left the old tunnel's delete exchange in the capture as its own SA. It had no
evidence at all, yet the server scored it 27/100 for "configuration drift" (an all-zero vector scored by the Isolation
Forest) and recorded it in the history, where it then pulled the tunnel's normal and the fleet towards "nothing".
"""
import os
from types import SimpleNamespace

from tunnelscope.anomaly.anomaly import History, has_evidence, observe, profile, tunnel_id
from tunnelscope.assess.engine import assess_record
from tunnelscope.evidence.extract import build_records
from tunnelscope.report.report import analyze
from tunnelscope.risk import risk as rk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures")


def _real_sa():
    return analyze(os.path.join(CAP, "cloud", "c-m.pcap"))["sas"][0]


def _empty_sa(like):
    r = like["record"]
    return {"record": SimpleNamespace(src=r.src, dst=r.dst, findings={}), "verdicts": []}


def test_has_evidence_needs_a_crypto_value_a_measurement_or_a_failed_rule():
    empty = profile(SimpleNamespace(findings={}), [])
    assert not has_evidence(empty)
    assert has_evidence(profile(_real_sa()["record"], _real_sa()["verdicts"]))
    assert has_evidence({**empty, "ike_dh_group": "MODP-2048"})
    assert has_evidence({**empty, "esp_rate": 0.0})        # a measured zero is still a measurement
    assert has_evidence({**empty, "fails": ["V-207193"]})


def test_an_empty_sa_is_not_judged_and_not_recorded(tmp_path):
    h = History(str(tmp_path))
    sa = _real_sa()
    for i in range(10):
        observe(h, [sa], "c-m.pcap", at=1000.0 + i)
    before = h.path.read_text()
    res = observe(h, [_empty_sa(sa)], "teardown.pcap", at=2000.0)[0]
    assert res["status"] == "no_evidence" and res["anomalies"] == []
    assert h.path.read_text() == before                     # nothing appended


def test_empty_rows_already_in_the_history_are_not_a_baseline(tmp_path):
    h = History(str(tmp_path))
    sa = _real_sa()
    empty = profile(SimpleNamespace(findings={}), [])
    tid = tunnel_id(sa["record"].src, sa["record"].dst)
    for i in range(5):
        h.record(tid, "old-teardown.pcap", empty, 1000.0 + i)
    res = observe(h, [sa], "c-m.pcap", at=2000.0)[0]
    assert res["status"] == "learning" and res["observations"] == 0


def test_drift_threat_is_not_assessable_for_an_sa_with_no_evidence():
    recs = [r for r in build_records(os.path.join(CAP, "cloud", "c-m.pcap")) if getattr(r, "_ike", [])]
    r = recs[0]
    an = {"status": "no_evidence", "observations": 0, "anomalies": []}
    t = {x["id"]: x for x in rk.assess_risk(r, assess_record(r), an)["threats"]}["TH-12"]
    assert t["status"] == "not_assessable" and "cannot be judged" in t["reason"]
