"""T-134: alerts for high-severity posture changes only (downgrade incl. PQ loss, first-time rule failure),
replayed on real lab captures of one tunnel (10.10.1.20 <-> 10.10.2.20)."""
import json
import re
from pathlib import Path

from tunnelscope.anomaly.alerts import alerts_from, format_alert, write_alerts
from tunnelscope.anomaly.anomaly import History, observe
from tunnelscope.report.report import analyze

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"


def _replay(tmp_path, names):
    h = History(str(tmp_path / "h"))
    got = []
    for i, n in enumerate(names):
        got.append(alerts_from(observe(h, analyze(str(CAP / n))["sas"], n, at=1000.0 + i), n, 1000.0 + i))
    return got


def test_pq_downgrade_and_loss_raise_alerts_after_learning(tmp_path):
    a = _replay(tmp_path, ["pq-mlkem768.pcap", "pq-mlkem768.pcap", "pq-downgrade.pcap", "classical-baseline.pcap"])
    assert a[0] == a[1] == []                                    # still learning: never an alert
    kinds = {(x["kind"], x["attribute"]) for x in a[2]}
    assert ("downgrade", "pq") in kinds and ("new_failure", "fails") in kinds
    assert a[2][0]["usual"] == "ML-KEM-768" and a[2][0]["now"] == "offered-but-not-used"
    assert [x["now"] for x in a[3] if x["kind"] == "downgrade"] == ["classical-only"]


def test_a_stable_tunnel_raises_nothing(tmp_path):
    assert _replay(tmp_path, ["pq-mlkem768.pcap"] * 5) == [[]] * 5


def _res(kind, severity, layer="posture"):
    return [{"tunnel": "a <-> b", "status": "anomalous",
             "anomalies": [{"layer": layer, "kind": kind, "severity": severity, "attribute": "x", "usual": 1,
                            "now": 2, "message": "m"}]}]


def test_only_high_posture_changes_are_alerts():
    assert alerts_from(_res("change", "medium"), "s", 0) == []
    assert alerts_from(_res("upgrade", "informational"), "s", 0) == []
    assert alerts_from(_res("shift", "medium", layer="traffic"), "s", 0) == []
    assert len(alerts_from(_res("downgrade", "high"), "s", 0)) == 1


def test_formats(tmp_path):
    (al,) = alerts_from(_res("downgrade", "high"), "s", 0)
    line = format_alert(al, "syslog", hostname="h1")
    assert re.match(r"<107>1 1970-01-01T00:00:00\+00:00 h1 tunnelscope - DOWNGRADE \[tunnelscope@32473 ", line), line
    assert json.loads(format_alert(al, "jsonl"))["kind"] == "downgrade"
    path = tmp_path / "alerts.jsonl"
    assert write_alerts([al, al], str(path), "jsonl") == 2 and len(path.read_text().splitlines()) == 2


def test_live_alerts_need_a_history(capsys):
    from tunnelscope.cli import main
    assert main(["live", "--follow", "/nonexistent-dir-for-test", "--alerts", "x.jsonl"]) == 2
    assert "--alerts needs --history" in capsys.readouterr().err
