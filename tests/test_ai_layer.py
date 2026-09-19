"""T-082: the AI layer — Random Forest attacker, anomaly detection, explanations."""
import csv
import gzip
import importlib.util
import json
import os
import threading
import urllib.request

import numpy as np
import pytest

from tunnelscope.anomaly import anomaly as an
from tunnelscope.explain import explain as ex
from tunnelscope.leakage import attacker as at

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures")
EXP05 = os.path.join(CAP, "exp05")


def _session(tag):
    with gzip.open(os.path.join(EXP05, f"{tag}.pkts.csv.gz"), "rt") as f:
        next(f)
        return [(float(t), d, int(n)) for t, d, n in (l.strip().split(",") for l in f) if n]


def _esp(pkts, a="10.0.0.1", b="10.0.0.2"):
    return [{"t": t, "src": a if d == "out" else b, "dst": b if d == "out" else a, "ip_len": n, "frame": i + 1}
            for i, (t, d, n) in enumerate(pkts)]


# ------------------------------------------------------------- attacker ---

def test_features_identical_to_exp05():
    spec = importlib.util.spec_from_file_location("exp05", os.path.join(ROOT, "experiments/exp05-metadata-leakage/analyze.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    pk = _session("exp05-base-web-rep1")
    assert np.allclose(np.array(m.window_features(pk)), np.array(at.window_features(pk)))


def test_attacker_generalises_to_a_held_out_repetition():
    """Train without repetition 4, test on it: the shipped attacker's skill is
    not just memorising the sessions it was trained on."""
    from sklearn.ensemble import RandomForestClassifier
    d = np.load(at.DATA, allow_pickle=False)
    tr, te = d["rep"] != 4, d["rep"] == 4
    rf = RandomForestClassifier(n_estimators=200, random_state=0).fit(d["X"][tr], d["y"][tr])
    assert (rf.predict(d["X"][te]) == d["y"][te]).mean() > 0.9


def test_attacker_names_the_traffic_type_only_with_its_confidence():
    """DEC-027 (supersedes DEC-021): a label is shown only together with its
    probability and alternatives, and only when the abstain rule is cleared."""
    r = at.assess_exposure(_esp(_session("exp05-tfc-video-rep2")))
    assert r["status"] == "measured" and r["level"] == "high"
    t = r["traffic"]
    if t["answered"]:
        assert t["class"] in at.CLASSES and 0 < t["probability"] <= 1 and t["alternatives"]
    else:
        assert t["class"] is None and t["why_not"]


def test_mixed_traffic_label_outside_the_mix_carries_its_warning():
    """EXP-15 P15-4 failed: most mixed sessions are named after their dominant
    type, but video+interactive reads as web. Every such label must say so."""
    from tunnelscope.evidence.record import EvidenceRecord
    mux = sorted(f[:-12] for f in os.listdir(EXP05) if f.startswith("exp05-mux") and f.endswith(".pkts.csv.gz"))
    outside = 0
    for m in mux:
        rec = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="x")
        rec._esp = _esp(_session(m))
        at.extract_attacker(rec)
        f = rec.findings["traffic_type"]
        parts = m.split("-")[2].split("_")
        if f.value and f.value["class"] not in parts:
            outside += 1
            assert "caution" in f.note and "dominant" in f.note, m
    assert outside >= 1       # the known confusion really is exercised


def test_too_little_traffic_is_insufficient():
    r = at.assess_exposure(_esp([(0.0, "out", 100), (0.1, "in", 100)]))
    assert r["status"] == "insufficient"


# -------------------------------------------------------------- anomaly ---

GOOD = {"ike_version": "IKEv2", "ike_encr": "AES-CBC-256", "ike_integ": "HMAC-SHA2-256-128",
        "ike_dh_group": "MODP-2048", "pq": "classical-only", "fails": ["V-207193"],
        "esp_rate": 40.0, "esp_mean_len": 250.0, "size_bits": 3.0, "timing_bits": 1.5}


def test_learning_then_normal():
    assert an.detect(GOOD, [])["status"] == "learning"
    assert an.detect(GOOD, [GOOD, GOOD])["status"] == "normal"


def test_downgrade_is_high_and_upgrade_is_not_an_alarm():
    weak = {**GOOD, "ike_dh_group": "MODP-1024", "fails": ["V-207193", "RFC8247-DH-MUST"]}
    r = an.detect(weak, [GOOD] * 3)
    kinds = {(a["kind"], a["attribute"]) for a in r["anomalies"]}
    assert r["status"] == "anomalous"
    assert ("downgrade", "ike_dh_group") in kinds and ("new_failure", "fails") in kinds
    strong = {**GOOD, "ike_dh_group": "ECP-384"}
    r = an.detect(strong, [GOOD] * 3)
    assert r["status"] == "normal" and r["anomalies"][0]["kind"] == "upgrade"


def test_pq_loss_is_a_downgrade():
    pq = {**GOOD, "pq": "ML-KEM-768"}
    r = an.detect(GOOD, [pq] * 3)
    assert any(a["kind"] == "downgrade" and a["attribute"] == "pq" for a in r["anomalies"])


def test_traffic_shift_needs_enough_history():
    past = [{**GOOD, "esp_rate": 40 + i % 3} for i in range(6)]
    burst = {**GOOD, "esp_rate": 900.0}
    assert any(a["layer"] == "traffic" for a in an.detect(burst, past)["anomalies"])
    assert not any(a["layer"] == "traffic" for a in an.detect(burst, past[:3])["anomalies"])


def test_isolation_forest_runs_after_min_model():
    past = [{**GOOD, "esp_rate": 40 + i % 3, "esp_mean_len": 250 + i % 4} for i in range(10)]
    odd = {**GOOD, "esp_rate": 5000.0, "esp_mean_len": 1400.0, "size_bits": 0.0}
    r = an.detect(odd, past)
    assert "model" in r["layers"] and any(a["layer"] == "model" for a in r["anomalies"])


def test_fleet_outlier():
    fleet = {f"t{i}": {**GOOD, "esp_rate": 40 + i} for i in range(8)}
    fleet["odd"] = {**GOOD, "ike_version": "IKEv1", "ike_dh_group": "MODP-768", "ike_encr": "3DES",
                    "esp_rate": 3000.0, "fails": ["a", "b", "c", "d", "e"]}
    assert "odd" in an.fleet_outliers(fleet)
    assert an.fleet_outliers(dict(list(fleet.items())[:3])) == {}


def test_history_end_to_end_on_real_captures(tmp_path):
    from tunnelscope.report.report import analyze
    h = an.History(str(tmp_path))
    for f in ["c-m", "c-m", "c-m"]:
        an.observe(h, analyze(os.path.join(CAP, "cloud", f + ".pcap"))["sas"], f)
    (res,) = an.observe(h, analyze(os.path.join(CAP, "cloud", "c-w.pcap"))["sas"], "c-w")
    assert res["status"] == "anomalous"
    assert {a["attribute"] for a in res["anomalies"] if a["kind"] == "downgrade"} >= {"ike_dh_group", "ike_integ"}
    with open(h.path, "a") as fh:
        fh.write('{"torn')            # a crash mid-write must not lose the history
    assert len(h.load()) == 4


def test_history_stores_no_packets(tmp_path):
    from tunnelscope.report.report import analyze
    h = an.History(str(tmp_path))
    an.observe(h, analyze(os.path.join(CAP, "cloud", "c-w.pcap"))["sas"], "c-w")
    row = h.load()[0]
    assert set(row) == {"at", "tunnel", "source", "profile"}
    assert set(row["profile"]) == set(an.CRYPTO) | set(an.NUMERIC) | {"fails"}


# -------------------------------------------------------------- explain ---

@pytest.fixture(scope="module")
def sa_cw():
    from tunnelscope.api.server import analysis_json
    from tunnelscope.report.report import analyze
    return analysis_json(analyze(os.path.join(CAP, "cloud", "c-w.pcap")), "c-w.pcap")["sas"][0]


def test_every_rule_has_a_plain_explanation():
    from tunnelscope.assess.engine import load_baselines
    ids = {r["id"] if isinstance(r, dict) else r.id for b in load_baselines()
           for r in (b["rules"] if isinstance(b, dict) else b.rules)}
    assert ids <= set(ex.GLOSSARY)


def test_no_outside_model_is_used():
    """Decision 2026-09-20: every model is trained by the project. No LLM client,
    no model download, no network call anywhere in the package."""
    import pathlib
    pkg = pathlib.Path(ex.__file__).parents[1]
    src = "\n".join(p.read_text() for p in pkg.rglob("*.py")).lower()
    for banned in ("anthropic", "openai", "ollama", "gemini", "urllib.request.urlopen", "transformers", "huggingface"):
        assert banned not in src, banned


def test_template_covers_every_fail(sa_cw):
    e = ex.explain_sa(sa_cw)
    fails = {v["rule_id"] for v in sa_cw["verdicts"] if v["verdict"] == "FAIL"}
    assert {p["rule_id"] for p in e["points"] if p["kind"] == "fail"} == fails
    assert "compliant" not in ex.as_text(e).lower()


# --------------------------------------------------------------- server ---

def test_server_history_and_explain(tmp_path, monkeypatch):
    from tunnelscope.api import server
    monkeypatch.setattr(server, "HISTORY_DIR", str(tmp_path))
    srv = server.make_server(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        h = json.load(urllib.request.urlopen(base + "/health"))
        assert h["history"] is True and "llm" not in h
        data = open(os.path.join(CAP, "cloud", "c-w.pcap"), "rb").read()
        res = json.load(urllib.request.urlopen(urllib.request.Request(base + "/api/analyze?name=c-w.pcap", data)))
        sa = res["sas"][0]
        assert sa["anomaly"]["status"] == "learning" and sa["explanation"]["source"] == "template"
        assert sa["explanation"]["summary"].startswith("This tunnel")
        hist = json.load(urllib.request.urlopen(base + "/api/history"))
        assert hist["tunnels"][0]["observations"] == 1
    finally:
        srv.shutdown()
