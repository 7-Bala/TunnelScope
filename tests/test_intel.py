"""T-130 / DEC-040: threat intelligence. No test uses the network: net.http_json is replaced by recorded, trimmed
real responses (tests/fixtures/intel, 2026-09-27)."""
import json
from pathlib import Path

import pytest

from tunnelscope import net
from tunnelscope.intel import lookup as L
from tunnelscope.intel.sources import PRODUCTS, SOURCES
from tunnelscope.risk.refs import THREAT_REFS, refs_for

FIX = Path(__file__).parent / "fixtures" / "intel"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def served(monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNELSCOPE_INTEL_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv(net.ENV, "on")
    monkeypatch.delenv("TUNNELSCOPE_NVD_API_KEY", raising=False)
    calls = []

    def fake(url, **kw):
        calls.append(url)
        if "services.nvd.nist.gov" in url:
            return json.loads((FIX / "nvd_strongswan.json").read_text()) if "strongswan" in url else \
                {"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 0}
        if "euvdservices" in url:
            return json.loads((FIX / "euvd_strongswan.json").read_text()) if "strongswan" in url else {"items": [], "total": 0}
        if "known_exploited" in url:
            return json.loads((FIX / "cisa_kev.json").read_text())
        raise AssertionError(url)
    monkeypatch.setattr(net, "http_json", fake)
    return calls


def test_merges_nvd_euvd_by_cve_and_labels_the_match(served):
    r = L.lookup("strongSwan")
    by = {e["id"]: e for e in r["cves"]}
    assert by["CVE-2023-41913"]["match"] == "cpe" and by["CVE-2023-41913"]["ipsec_related"]
    assert by["CVE-2026-25998"]["match"] == "keyword"               # strongMan: only mentions strongSwan
    assert by["CVE-2026-78135"]["sources"] == ["euvd"] and by["CVE-2026-78135"]["epss"] is not None
    assert r["status"] == "INFERRED" and "never its version" in r["note"]
    assert [e["match"] for e in r["cves"]].index("keyword") > [e["match"] for e in r["cves"]].index("cpe")


def test_kev_flags_actively_exploited_for_the_right_vendor_only(served):
    m = L.lookup("MikroTik RouterOS")
    assert m["counts"]["kev"] == 2 and all(e["kev"] for e in m["cves"][:2])
    assert not any("fortinet" in (e["description"] or "").lower() for e in m["cves"])


def test_second_lookup_uses_the_cache(served):
    L.lookup("strongSwan")
    n = len(served)
    r = L.lookup("strongSwan")
    assert len(served) == n and {v["status"] for v in r["sources"].values()} == {"cached"}


def test_network_off_serves_stale_cache_labelled_and_never_calls(served, monkeypatch):
    L.lookup("strongSwan")
    for p in Path(L.cache_dir()).glob("*.json"):           # age the cache past its TTL
        d = json.loads(p.read_text())
        d["fetched_at"] -= L.TTL_S + 60
        p.write_text(json.dumps(d))
    monkeypatch.setenv(net.ENV, "off")
    n = len(served)
    r = L.lookup("strongSwan")
    assert len(served) == n and {v["status"] for v in r["sources"].values()} == {"stale-offline"}
    assert r["counts"]["total"] > 0


def test_network_off_and_no_cache_is_unavailable_not_empty_success(monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNELSCOPE_INTEL_DIR", str(tmp_path / "empty"))
    monkeypatch.setenv(net.ENV, "off")
    r = L.lookup("strongSwan")
    assert {v["status"] for v in r["sources"].values()} == {"unavailable"}
    assert all("network is off" in v["reason"] for v in r["sources"].values())


def test_http_json_refuses_when_the_network_is_off(monkeypatch):
    monkeypatch.setenv(net.ENV, "off")
    with pytest.raises(net.NetworkDisabled):
        net.http_json("https://example.org")


def test_every_source_states_its_owner_licence_and_attribution():
    for sid, s in SOURCES.items():
        assert s["owner"] and s["licence"] and s["attribution"] and "licence_verified" in s, sid
        assert not (s["redistributable"] and not s["licence_verified"]), sid
    assert set(PRODUCTS) == {"strongSwan", "Libreswan", "MikroTik RouterOS"}   # the EXP-29 fingerprints


def test_mitre_mapping_matches_the_verified_snapshot():
    snap = json.loads((ROOT / "tunnelscope" / "risk" / "data" / "mitre_names.json").read_text())["names"]
    for tid, refs in THREAT_REFS.items():
        for i, name in refs:
            assert snap[i] == name, (tid, i)
    assert refs_for("TH-03")[0] == {"id": "T1557", "name": "Adversary-in-the-Middle", "catalogue": "ATT&CK"}
    assert set(THREAT_REFS) == {f"TH-{i:02d}" for i in range(1, 13)}


def _serve():
    import threading
    from tunnelscope.api import server
    srv = server.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_api_intel_returns_the_lookup_for_a_fingerprinted_implementation(served):
    import urllib.request
    srv, base = _serve()
    try:
        r = json.load(urllib.request.urlopen(base + "/api/intel?implementation=strongSwan"))
        assert r["ok"] and r["status"] == "INFERRED" and r["counts"]["total"] == 4
    finally:
        srv.shutdown()


def test_api_intel_refuses_anything_but_a_known_implementation(served):
    import urllib.error
    import urllib.request
    srv, base = _serve()
    try:
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/api/intel?implementation=../../etc")
        assert e.value.code == 400 and served == []          # nothing was looked up
    finally:
        srv.shutdown()


# ------------------------------------------------------------------ DEC-045: on every analysis

def _json(path):
    from tunnelscope.api.server import analysis_json
    from tunnelscope.report.report import analyze
    return analysis_json(analyze(str(path)), path.name)


def test_the_network_is_on_by_default(monkeypatch):
    monkeypatch.delenv(net.ENV, raising=False)
    assert net.network_enabled() is True
    monkeypatch.setenv(net.ENV, "off")
    assert net.network_enabled() is False


def test_every_analysis_carries_known_vulnerabilities_and_they_change_no_verdict(served, monkeypatch):
    cap = ROOT / "testbed" / "captures" / "pq-downgrade.pcap"
    with_intel = _json(cap)["sas"][0]
    kv = with_intel["known_vulnerabilities"]
    assert kv["status"] == "INFERRED" and "some version" in kv["note"].lower()
    p = kv["products"][0]
    assert p["implementation"] == "strongSwan" and p["ends"] == ["initiator", "responder"]
    assert p["counts"]["total"] == 4 and len(p["top"]) <= L.TOP_N and p["sources"]["nvd"] == "fresh"
    monkeypatch.setenv(net.ENV, "off")                                  # same capture, no intel at all
    monkeypatch.setenv("TUNNELSCOPE_INTEL_DIR", str(Path(L.cache_dir()).parent / "empty"))
    without = _json(cap)["sas"][0]
    assert without["known_vulnerabilities"]["products"][0]["sources"]["nvd"] == "unavailable"
    assert with_intel["verdicts"] == without["verdicts"]
    assert with_intel["risk"]["risk"]["score"] == without["risk"]["risk"]["score"]


def test_no_fingerprint_means_no_lookup_and_says_so(served):
    kv = L.known_vulnerabilities({})
    assert kv["status"] == "UNKNOWN" and kv["products"] == [] and served == []


def test_a_source_that_fails_is_not_retried_on_every_analysis(monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNELSCOPE_INTEL_DIR", str(tmp_path))
    monkeypatch.setenv(net.ENV, "on")
    calls = []

    def down(url, **kw):
        calls.append((url, kw.get("timeout")))
        raise OSError("connection refused")
    monkeypatch.setattr(net, "http_json", down)
    monkeypatch.setattr(L, "_FAILED", {})
    L.known_vulnerabilities({"implementation": {"status": "INFERRED", "value": {"initiator": "strongSwan"}}})
    n = len(calls)
    assert n == 3 and all(t == L.AUTO_TIMEOUT_S for _, t in calls)      # NVD, EUVD, KEV: each once, short timeout
    r = L.known_vulnerabilities({"implementation": {"status": "INFERRED", "value": {"initiator": "strongSwan"}}})
    assert len(calls) == n                                               # not retried within RETRY_AFTER_S
    assert set(r["products"][0]["sources"].values()) == {"unavailable"}
