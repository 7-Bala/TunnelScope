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
