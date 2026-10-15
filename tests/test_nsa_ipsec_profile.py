"""T-122 part 3 / EXP-53: NSA's "Configuring IPsec Virtual Private Networks" (ver. 1.3, Feb 2025) as an opt-in rules profile, and
verified source text on the DST/NQM baseline. The expected verdicts below are the ones pre-registered in
experiments/exp53-nsa-dst-profile/PREREG.md (H3), on real captures."""
from pathlib import Path

import pytest
import yaml

from tunnelscope.assess.engine import RULES_DIR, assess_record, available_profiles, load_baselines
from tunnelscope.evidence.extract import build_records
from tunnelscope.explain import explain as ex

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
PROFILE = "nsa-ipsec-config"
ORDER = ["NSA-IKE-DH-EXAMPLE", "NSA-IKE-ENCR-EXAMPLE", "NSA-IKE-PRF-EXAMPLE", "NSA-IKE-INTEG-EXAMPLE", "NSA-ESP-SUITE-EXAMPLE",
         "NSA-IKE-OUTDATED-ENCR", "NSA-IKE-OUTDATED-DH", "NSA-OFFER-OUTDATED-DH", "NSA-ESP-OUTDATED"]
V = {"P": "PASS", "F": "FAIL", "U": "UNKNOWN", "-": None}

# PREREG H3 table, row by row (- = no verdict: the rule applies only to ESP)
H3 = {
    "exp15/s-ecp256.pcap":    "F F F U F P P P P",
    "exp15/s-3des.pcap":      "F F F F F F F F U",
    "exp15/s-x25519.pcap":    "F P F F F P P P P",
    "exp15/s-modp1536.pcap":  "F F F F F P F F U",
    "exp15/s-modp4096.pcap":  "P P P P F P P P P",
    "cloud/c-v1.pcap":        "F F F U F P F U U",
    "cloud/c-w.pcap":         "F F F F F P F F U",
    "exp15/a-tra-sha1.pcap":  "F P F F - P P P -",
    "exp07/e7-pfs-on.pcap":   "F P F F F P P P P",
    "a7-cs-aes256gcm16.pcap": "U U U U F U U U P",
}

# the two DST rules exactly as they were before this experiment added provenance fields
DST_BEFORE = {
    "DST-PQ-KE": ("pq_key_exchange", {"op": "pq_present"}, "informational",
                  "No post-quantum key exchange negotiated - quantum-vulnerable to Harvest-Now-Decrypt-Later (HNDL)"),
    "DST-PQ-DOWNGRADE": ("pq_key_exchange", {"op": "not_equals", "value": "offered-but-not-used"}, "high",
                         "PQ key exchange offered, classical selected - an insecure fallback under DST policy (cause not attributable passively)"),
}


def _nsa(path):
    recs = build_records(str(CAP / path))
    assert len(recs) == 1, (path, len(recs))
    return {v.rule_id: v.verdict for v in assess_record(recs[0], load_baselines(profiles=[PROFILE]))
            if v.rule_id.startswith("NSA-")}


def _profile_rules():
    with open(Path(RULES_DIR) / "profiles" / f"{PROFILE}.yaml") as fh:
        return yaml.safe_load(fh)["rules"]


def test_profile_is_opt_in_so_default_reports_do_not_change():
    ids = {r["id"] for b in load_baselines() for r in b["rules"]}
    assert not any(i.startswith("NSA-") for i in ids)
    assert PROFILE in available_profiles()
    assert [r["id"] for r in _profile_rules()] == ORDER


@pytest.mark.parametrize("path", sorted(H3))
def test_preregistered_verdicts_on_real_captures(path):
    got = _nsa(path)
    want = {rid: V[c] for rid, c in zip(ORDER, H3[path].split())}
    assert {rid: got.get(rid) for rid in ORDER} == want


def test_every_rule_carries_its_source_text():
    for r in _profile_rules():
        assert r.get("section") and r.get("page"), r["id"]
        assert isinstance(r.get("quote"), list) and r["quote"] and all(isinstance(q, str) and len(q) > 10 for q in r["quote"]), r["id"]


def test_examples_are_informational_and_outdated_algorithms_are_medium():
    sev = {r["id"]: r["severity"] for r in _profile_rules()}
    assert all(sev[i] == "informational" for i in ORDER[:5])          # "an example of a recommended ... setting"
    assert all(sev[i] == "medium" for i in ORDER[5:])                  # named as outdated / downgrade warning
    # an example mismatch must say it is only an example
    for r in _profile_rules()[:5]:
        assert "example" in r["fail_message"], r["id"]


def test_the_dst_baseline_keeps_its_rules_and_gains_verified_source_text():
    with open(Path(RULES_DIR) / "dst-nqm-pq.yaml") as fh:
        doc = yaml.safe_load(fh)
    rules = {r["id"]: r for r in doc["rules"]}
    assert list(rules) == list(DST_BEFORE)
    for rid, (attr, assertion, sev, msg) in DST_BEFORE.items():
        r = rules[rid]
        assert (r["attribute"], r["assert"], r["severity"], r["fail_message"]) == (attr, assertion, sev, msg), rid
        assert r.get("section") and r.get("page") and r.get("note"), rid
        assert isinstance(r["quote"], list) and r["quote"] and all(len(q) > 20 for q in r["quote"]), rid
    # the original (now dead) address stays recorded; the archived copy and the hash are in the file's header
    assert doc["url"].startswith("https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26")
    head = Path(RULES_DIR, "dst-nqm-pq.yaml").read_text().split("rules:")[0]
    assert "web.archive.org/web/20260926154852id_" in head
    assert "461d8b42aea3847a3f9083e369065eff7985b03f8e4b1e9974f236ce93d99f31" in head


def test_every_profile_rule_has_a_plain_explanation():
    ids = {r["id"] for r in load_baselines(profiles=[PROFILE])[-1]["rules"]}
    assert ids <= set(ex.GLOSSARY), sorted(ids - set(ex.GLOSSARY))
    for rid in ids:
        what, why, fix = ex.GLOSSARY[rid]
        assert what and why and fix, rid
