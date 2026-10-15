"""T-122 part 4 / EXP-54: every rule cites verified source text, and adding that text changed nothing the engine reads.
The quotes themselves are checked against the hashed source files by experiments/exp54-rule-sources/analyze.py; this file pins the
structure, the disclosed gaps, and the 21 rules' engine-visible fields (a changed severity or assertion must be a visible decision)."""
import glob
import hashlib
import json
import os
import re
from pathlib import Path

import pytest
import yaml

from tunnelscope.assess.engine import RULES_DIR

SRC = Path(os.path.expanduser("~/Datasets/sources/part4"))
FILES = ["cve-2026-78135.yaml", "disa-vpn-srg-v2r6.yaml", "rfc8221-4303-ipsec.yaml", "rfc8247-ikev2.yaml", "profiles/cnsa2-ipsec.yaml"]

# the 21 rules exactly as they were before this experiment added source fields: (attribute, assertion, severity, applies_to_*)
BEFORE = {
    "CVE-2026-78135": ("early_childsa_cve", {"op": "not_equals", "value": "early-child-sa-before-auth"}, "high", {}),
    "CVE-WATCH-KE-MALFORMED": ("ke_payload_anomaly", {"op": "not_equals", "value": "malformed-ke"}, "high", {}),
    "CVE-WATCH-INFO-BEFORE-AUTH": ("informational_before_auth", {"op": "not_equals", "value": "informational-before-auth"}, "high", {}),
    "CVE-WATCH-INIT-PAYLOADS": ("init_missing_payloads", {"op": "not_equals", "value": "init-missing-required-payload"}, "high", {}),
    "V-207205": ("ike_version", {"op": "equals", "value": "IKEv2"}, "high", {}),
    "V-207193": ("ike_dh_group", {"op": "dh_group_ge", "value": 16}, "high", {}),
    "V-207223": ("ike_integ", {"op": "in", "value": ["HMAC-SHA2-384-192", "HMAC-SHA2-512-256"]}, "medium", {}),
    "RFC4301-CONFIDENTIALITY": ("ipsec_protocols", {"op": "contains", "value": "ESP"}, "medium", {}),
    "RFC8221-AH-INTEG": ("ah_integrity", {"op": "candidates_not_all_in", "value": ["HMAC-MD5-96"]}, "high", {"applies_to_protocol": "AH"}),
    "RFC8221-AH-LEGACY": ("ah_integrity", {"op": "candidates_none_in", "value": ["HMAC-MD5-96", "HMAC-SHA1-96", "AES-XCBC-96"]}, "informational", {"applies_to_protocol": "AH"}),
    "RFC8221-ESP-3DES": ("esp_cipher_family", {"op": "candidates_not_all_in", "value": ["3DES-CBC+HMAC-SHA1-96"]}, "medium", {"applies_to_protocol": "ESP"}),
    "RFC4303-SEQ": ("sequence_integrity", {"op": "seq_clean"}, "high", {}),
    "RFC8247-DH-MUST": ("ike_dh_group", {"op": "dh_group_not_in", "value": [1, 2, 5, 22, 23, 24]}, "high", {"applies_to_ike_version": "IKEv2"}),
    "RFC8247-DH-OFFER": ("ike_offered_dh", {"op": "dh_groups_none_in", "value": [1, 2, 5, 22, 23, 24]}, "medium", {"applies_to_ike_version": "IKEv2"}),
    "RFC8247-ENCR": ("ike_encr", {"op": "matches_any", "value": ["AES-GCM", "AES-CBC", "ChaCha20"]}, "medium", {"applies_to_ike_version": "IKEv2"}),
    "CNSA2-IKE-ENCR": ("ike_encr", {"op": "equals", "value": "AES-GCM-16-256"}, "high", {}),
    "CNSA2-IKE-PRF": ("ike_prf", {"op": "in", "value": ["PRF-HMAC-SHA2-384", "PRF-HMAC-SHA2-512"]}, "high", {}),
    "CNSA2-IKE-KE": ("ike_dh_group", {"op": "in", "value": ["ECP-384", "MODP-3072", "MODP-4096"]}, "high", {}),
    "CNSA2-ADDKE": ("pq_key_exchange", {"op": "contains", "value": "ML-KEM-1024"}, "high", {}),
    "CNSA2-ESP-ENCR": ("esp_cipher_family", {"op": "candidate_required", "value": "AES-GCM-16"}, "high", {}),
    "CNSA2-AUTH": ("peer_auth_method", {"op": "equals", "value": "ML-DSA-87"}, "high", {}),
}

# a gap between source and rule that the PREREG disclosed: these words must stay in that rule's note
NOTE_WORDS = {
    "V-207205": ["Medium (CAT II)", "severity is high", "mirror"],
    "V-207193": ["all IKE proposals", "negotiated"],
    "V-207223": ["High (CAT I)", "severity is medium", "SHA-1"],
    "RFC8247-ENCR": ["ENCR_3DES", "AES-CCM-8", "AES-CBC"],
    "RFC8247-DH-OFFER": ["does not say", "project's"],
    "RFC4301-CONFIDENTIALITY": ["does not forbid AH-only", "project's"],
    "RFC8221-AH-LEGACY": ["does not say", "informational", "packet geometry"],
    "RFC4303-SEQ": ["cycling", "replayed or duplicated"],
    "CVE-2026-78135": ["6.1.0", "release notes", "no fix version"],
    "CVE-WATCH-KE-MALFORMED": ["examples", "not shown to be an exploit"],
    "CVE-WATCH-INFO-BEFORE-AUTH": ["Libreswan 3.27", "not a product or version"],
    "CVE-WATCH-INIT-PAYLOADS": ["does not use the words", "Libreswan"],
}


def _load(rel):
    with open(Path(RULES_DIR) / rel) as fh:
        return yaml.safe_load(fh)


def _all_rules():
    for f in sorted(glob.glob(os.path.join(RULES_DIR, "*.yaml")) + glob.glob(os.path.join(RULES_DIR, "profiles", "*.yaml"))):
        for r in yaml.safe_load(open(f))["rules"]:
            yield os.path.relpath(f, RULES_DIR), r


def test_every_rule_in_every_file_cites_its_source_text():
    n = 0
    for rel, r in _all_rules():
        n += 1
        assert r.get("section") and r.get("page"), (rel, r["id"])
        assert isinstance(r.get("quote"), list) and r["quote"], (rel, r["id"])
        assert all(isinstance(q, str) and q for q in r["quote"]), (rel, r["id"])
        assert len(set(r["quote"])) == len(r["quote"]), (rel, r["id"])
        if rel in FILES:                    # EXP-54 pre-registered a 20-character floor for its own 21 rules
            assert all(len(q) >= 20 for q in r["quote"]), (rel, r["id"])
    assert n >= 43                      # 22 rules sourced by EXP-35/53 and 21 by this experiment


@pytest.mark.parametrize("rel", FILES)
def test_sources_map_names_every_source_with_a_sha256(rel):
    doc = _load(rel)
    smap = doc["sources"]
    assert smap
    for key, ent in smap.items():
        assert set(ent) == {"file", "url", "sha256"}, key
        assert re.fullmatch(r"[0-9a-f]{64}", ent["sha256"]), key
        assert ent["url"].startswith("https://"), key
    used = {k for r in doc["rules"] for k in r["source"]}
    assert used == set(smap), (rel, used ^ set(smap))


def test_the_21_rules_still_judge_exactly_what_they_judged():
    seen = {}
    for rel in FILES:
        for r in _load(rel)["rules"]:
            extra = {k: v for k, v in r.items() if k in ("applies_to_protocol", "applies_to_ike_version")}
            seen[r["id"]] = (r["attribute"], r["assert"], r["severity"], extra)
    assert seen == BEFORE


@pytest.mark.parametrize("rid", sorted(NOTE_WORDS))
def test_disclosed_gaps_stay_written_down(rid):
    rule = next(r for rel in FILES for r in _load(rel)["rules"] if r["id"] == rid)
    for w in NOTE_WORDS[rid]:
        assert w in rule.get("note", ""), (rid, w)


@pytest.mark.skipif(not SRC.is_dir(), reason="the hashed source files live outside the repository (~/Datasets/sources/part4)")
@pytest.mark.parametrize("rel", FILES)
def test_source_files_on_disk_match_the_recorded_hashes(rel):
    for key, ent in _load(rel)["sources"].items():
        assert hashlib.sha256((SRC / ent["file"]).read_bytes()).hexdigest() == ent["sha256"], key


def _analyze():
    import importlib.util
    spec = importlib.util.spec_from_file_location("exp54_analyze", Path(__file__).resolve().parents[1] / "experiments" / "exp54-rule-sources" / "analyze.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.skipif(not SRC.is_dir(), reason="the hashed source files live outside the repository (~/Datasets/sources/part4)")
@pytest.mark.parametrize("rel", FILES)
def test_quotes_are_verbatim_and_on_the_declared_pages(rel):
    """The same rule the scorer applies (H2, H3), so a changed quote or page fails here when the sources are on disk."""
    a = _analyze()
    doc = _load(rel)
    cache = {k: a.pages(a.kind_of(e["file"]), str(SRC / e["file"])) for k, e in doc["sources"].items()}
    for r in doc["rules"]:
        declared = set() if r["page"] == "n/a" else {(s.split(":")[0].strip(), int(n)) for s in r["page"].split(";") for n in s.split(":")[1].split(",")}
        reached = set()
        for q in r["quote"]:
            hits = {(k, p) for k in r["source"] for p, t in cache[k] if a.normalise(q) in t}
            assert hits, (r["id"], "quote not found in its sources", q[:60])
            paged = {h for h in hits if h[1] is not None}
            if not declared:
                assert not paged, (r["id"], "page is n/a but the quote is in a paged source")
            else:
                assert paged & declared or len(paged) < len(hits), (r["id"], "no hit on a declared page", q[:60])
            reached |= paged & declared
        assert reached == declared, (r["id"], sorted(declared - reached))
