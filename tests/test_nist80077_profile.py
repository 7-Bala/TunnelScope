"""T-122 part 2 / EXP-35: NIST SP 800-77r1 as an opt-in rules profile. The expected verdicts below are the ones
pre-registered in experiments/exp35-nist-800-77r1-profile/PREREG.md (H3), on real captures."""
from pathlib import Path

import pytest
import yaml

from tunnelscope.assess.engine import RULES_DIR, _assert, assess_record, available_profiles, load_baselines
from tunnelscope.evidence.extract import build_records
from tunnelscope.explain import explain as ex

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
PROFILE = "nist-sp800-77r1"
ORDER = ["NIST77-IKE-VERSION", "NIST77-IKE-ENCR", "NIST77-IKE-PRF", "NIST77-IKE-INTEG", "NIST77-DH-APPROVED",
         "NIST77-DH-RECOMMENDED", "NIST77-PFS", "NIST77-AH", "NIST77-ESP-ENCR", "NIST77-ESP-INTEG", "NIST77-AUTH"]
V = {"P": "PASS", "F": "FAIL", "U": "UNKNOWN", "N": "NOT_OBSERVABLE", "-": None}

# PREREG H3 table, row by row (- = no verdict: the rule applies to ESP only)
H3 = {
    "exp15/s-ecp256.pcap":   "P P P U P P U P U U N",
    "exp15/s-3des.pcap":     "P F F F F F F P U U N",
    "exp15/s-x25519.pcap":   "P P P P P F U P U U N",
    "exp15/s-modp1536.pcap": "P P P P F F F P U U N",
    "exp15/s-modp4096.pcap": "P P P P P P P P U U N",
    # Superseded by DEC-051 / EXP-40 (owner-approved 2026-10-02): the PREREG row was "F U U U U U N P U U N" because the
    # IKEv1 suite was unreadable then. It is read now and agrees with strongSwan's own swanctl output for this capture
    # (AES_CBC-128 / PRF_HMAC_SHA1 / MODP_1024): cipher PASS, SHA-1 PRF FAIL, group 2 FAIL, integ stays UNKNOWN (IKEv1 has none).
    "cloud/c-v1.pcap":       "F P F U F F N P U U N",
    "cloud/c-w.pcap":        "P P F F F F N P U U N",
    "exp15/a-tra-sha1.pcap": "P P P P P P F F - - N",
    "exp07/e7-pfs-on.pcap":  "P P P P P P P P U U N",
    "a7-cs-aes256gcm16.pcap": "U U U U U U N P U U U",
}


def _nist(path):
    recs = build_records(str(CAP / path))
    assert len(recs) == 1, (path, len(recs))
    return {v.rule_id: v.verdict for v in assess_record(recs[0], load_baselines(profiles=[PROFILE]))
            if v.rule_id.startswith("NIST77")}


def _profile_rules():
    with open(Path(RULES_DIR) / "profiles" / f"{PROFILE}.yaml") as fh:
        return yaml.safe_load(fh)["rules"]


def test_profile_is_opt_in_so_default_reports_do_not_change():
    ids = {r["id"] for b in load_baselines() for r in b["rules"]}
    assert not any(i.startswith("NIST77") for i in ids)
    assert PROFILE in available_profiles()
    assert [r["id"] for r in _profile_rules()] == ORDER


@pytest.mark.parametrize("path", sorted(H3))
def test_preregistered_verdicts_on_real_captures(path):
    got = _nist(path)
    want = {rid: V[c] for rid, c in zip(ORDER, H3[path].split())}
    assert {rid: got.get(rid) for rid in ORDER} == want


def test_every_rule_carries_its_source_text():
    for r in _profile_rules():
        assert r.get("section") and r.get("page"), r["id"]
        assert isinstance(r.get("quote"), list) and r["quote"] and all(isinstance(q, str) and len(q) > 10
                                                                      for q in r["quote"]), r["id"]


def test_every_profile_rule_has_a_plain_explanation():
    for name in available_profiles():
        ids = {r["id"] for r in load_baselines(profiles=[name])[-1]["rules"]}
        assert ids <= set(ex.GLOSSARY), (name, sorted(ids - set(ex.GLOSSARY)))


def test_not_contains_fails_on_the_item_and_never_passes_a_non_list():
    assert _assert("not_contains", "AH", ["ESP"]) is True
    assert _assert("not_contains", "AH", ["AH"]) is False
    assert _assert("not_contains", "AH", ["ESP", "AH"]) is False       # AH+ESP is still AH
    assert _assert("not_contains", "AH", None) is None
    assert _assert("not_contains", "AH", "ESP") is None


def test_esp_rules_fail_only_when_every_candidate_is_outside_the_recommended_list():
    r = {x["id"]: x["assert"] for x in _profile_rules()}
    enc, integ = r["NIST77-ESP-ENCR"], r["NIST77-ESP-INTEG"]
    assert _assert(enc["op"], enc["value"], ["3DES-CBC+HMAC-SHA1-96", "DES-CBC+HMAC-96"]) is False
    assert _assert(enc["op"], enc["value"], ["AES-GCM-16", "ChaCha20-Poly1305"]) is None
    assert _assert(enc["op"], enc["value"], ["AES-CBC+HMAC-SHA256-128"]) is True
    assert _assert(integ["op"], integ["value"], ["AES-CBC+HMAC-SHA1-96", "NULL+HMAC-96"]) is False
    assert _assert(integ["op"], integ["value"], ["AES-CBC+HMAC-SHA256-128", "AES-GCM-16"]) is True
