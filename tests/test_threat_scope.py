"""T-122 part 1 / DEC-039: the matrix scores only what a capture can decide; the rest is listed, never scored.
The CNSA 2.0 IPsec baseline quotes draft-guthrie-cnsa2-ipsec-profile-04; its ESP rule can never PASS."""
from pathlib import Path

import pytest

from tunnelscope.assess.engine import _assert, assess_record, available_profiles, load_baselines
from tunnelscope.evidence.extract import build_records
from tunnelscope.risk.risk import OUT_OF_SCOPE, assess_risk

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"


def _rec(path):
    return next(r for r in build_records(str(CAP / path)) if getattr(r, "_ike", []))


def test_out_of_scope_risks_are_listed_with_reason_and_where_to_check():
    r = _rec("cs-aes256gcm16.pcap")
    out = assess_risk(r, assess_record(r, load_baselines()))
    assert out["out_of_scope"] == OUT_OF_SCOPE and len(OUT_OF_SCOPE) >= 9
    for o in out["out_of_scope"]:
        assert o["name"] and o["why"] and o["check_with"]
    threat_names = {t["name"].lower() for t in out["threats"]}
    assert not threat_names & {o["name"].lower() for o in OUT_OF_SCOPE}   # listed OR scored, never both


def test_out_of_scope_never_changes_the_score():
    r = _rec("cs-aes256gcm16.pcap")
    v = assess_record(r, load_baselines())
    before = assess_risk(r, v)["risk"]["score"]
    import tunnelscope.risk.risk as rk
    saved = list(rk.OUT_OF_SCOPE)
    rk.OUT_OF_SCOPE.clear()
    try:
        assert assess_risk(r, v)["risk"]["score"] == before
    finally:
        rk.OUT_OF_SCOPE.extend(saved)


def _cnsa(path):
    r = _rec(path)
    return {v.rule_id: v.verdict for v in assess_record(r, load_baselines(profiles=["cnsa2-ipsec"]))
            if v.rule_id.startswith("CNSA2")}


def test_cnsa2_is_opt_in_so_default_reports_do_not_change():
    ids = {r["id"] for b in load_baselines() for r in b["rules"]}
    assert not any(i.startswith("CNSA2") for i in ids)
    assert "cnsa2-ipsec" in available_profiles()


def test_unknown_profile_is_refused():
    from tunnelscope.errors import DependencyError
    with pytest.raises(DependencyError):
        load_baselines(profiles=["nope"])


def test_cnsa2_ike_suite_passes_only_on_the_profile_suite():
    v = _cnsa("exp15/s-ecp384.pcap")        # aes256gcm16-prfsha384-ecp384
    assert v["CNSA2-IKE-ENCR"] == v["CNSA2-IKE-PRF"] == v["CNSA2-IKE-KE"] == "PASS"
    assert v["CNSA2-ADDKE"] == "FAIL"        # no ML-KEM-1024
    w = _cnsa("cs-aes256gcm16.pcap")         # aes256-sha256-modp2048
    assert w["CNSA2-IKE-ENCR"] == w["CNSA2-IKE-PRF"] == w["CNSA2-IKE-KE"] == "FAIL"


@pytest.mark.parametrize("path", ["exp15/s-mlkem.pcap", "pq-mlkem768.pcap"])
def test_ml_kem_768_does_not_meet_the_1024_requirement(path):
    assert _cnsa(path)["CNSA2-ADDKE"] == "FAIL"


def test_cnsa2_esp_and_auth_are_never_passed_from_the_wire():
    for p in ("cs-aes256gcm16.pcap", "exp15/s-ecp384.pcap", "cs-aes256cbc-sha256.pcap"):
        v = _cnsa(p)
        assert v["CNSA2-ESP-ENCR"] in ("UNKNOWN", "FAIL") and v["CNSA2-AUTH"] == "NOT_OBSERVABLE", (p, v)


def test_candidate_required_can_fail_but_never_pass():
    assert _assert("candidate_required", "AES-GCM-16", ["AES-CBC+HMAC-SHA256-128"]) is False
    assert _assert("candidate_required", "AES-GCM-16", ["AES-GCM-16", "AES-CCM-16"]) is None
    assert _assert("candidate_required", "AES-GCM-16", ["AES-GCM-16"]) is None
