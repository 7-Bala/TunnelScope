"""T-107: after a confirmed fix the tunnel is forced to rekey. It must still be up afterwards
(endpoint-reported), or the change is rolled back. What the rekey negotiated is encrypted on the
wire, so the passive result is NOT_OBSERVABLE; the daemon's own report is shown, labelled, and
never used as evidence for the verdict."""
import pytest
from fake_lab import ALICE_CONF, FakeLab, sas

from tunnelscope.remediate import execute
from tunnelscope.remediate.execute import apply_remediation, rekey_check

A, FA = "sih26-alice-pq", "/tmp/exp15-alice.conf"


@pytest.fixture
def lab(monkeypatch, tmp_path):
    return FakeLab(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "PASS"})).install(monkeypatch, tmp_path)


def test_confirmed_fix_survives_a_rekey_and_says_what_is_and_is_not_evidence(lab, tmp_path):
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path)
    assert r["confirmed_fixed"] is True, r
    rk = r["rekey"]
    assert rk["passive"] == "NOT_OBSERVABLE" and "encrypted" in rk["note"] and "never as evidence" in rk["note"]
    assert rk["tunnel_after_rekey"] is True and rk["rekeyed"] is True
    assert rk["endpoint_reported"] == {"algorithms": ["AES_CBC_256", "HMAC_SHA2_256_128", "PRF_HMAC_SHA2_256", "MODP_4096"],
                                       "rule_verdict": "PASS"}
    assert lab.rekeys == ["--ike", "--child"]


def test_a_tunnel_that_does_not_survive_the_rekey_is_rolled_back(lab, tmp_path):
    lab.rekey_outcome = "down"
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path)
    assert r["confirmed_fixed"] is False and r["verdict_after"] == "REGRESSION"
    assert "did not survive a forced rekey" in r["reason"]
    assert r["rolled_back"] is True and r["rollback_verified"] is True
    assert lab.fs[A][FA] == ALICE_CONF


def test_the_endpoint_report_is_information_only(lab, tmp_path):
    """If the daemon says the rekey chose a weak group, that is shown, but the verdict stays the
    passive one: the endpoint's word is not evidence."""
    lab.sa_fields = lab.sa_fields.replace("MODP_4096", "MODP_1024")
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path)
    assert r["confirmed_fixed"] is True
    assert r["rekey"]["endpoint_reported"]["rule_verdict"] == "FAIL"


def test_unreadable_sa_report_is_treated_as_down(lab, monkeypatch, tmp_path):
    real = lab.run

    def garbled(cmd, *a, **k):
        if cmd[:2] == ["docker", "exec"] and "--list-sas" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "???", "stderr": ""})()
        return real(cmd, *a, **k)
    monkeypatch.setattr(execute.subprocess, "run", garbled)
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path)
    assert r["confirmed_fixed"] is False and r["rolled_back"] is True


def test_no_rekey_when_the_fix_is_not_confirmed(monkeypatch, tmp_path):
    lab = FakeLab(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "FAIL"})).install(monkeypatch, tmp_path)
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path)
    assert r["confirmed_fixed"] is False and r["rekey"] is None and lab.rekeys == []


def test_endpoint_verdict_is_unknown_for_algorithms_never_observed(lab):
    lab.sa_fields = lab.sa_fields.replace("MODP_4096", "MODP_8192")
    assert rekey_check(A, "V-207193")["endpoint_reported"]["rule_verdict"] == "UNKNOWN"
    # a rule the IKE SA does not carry at all
    assert rekey_check(A, "RFC8221-ESP-3DES")["endpoint_reported"]["rule_verdict"] == "UNKNOWN"


def test_rekey_commands_are_fixed_argument_lists():
    assert execute._REKEY_ARGV == (["swanctl", "--rekey", "--ike", "t-tun"], ["swanctl", "--rekey", "--child", "t-tun"])
