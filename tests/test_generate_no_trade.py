"""T-138 / EXP-31: V6 also refuses a draft that makes another active rule on the same line fail that does not fail
now (EXP-18b T9: fixing RFC8247-DH-MUST with MODP-3072 broke DISA's group >= 16), before anything touches the lab,
and tells the model which rule and which keywords satisfy both."""
from fake_model import FakeModel, answer
from test_generate import A, make_lab

from tunnelscope.remediate import generate as gen

T9_LINE = "aes256-sha256-modp1024s160"
TRADE = answer("proposals", [{"op": "replace", "from": "modp1024s160", "to": "modp3072"}], "proposals = aes256-sha256-modp3072")
BOTH = answer("proposals", [{"op": "replace", "from": "modp1024s160", "to": "modp4096"}], "proposals = aes256-sha256-modp4096")


def test_a_trade_is_refused_at_v6_before_the_dry_run(monkeypatch, tmp_path):
    make_lab(monkeypatch, tmp_path, proposals=T9_LINE)
    FakeModel([TRADE]).install(monkeypatch)
    r = gen.generate_plan("RFC8247-DH-MUST", A, force=True)
    assert r["ok"] is False and r["stage"] == "V6", r
    assert "V-207193" in r["reason"] and "MODP-3072" in r["reason"]
    assert "DRY" not in [c["id"] for c in r["checks"]]                # never reached the dry run


def test_the_conflict_is_fed_back_and_a_fix_satisfying_both_is_accepted(monkeypatch, tmp_path):
    make_lab(monkeypatch, tmp_path, proposals=T9_LINE)
    m = FakeModel([TRADE, BOTH]).install(monkeypatch)
    r = gen.generate_plan("RFC8247-DH-MUST", A, force=True, critique_rounds=1)
    assert r["ok"] is True, r
    fb = m.calls[1]["blocks"]["checks_that_failed"]
    assert "not make V-207193 fail" in fb and "modp4096" in fb, fb
    assert "modp3072" not in fb.split("satisfy", 1)[-1]                # suggested keywords satisfy both rules
    assert r["plan"]["new_value"].endswith("modp4096")


def test_a_rule_already_failing_is_not_a_conflict():
    # V-207193 fails on MODP-2048 before and after an integrity change: that is not a new failure
    assert gen.other_rule_conflicts("V-207223", "proposals", "aes256-sha256-modp2048", "aes256-sha384-modp2048") == []


def test_a_weaker_integrity_while_fixing_the_group_is_a_conflict():
    c = gen.other_rule_conflicts("V-207193", "proposals", "aes256-sha384-modp2048", "aes256-sha256-modp4096")
    assert [i for i, _ in c] == ["V-207223"]


def test_rules_v6_cannot_judge_from_the_line_are_left_to_the_live_check():
    # RFC8247-DH-OFFER judges the offered groups; rule_outcome cannot, so V6 never claims it passes or fails
    for new in ("aes256-sha256-modp1024", "aes256-sha256-modp4096"):
        ids = [i for i, _ in gen.other_rule_conflicts("V-207223", "proposals", "aes256-sha256-modp2048", new)]
        assert "RFC8247-DH-OFFER" not in ids
