"""EXP-30 prompt P3: with other_rules on, the model also sees the other active rules judged on the line it may
edit, and one system-prompt sentence not to make any of them fail. Off, the prompt is P0 byte for byte."""
from fake_model import FakeModel, answer
from test_generate import A, make_lab

from tunnelscope.remediate import generate as gen

GOOD = answer("proposals", [{"op": "replace", "from": "modp2048", "to": "modp4096"}], "proposals = aes256-sha256-modp4096")
BAD_V4 = answer("proposals", [{"op": "replace", "from": "modp2048", "to": "modp3076"}], "proposals = aes256-sha256-modp3076")


def test_off_is_p0_exactly(monkeypatch, tmp_path):
    make_lab(monkeypatch, tmp_path)
    m = FakeModel([GOOD]).install(monkeypatch)
    r = gen.generate_plan("V-207193", A, force=True)
    assert r["ok"] is True, r
    assert m.calls[0]["system"] == gen.SYSTEM_PROMPT
    assert "other_active_rules" not in m.calls[0]["blocks"]
    assert "other_rules" not in r["plan"]["settings"]


def test_on_shows_the_other_rules_of_the_same_line_and_the_instruction(monkeypatch, tmp_path):
    make_lab(monkeypatch, tmp_path)
    m = FakeModel([BAD_V4, GOOD]).install(monkeypatch)
    r = gen.generate_plan("V-207193", A, force=True, critique_rounds=1, other_rules=True)
    assert r["ok"] is True, r
    for call in m.calls:                                               # every round, not only the first
        block = call["blocks"]["other_active_rules"]
        ids = [line.split(" ", 1)[0] for line in block.splitlines()]
        assert "RFC8247-DH-MUST" in ids and "V-207223" in ids          # same proposals line
        assert "V-207193" not in ids                                   # never the rule itself
        assert not any(i.startswith(("RFC8221", "V-207205")) for i in ids)   # ESP/AH/version lines: not editable here
        assert call["system"] == gen.SYSTEM_PROMPT + "\n" + gen.OTHER_RULES_SENTENCE
    assert r["plan"]["settings"]["other_rules"] is True


def test_the_t9_conflict_is_visible_to_the_model():
    """EXP-18b T9: fixing RFC8247-DH-MUST with MODP-2048/3072 broke DISA's group >= 16. P3 shows that rule."""
    shown = gen.other_active_rules("RFC8247-DH-MUST")
    v = next(line for line in shown if line.startswith("V-207193 "))
    assert '"dh_group_ge"' in v and "16" in v


def test_a_line_with_no_other_rules_adds_nothing(monkeypatch, tmp_path):
    assert gen.other_active_rules("V-207205") == []
    assert gen.other_active_rules("RFC8221-ESP-3DES") == []
