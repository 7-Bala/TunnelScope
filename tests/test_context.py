"""Mentor follow-up D: Indian regulatory context (tunnelscope/rules/context/india.yaml).

These guard the honesty of the mapping, not just its plumbing: evidence, never
a compliance verdict; real in-force dates; no rule that the instruments don't
actually ask for."""
import datetime as dt

from tunnelscope.assess.context import clause_evidence, executive_lines, load_context
from tunnelscope.assess.engine import Verdict, load_baselines


def _v(rule_id, verdict):
    return Verdict(baseline="b", authority="a", rule_id=rule_id, title="t", verdict=verdict,
                   severity="high", attribute="x")


def test_every_evidence_rule_is_a_real_baseline_rule():
    ids = {r["id"] for b in load_baselines() for r in b["rules"]}
    for c in load_context("india")["clauses"]:
        assert set(c["evidence_rules"]) <= ids, c["id"]


def test_never_claims_compliance():
    ctx = load_context("india")
    text = str(ctx).lower()
    assert "not a compliance verdict" in text
    assert "compliant" not in text and "complies" not in text


def test_post_quantum_rules_are_not_counted_as_dpdp_or_certin_evidence():
    """Neither instrument asks for PQ key exchange; that is the DST/NQM baseline's job."""
    for c in load_context("india")["clauses"]:
        assert not any(r.startswith("DST-") for r in c["evidence_rules"]), c["id"]


def test_dpdp_rule_6_commences_18_months_after_publication():
    """G.S.R. 846(E) of 13 Nov 2025, rule 1(4): rules 3, 5-16 in force eighteen months later."""
    ctx = load_context("india")
    r6 = [c for c in ctx["clauses"] if c["id"].startswith("DPDP-R6")]
    assert r6 and all(c["in_force"] == "2027-05-13" for c in r6)
    before = clause_evidence(ctx, [], dt.date(2026, 9, 19))
    after = clause_evidence(ctx, [], dt.date(2027, 5, 13))
    assert not any(c["in_force_now"] for c in before if c["id"].startswith("DPDP"))
    assert all(c["in_force_now"] for c in after if c["id"].startswith("DPDP"))


def test_guidance_is_not_labelled_as_law_in_force():
    lines = "\n".join(executive_lines(load_context("india"), [], dt.date(2026, 9, 19)))
    assert "CERT-In Guidelines for Government Entities, 7.1** (guidance, issued 2023-06-30)" in lines


def test_failing_evidence_is_named():
    lines = "\n".join(executive_lines(load_context("india"), [_v("V-207193", "FAIL"), _v("RFC8247-DH-MUST", "PASS")]))
    assert "failing: V-207193" in lines
