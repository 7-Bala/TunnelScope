"""Regulatory CONTEXT (mentor follow-up D): which verdicts are evidence toward
which clause of a regulation that requires encryption without specifying how.

Deliberately not a baseline. A context never produces PASS/FAIL of its own; it
groups existing, standard-referenced verdicts under a clause and states what
the capture cannot show. Data: tunnelscope/rules/context/<name>.yaml.
"""
from __future__ import annotations

import datetime as _dt
import os
from collections import Counter

import yaml

from .engine import RULES_DIR, Verdict


def load_context(name: str = "india", rules_dir: str = RULES_DIR) -> dict:
    with open(os.path.join(rules_dir, "context", f"{name}.yaml")) as fh:
        return yaml.safe_load(fh)


def clause_evidence(ctx: dict, verdicts: list[Verdict], today: _dt.date | None = None) -> list[dict]:
    """Per clause: the relevant verdict counts and whether the clause is in force."""
    today = today or _dt.date.today()
    out = []
    for c in ctx["clauses"]:
        rel = [v for v in verdicts if v.rule_id in c["evidence_rules"]]
        counts = Counter(v.verdict for v in rel)
        in_force = c.get("in_force")
        out.append({**c,
                    "counts": dict(counts),
                    "failing": sorted({v.rule_id for v in rel if v.verdict == "FAIL"}),
                    "in_force_now": None if in_force is None else today >= _dt.date.fromisoformat(str(in_force))})
    return out


def _when(c: dict) -> str:
    if c["in_force_now"] is None:
        return f"guidance, issued {c['issued']}"
    return "in force" if c["in_force_now"] else f"in force from {c['in_force']}"


def _tally(c: dict) -> str:
    if not c["evidence_rules"]:
        return "the whole report is the evidence"
    k = c["counts"]
    parts = [f"{k.get(s, 0)} {s.lower().replace('_', ' ')}" for s in ("FAIL", "PASS", "UNKNOWN", "NOT_OBSERVABLE")
             if k.get(s)]
    return ", ".join(parts) or "no relevant verdicts"


def executive_lines(ctx: dict, verdicts: list[Verdict], today: _dt.date | None = None) -> list[str]:
    L = [f"## {ctx['title']} (evidence, not a compliance verdict)", ""]
    for c in clause_evidence(ctx, verdicts, today):
        flag = f" — failing: {', '.join(c['failing'])}" if c["failing"] else ""
        L.append(f"- **{c['authority']}** ({_when(c)}): {_tally(c)}{flag}")
    L += ["", f"_{ctx['disclaimer']}_", ""]
    return L


def technical_lines(ctx: dict, verdicts: list[Verdict], today: _dt.date | None = None) -> list[str]:
    L = [f"## {ctx['title']} (evidence, not a compliance verdict)", "", f"> {ctx['disclaimer']}", ""]
    for c in clause_evidence(ctx, verdicts, today):
        L += [f"### {c['authority']} — {_when(c)}", "",
              f"> \"{c['text']}\"", "",
              f"- **What this report shows:** {c['relevance']}",
              f"- **Relevant verdicts:** {_tally(c)}" + (f"; failing: {', '.join(c['failing'])}" if c["failing"] else ""),
              f"- **Not shown by a capture:** {c['does_not_show']}",
              f"- Source: {c['source']}", ""]
    L += ["**Outside what TunnelScope can evidence:**", ""] + [f"- {n}" for n in ctx.get("not_covered", [])] + [""]
    return L
