"""Assessment engine — rules as versioned data (ADR-003, invariant I5).

Evaluates baseline rule sets (rules/*.yaml) against an EvidenceRecord and emits
Verdicts. Every verdict names its baseline authority and rule id and carries the
finding's evidence (I3). Absence of evidence NEVER becomes PASS or FAIL:
- finding UNKNOWN        -> verdict UNKNOWN
- finding NOT_OBSERVABLE -> verdict NOT_OBSERVABLE
- finding CONTRADICTORY  -> verdict CONTRADICTORY
Only an actually-observed value is asserted against (I4, DEC-008).
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field

import yaml

from ..errors import DependencyError
from ..evidence.record import EvidenceRecord, Status

# Shipped inside the package (tunnelscope/rules/, package data) so an installed
# copy has its baselines. They used to live at the repo root, resolved relative
# to the source checkout: an installed wheel found none and assessed every
# capture against nothing, silently (found by the on-prem install test, 2026-09-18).
RULES_DIR = os.environ.get("TUNNELSCOPE_RULES_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules"))

# DH group name -> numeric id (for dh_group_ge)
_DH_ID = {"MODP-1024": 2, "MODP-2048": 14, "MODP-3072": 15, "MODP-4096": 16,
          "ECP-256": 19, "ECP-384": 20, "ECP-521": 21, "Curve25519": 31, "Curve448": 32}


@dataclass
class Verdict:
    baseline: str
    authority: str
    rule_id: str
    title: str
    verdict: str          # PASS | FAIL | UNKNOWN | NOT_OBSERVABLE | CONTRADICTORY
    severity: str
    attribute: str
    observed: object = None
    message: str = ""
    evidence: list = field(default_factory=list)

    def to_dict(self):
        d = self.__dict__.copy()
        d["evidence"] = [e.__dict__ if hasattr(e, "__dict__") else e for e in self.evidence]
        return d


def _assert(op: str, want, value) -> bool:
    if op == "equals":       return value == want
    if op == "not_equals":   return value != want
    if op == "in":           return value in want
    if op == "not_in":       return value not in want
    if op == "matches_any":  return isinstance(value, str) and any(w in value for w in want)
    if op == "dh_group_ge":  return _DH_ID.get(value, -1) >= want
    if op == "pq_present":   return isinstance(value, list) and any("ML-KEM" in str(v) for v in value)
    raise ValueError(f"unknown assert op: {op}")


def load_baselines(rules_dir: str = RULES_DIR) -> list[dict]:
    out = []
    for f in sorted(glob.glob(os.path.join(rules_dir, "*.yaml"))):
        with open(f) as fh:
            out.append(yaml.safe_load(fh))
    if not out:
        # An assessment against zero baselines has no verdicts, which reads as
        # "nothing wrong". That is absence scored as compliance (I8): refuse.
        raise DependencyError(
            f"no baselines found in {os.path.abspath(rules_dir)}: refusing to assess against nothing "
            "(reinstall TunnelScope, or point TUNNELSCOPE_RULES_DIR at a rules directory)")
    return out


def assess_record(rec: EvidenceRecord, baselines: list[dict] | None = None) -> list[Verdict]:
    baselines = baselines if baselines is not None else load_baselines()
    verdicts = []
    for b in baselines:
        for rule in b["rules"]:
            f = rec.findings.get(rule["attribute"])
            common = dict(baseline=b["baseline"], authority=b["authority"], rule_id=rule["id"],
                          title=rule["title"], severity=rule.get("severity", "medium"),
                          attribute=rule["attribute"])
            if f is None or f.status == Status.UNKNOWN:
                verdicts.append(Verdict(**common, verdict="UNKNOWN",
                                        message="attribute not observed at this vantage",
                                        evidence=f.evidence if f else [])); continue
            if f.status == Status.NOT_OBSERVABLE:
                verdicts.append(Verdict(**common, verdict="NOT_OBSERVABLE",
                                        message=f.note, evidence=f.evidence)); continue
            if f.status == Status.CONTRADICTORY:
                verdicts.append(Verdict(**common, verdict="CONTRADICTORY",
                                        message=f.note, evidence=f.evidence)); continue
            a = rule["assert"]
            ok = _assert(a["op"], a.get("value"), f.value)
            verdicts.append(Verdict(
                **common, verdict="PASS" if ok else "FAIL",
                observed=f.value, evidence=f.evidence,
                message="" if ok else rule.get("fail_message", "does not meet the baseline")))
    return verdicts
