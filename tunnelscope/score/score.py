"""Security scoring (T-035, R16) — a defensible, cited construction, not an
invented 0-100.

Principles (each guards against a known failure mode):
  1. **Per baseline, never one global number.** A single score hides the
     multi-baseline reality (a config PASSES RFC 8247 and FAILS DISA); DEC-007.
  2. **UNKNOWN / NOT_OBSERVABLE never count as PASS.** They lower *coverage*,
     not raise the score - absence of evidence is not compliance (DEC-008).
  3. **Score = severity-weighted pass rate over ASSESSABLE rules only.**
     coverage = assessable / total is reported next to it, so a high score on
     two assessable rules is never mistaken for a clean bill.
  4. **Severity weights are explicit and the score is sensitivity-tested**
     (score_sensitivity) - a score that swings wildly under reasonable
     re-weighting is reported as fragile.

Every number traces to a Verdict, which traces to a Finding, which points at
its packets. No step invents a value.
"""
from __future__ import annotations

SEVERITY_WEIGHT = {"high": 5, "medium": 3, "low": 1, "informational": 0.5}
ASSESSED = {"PASS", "FAIL"}


def score_baseline(verdicts, weights=SEVERITY_WEIGHT):
    """Score one baseline's verdicts. Returns a dict with the score, coverage,
    and the exact counts behind them."""
    passed = fail = 0.0
    n_pass = n_fail = n_unknown = n_not_obs = n_contra = 0
    high_fail = []
    for v in verdicts:
        w = weights.get(v.severity, 1)
        if v.verdict == "PASS":
            passed += w; n_pass += 1
        elif v.verdict == "FAIL":
            fail += w; n_fail += 1
            if v.severity == "high":
                high_fail.append(v.rule_id)
        elif v.verdict == "UNKNOWN":
            n_unknown += 1
        elif v.verdict == "NOT_OBSERVABLE":
            n_not_obs += 1
        elif v.verdict == "CONTRADICTORY":
            n_contra += 1
    assessable_w = passed + fail
    total = n_pass + n_fail + n_unknown + n_not_obs + n_contra
    score = round(100 * passed / assessable_w, 1) if assessable_w else None
    coverage = round((n_pass + n_fail) / total, 2) if total else 0.0
    return {
        "score": score,                       # None when nothing was assessable
        "coverage": coverage,                 # fraction of rules that could be judged
        "counts": {"pass": n_pass, "fail": n_fail, "unknown": n_unknown,
                   "not_observable": n_not_obs, "contradictory": n_contra},
        "high_severity_failures": high_fail,
        "note": ("no rule was assessable at this vantage" if score is None else
                 f"{n_pass}/{n_pass + n_fail} assessable rules pass "
                 f"(severity-weighted); {n_unknown + n_not_obs} not assessable"),
    }


def score_record(verdicts, weights=SEVERITY_WEIGHT):
    """Group verdicts by baseline and score each. No cross-baseline average -
    that would hide the point of multi-baseline assessment."""
    by_base = {}
    for v in verdicts:
        by_base.setdefault(v.baseline, []).append(v)
    return {b: score_baseline(vs, weights) for b, vs in by_base.items()}


def score_sensitivity(verdicts):
    """Re-score under several reasonable severity weightings; a score that is
    stable across them is trustworthy, one that swings is reported as fragile."""
    schemes = {
        "default": SEVERITY_WEIGHT,
        "flat": {k: 1 for k in SEVERITY_WEIGHT},
        "high-heavy": {"high": 10, "medium": 3, "low": 1, "informational": 0.5},
        "high-only": {"high": 1, "medium": 0, "low": 0, "informational": 0},
    }
    out = {}
    for name, w in schemes.items():
        out[name] = {b: r["score"] for b, r in score_record(verdicts, w).items()}
    # per-baseline spread across schemes
    spread = {}
    for b in out["default"]:
        vals = [out[s][b] for s in schemes if out[s][b] is not None]
        spread[b] = round(max(vals) - min(vals), 1) if vals else None
    return {"by_scheme": out, "spread_per_baseline": spread,
            "verdict": "stable" if all((s or 0) <= 15 for s in spread.values()) else "fragile"}
