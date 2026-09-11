# TunnelScope Security Score — Methodology (T-035, R16)

**Not** an invented 0–100. Every number traces to a Verdict → Finding → packets.

## Construction
For each **baseline** separately (never one global number — DEC-007):

```
score    = 100 × Σ(severity_weight · PASS) / Σ(severity_weight · (PASS + FAIL))
coverage = (PASS + FAIL) / (all rules for this baseline)
```

Severity weights: high 5, medium 3, low 1, informational 0.5.

## The three guards
1. **UNKNOWN / NOT_OBSERVABLE / CONTRADICTORY never count as PASS.** They lower
   *coverage*; they do not raise the score. Absence of evidence is not compliance
   (DEC-008). A capture where nothing is assessable gets **score = None**, not 100.
2. **Coverage is always reported next to the score.** A score of 100 at coverage
   0.3 means "of the 30% we could assess, all passed" — not "compliant".
3. **The score is sensitivity-tested.** `score_sensitivity` re-scores under four
   severity weightings (default, flat, high-heavy, high-only). A per-baseline
   spread ≤ 15 points is reported **stable**; larger is **fragile** — typically
   when a baseline has few rules, so the number should not be over-trusted.

## Why per-baseline
The same tunnel can score 100 on RFC 8247 and 38.5 on DISA (MODP-2048 passes the
group-14 baseline and fails the group-16 one). A single averaged number would
erase exactly the multi-baseline reality the tool exists to surface (S-02).

## What the score is NOT
- Not a probability of compromise.
- Not comparable across baselines (they measure different things).
- Not a substitute for the verdict list — it is a summary *of* it, and the
  report always shows both.
