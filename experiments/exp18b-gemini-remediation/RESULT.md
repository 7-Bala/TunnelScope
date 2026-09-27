# EXP-18b — Cloud models drafting remediation, under EXP-18's bar — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (2026-09-25) + ADDENDUM A-D (all written before the runs they govern). Scored by
EXP-18's own `analyze.py`, unchanged (`analyze.py` here only points it at each arm): `results/<arm>/summary.json`.
Harness: `testbed/scripts/run_exp18b.py`. Freezes: `FREEZE-groq.md`, `FREEZE-gemini-lite.md`.

## Headline
Both cloud models turn a 0/16 local model into a useful drafting assistant, and the safety net held: **every
applied draft that broke another rule was rolled back automatically and the rollback verified (11/11)**. Neither
model clears the pre-registered ship bar (>= 0.80 AND Wilson 95% lower bound >= 0.60): gemini-3.1-flash-lite
reaches 0.8125 but its lower bound is 0.57 (16 items is a small sample).

| Arm (A1 = 2 critique rounds) | H1 safety (S11a/b) | H2 test confirmed fixed | Wilson 95% | Robustness (48) | Median s/draft (A1) |
|---|---|---|---|---|---|
| Local model (EXP-18) | pass | 0/16 | [0.00, 0.19] | 0 | — |
| Groq `openai/gpt-oss-120b` | **pass** (2/2 confirmed, injection ignored) | **12/16 = 0.75** | [0.505, 0.898] | 38/48 = 0.79 | **3.3** |
| Gemini `gemini-3.1-flash-lite` | **pass** (2/2) | **13/16 = 0.8125** | [0.570, 0.934] | 40/48 = 0.83 | 13.3 |
| Gemini `gemini-3.8-flash` | not run | not run (dev 3/3 confirmed, then free quota exhausted on two keys) | — | — | — |

H3: critique rounds help both (A0 9/16 -> A1 12/16 Groq, 13/16 Gemini-lite): keep. Self-review never flagged a
draft that failed (0 true catches, 0 false alarms): stays off.

## Where they fail
- **T9 (RFC8247-DH-MUST, modp1024s160), every run of both models:** the draft satisfies the rule asked about but
  picks MODP-2048 (Groq) / MODP-3072 (Gemini), which fails DISA V-207193 (group >= 16). The live re-assessment
  caught the regression each time and rolled back, rollback verified. The drafting prompt names only the failing
  rule, not the other baselines; giving it the other active rules is the obvious next improvement (not tried here).
- A few V1/V4 stops (answer shape / keyword validity), refused before anything ran.
- T17-T20 excluded for both (baseline not FAIL: ESP 3DES and AH MD5 not judged on these lab captures), as in EXP-18.

## Deviations and invalid runs, all disclosed in the addenda
- ADDENDUM B: the first Groq dev run was invalid (client bug: reasoning consumed the 320-token budget, HTTP 400);
  kept unscored in `results/groq/raw-invalid-client-bug.jsonl`, arm restarted after the fix.
- ADDENDUM C/D: gemini-3.8-flash's free daily quota ran out (experiment key, then a second account's key at the
  owner's decision); replaced by a new, fully pre-frozen gemini-3.1-flash-lite arm on the experiment key.
- 5 gemini-lite and 0 Groq runs hit 429/503, recorded as infrastructure and re-run (ADDENDUM A item 4).
- Dev items D3/D4 were excluded in EXP-18 (baseline UNKNOWN) but included here: TunnelScope's AH analysis now
  judges them; the inclusion rule itself is unchanged.

## Decision this informs
DEC-041: drafting chain order Groq -> gemini-3.1-flash-lite -> local (fix rates within each other's intervals; Groq
4x faster and its free tier does not train on inputs). Drafting stays opt-in (`TUNNELSCOPE_GENERATOR=1`) because
the pre-registered ship bar is not met; every draft remains verified live with automatic rollback.
