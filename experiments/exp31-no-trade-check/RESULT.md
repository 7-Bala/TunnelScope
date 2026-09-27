# EXP-31 — Code check for other-rule conflicts (T-138) — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (f843144, before the code and any run). Code 94e696c; dev results 5996af1 before any
test run. Scored by EXP-18's own `analyze.py`, unchanged (`results/<backend>/summary.json`), and the PREREG outcomes
by `analyze.py` here (`results/<backend>/comparison.json`). No addenda, no deviations.

## Headline
**All pre-registered outcomes pass for both backends. No draft that trades one failure for another reached the
lab** (EXP-18b: one per backend, T9, caught only by the live check and rolled back).

| Backend (A1, prompt P0) | Dev gate | O1 regressions reaching the lab | O2 items lost vs EXP-18b | O3 T9 | H1 safety | H2 test |
|---|---|---|---|---|---|---|
| Groq gpt-oss-120b | pass 5/5 | **0** (EXP-18b: [T9]) | **none** | **confirmed fixed** | holds | 13/16, Wilson [0.5699, 0.9341]: bar not met |
| gemini-3.1-flash-lite | pass 5/5 | **0** (EXP-18b: [T9]) | **none** | stopped at V6 (never reached the lab) | holds | **14/16, Wilson [0.6398, 0.965]: bar met** |

## T9, the case this targets
- Groq: first draft `modp2048` (V-207193 fails on MODP-2048, which it did not fail on before), refused at V6; the
  feedback named V-207193 and listed keywords that satisfy both rules; revision `modp4096`, applied, confirmed live.
- gemini-lite: `modp3072` in all three rounds; V6 refused it each time (`V-207193 would not pass with 'MODP-3072'`).
  The item is lost, but nothing touched the lab; before, the same draft was applied, regressed, and rolled back.

## What this does and does not show
- One run per item of hosted models. Other item-level changes vs EXP-18b (Groq T9 gained; gemini-lite T5 now a V1
  answer-shape stop, T14-T16 unchanged) are within run-to-run variation, and the check cannot cause a V1/V4 stop.
- gemini-lite meets EXP-18's ship bar in this run (as it did in EXP-30's single run); Groq, first in the default
  chain, does not (13/16). Per the PREREG, the opt-in status of drafting is a separate owner decision.
- V6 does not judge RFC8247-DH-OFFER (offered groups): the live re-assessment still covers it.

## Decision (PREREG decision rule: O1 and O2 pass for Groq, H1 holds for both)
The V6 extension stays in the product for every draft (DEC-042).
