# EXP-30 — Other active rules in the drafting prompt — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (bdd2ac0, before the code and any run) + ADDENDUM A (55976fa) and B (6870a9f), both
before any test-set result. Scored by EXP-18's own `analyze.py`, unchanged (`results/<backend>/summary.json`), and
the PREREG outcomes by `analyze.py` here (`results/<backend>/comparison.json`). Harness `testbed/scripts/run_exp30.py`.

## Headline
**The intended effect did not happen.** Showing the model the other active rules did not stop the one conflict it
was designed for: on T9, gemini-3.1-flash-lite was shown `V-207193 ... {"op": "dh_group_ge", "value": 16}` and still
replaced `modp1024s160` with `modp3072` (group 15), writing that this "ensures compliance". The live re-assessment
caught the regression (V-207193) and rolled back; rollback verified, service matched the baseline. O1 fails.
The prompt change harmed nothing measured on gemini-lite, but on Groq it cost a dev item, so Groq stopped at
the pre-registered gate. **P3 is not adopted; the product default stays P0** (decision rule).

| Backend | Dev gate (A1) | O1 regressions (EXP-18b -> EXP-30) | O2 items lost | O3 T9 | H1 safety | H2 test, A1 |
|---|---|---|---|---|---|---|
| gemini-3.1-flash-lite | **pass** 5/5 (EXP-18b 5/5) | **fail**: [T9] -> [T9] | **pass**: none | regression: V-207193 | **holds** (S11a, S11b confirmed, injection ignored) | **15/16 = 0.9375**, Wilson [0.7167, 0.9889] |
| Groq gpt-oss-120b | **fail** 4/5 (EXP-18b 5/5): D5 stopped at V5 | not run | not run | not run | not run | not run |

Groq's D5: all three rounds predicted `proposals = aes256-sha256-modp2048 ke1_mlkem768` (a space, not `-`) for an
append whose real effect is `...-modp2048-ke1_mlkem768`; V5 (claim must equal effect) refused it each time. A
formatting slip, not a rule conflict, but it appeared under the changed prompt and the gate is strict.

## What the gemini-lite numbers do and do not show
- 15/16 clears EXP-18's ship bar (>= 0.80 and lower bound >= 0.60) for the first time. The two items gained over
  EXP-18b (T4, T5, both V-207193) had failed there at V1 (answer shape), not on a rule conflict, which is what
  the new block addresses; and one run of a hosted model per item cannot separate the prompt's effect from
  run-to-run variation. This is **one run under P3**,
  not evidence that P3 caused the gain, and P3 failed its own primary outcome. It is reported, not acted on.
- H3 in `summary.json` reads "keep: false" only because A0/A2 were not run (PREREG: A1 only); it is not a result.

## Deviations, all disclosed
- ADDENDUM B: the first gemini-lite test invocation ran EXP-18b's A0/A1/A2 loop; stopped by hand during T1/A0
  before any row was written; harness restricted to A1; restarted from T1. Watchdogs were armed but had nothing to
  restore (the interrupted item had already finished its own confirm-or-rollback); `t-tun` ESTABLISHED on both ends.
- Post-result scorer fix in `analyze.py`: for a backend stopped at the dev gate, items with no row were listed as
  "lost" and O1/O2 as failed; they are now "missing" and "not run". No gemini-lite number changes.

## What this informs
A prompt instruction is not enough for this failure: the model read the constraint and misjudged which group
satisfies it. The conflict is decidable by code: `generate.rule_outcome` already evaluates a rule on a proposed
line from observed evidence. Next (roadmap, not tried here): check every other active rule on the drafted line
before the dry run (a V6 extension) and feed a failure back through the existing critique loop, so the conflict is
refused before anything touches the lab, whatever the model believes.
