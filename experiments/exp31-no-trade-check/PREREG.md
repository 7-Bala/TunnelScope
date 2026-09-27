# EXP-31 — Does a code check for other-rule conflicts stop drafts trading one failure for another? — PRE-REGISTRATION (2026-09-27, before the code change and any run)

## Why
EXP-30 (RESULT.md): telling the model the other active rules did not stop the T9 conflict. gemini-3.1-flash-lite
read "group >= 16" and still chose modp3072 (group 15). The conflict is decidable by code:
`generate.rule_outcome` already judges a rule on a proposed line from what TunnelScope observed on the wire.
Roadmap T-138.

**Disclosure:** as in EXP-30, this targets a failure seen on the test set (T9), so a T9 improvement is expected by
design. The claim this experiment can support is "conflicts are refused before the lab, without harming the
other items".

## Intervention (fixed here)
Check **V6** is extended. The drafted line must still make the target rule pass (unchanged), and now also:
for every other rule in the default active baselines that judges an attribute carried on that line (the EXP-30
attribute map), if the rule does not FAIL on the current line and FAILS on the drafted line (both judged by
`rule_outcome` on observed evidence), V6 stops the draft. Rules whose attribute `rule_outcome` cannot judge from
a proposals line (RFC8247-DH-OFFER, `ike_offered_dh`) are not checked by V6; the live re-assessment still judges
them after apply, as before. The feedback to the model (critique rounds) names the conflicting rule ids and
lists vocabulary keywords that satisfy the target rule AND those rules; never model or config text.
The prompt is P0 (EXP-30's P3 is not used). V6 is on for every draft (it is a check, not an option).

## Design
Same as EXP-30: Groq `openai/gpt-oss-120b` and Gemini `gemini-3.1-flash-lite`, arm **A1** (2 critique rounds,
temperature 0), EXP-18's dev D1-D7 and test T1-T20, same inclusion rule and lab discipline, S11a/S11b re-run.
Harness `testbed/scripts/run_exp31.py` (EXP-18b's harness, results dir changed, test on A1 only as in EXP-30
ADDENDUM B). Scored by EXP-18's `analyze.py` unchanged + `analyze.py` here (same outcome code as EXP-30's, after
its disclosed scorer fix, with P0 rows and this experiment's directory).

## Order
PREREG committed -> code + unit tests committed -> dev per backend -> **dev gate** (each backend must confirm >= its
EXP-18b A1 dev result, 5/5, or it stops there) -> test A1 + S11 per backend that passed.

## Outcomes (per backend, vs its EXP-18b A1 on the same items; Groq 12/16, gemini-lite 13/16, each with T9 regressed)
- **O1 (intended effect):** accepted drafts that reached the lab and regressed another rule: **0** (EXP-18b: 1 each).
- **O2 (no harm):** EXP-18b-confirmed items not confirmed now: **at most 1**.
- **O3:** T9 outcome, reported separately (confirmed, stopped at V6, or other).
- **H1 safety:** S11a and S11b each stopped, confirmed, or rolled back and verified.
- **H2 ship bar (EXP-18's):** >= 0.80 and Wilson lower bound >= 0.60. Reported, not this experiment's criterion.

## Decision rule
V6's extension is a safety check, so it stays in the product if O1 and O2 pass for Groq (first in the DEC-041
chain) and H1 holds for both; recorded as a decision. If O2 fails (the check refuses fixes that were correct), it
is reverted and the reason reported. The opt-in status of drafting is a separate owner decision.

## Rules
No threshold, item, arm or check definition changes after this commit. RESULT.md quotes only analyze.py's
outputs. Deviations are dated addenda, before the runs they govern.
