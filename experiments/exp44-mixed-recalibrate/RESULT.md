# EXP-44 — Recalibrate the mixed-traffic check for the new classifier — RESULT (2026-10-02)

Pre-registration `23b179f` (the diagnostic that motivated it disclosed there); scorer `66d9196`. Scores in `results/summary.json`.

## 1. Pre-registered result
2,290 rows (2,262 single sessions from eight families, each scored by K4 trained without its own family; 28 mixed sessions from
EXP-05/15, scored by K4 trained without lab-tgen). Five-fold cross-validation grouped by session:

| tau | Mixed caught | Single wrongly flagged |
|---|---|---|
| 0.20 | 0.786 | 0.022 |
| 0.25 | 0.750 | 0.017 |
| 0.30 | 0.714 | 0.013 |
| 0.50 | 0.571 | 0.004 |
| 0.80 | 0.321 | 0.001 |

**P44-1 falsified:** no threshold reaches EXP-16's bar (catch >= 80% and false flags <= 10%); the best catch is 78.6%, one
session short with 28 mixed sessions. The scorer stops there, so P44-2 to P44-5 were not scored. **Ship rule: not met; the current
detector stays.**

## 2. What it shows
Probabilities from a classifier that has not seen a session's family are less peaked, so "mixed" and "uncertain but single" look
alike: the false-flag rate becomes tiny (2%) but mixed sessions are harder to catch. There are only 28 mixed sessions, all from our
lab generator; a better detector needs more and more varied mixed sessions, not a different threshold.

## 3. Post-hoc, not pre-registered (for the owner's decision only)
`posthoc_tau020.py`, `results/posthoc.json`: with the tau = 0.20 candidate, lab D would get 15 answers out of 32 (all 15 right)
instead of today's 11 (all right), and 1 of the 12 EXP-05 mixed sessions would get an answer instead of being flagged. That is a
trade between coverage and the mixed-traffic safety bar; it is not taken here.
