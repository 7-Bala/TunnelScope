# EXP-44 — Recalibrate the mixed-traffic check for the new classifier — PRE-REGISTRATION (2026-10-02, before any run)

## Why (and what was seen first)
The mixed-traffic check (EXP-16 part D, `tunnelscope/models/mixed_windows.npz`) reads the shape of the classifier's per-window
probabilities. It was trained on probabilities from a classifier that had seen the session's generators (leave-one-repetition-out
inside our lab), so it learned that a single-traffic session looks very confident. After DEC-054 the classifier is K4. A diagnostic
run after EXP-43, before this was written, found: EXP-05 mixed sessions 12/12 flagged (right), lab C singles 0/32, EXP-16 real-app
singles 0/32, but **lab D singles 21/32 wrongly flagged as mixed**. On lab D K4 picks the right class for 26 of 32 sessions
ungated, yet answers only 11, mostly because of those false flags. Safe, but it throws correct answers away.

## Change under test (fixed here)
Same detector design (RandomForest, 300 trees, balanced classes, the 11 order-free `session_features`), retrained on probabilities
that look like deployment: every **single** session of the eight EXP-42 families gets its probabilities from the K4 recipe trained
**without its own family** (leave-one-family-out); every **mixed** session (EXP-05 and EXP-15 mux arms, all from the lab-tgen
family) gets its probabilities from K4 trained without lab-tgen. Threshold chosen by EXP-16's own rule: the smallest tau in
0.20..0.80 (step 0.05) at which, in 5-fold cross-validation grouped by session, at least 80% of mixed sessions are caught and at
most 10% of single sessions are wrongly flagged. Lab D trains nothing.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P44-1 | A threshold meeting EXP-16's bar exists in cross-validation (catch >= 80%, false flags <= 10%) | none exists |
| P44-2 | The EXP-05 mixed sessions are still caught: >= 80% flagged by the shipped path with the new detector | < 80% |
| P44-3 | Lab D gated coverage rises from 11/32 to >= 20/32 | < 20 |
| P44-4 | Lab D answers stay right: >= 90% of gated answers correct | < 90% |
| P44-5 | No new false flags where there were none: lab C and EXP-16 real-app singles each flagged <= 2/32 | > 2 in either |

## Ship rule
The new `mixed_windows.npz` ships only if P44-1, P44-2 and P44-4 hold and P44-3 or P44-5 is not made worse than today. Otherwise
the current detector stays and the RESULT says so. Every prediction is reported whether or not it holds.
