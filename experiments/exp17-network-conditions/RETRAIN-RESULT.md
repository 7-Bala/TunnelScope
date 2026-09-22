# EXP-17 Follow-Up: Hardened Retraining under Network Delay and Loss

Pre-registration: `PREREG.md`. Initial results: `RESULT.md`. Retrain metrics: `results/exp17_retrain_results.json`.

## 1. Repetitions Captured

- **Existing data (reps 1–3):** 96 sessions (48 synthetic, 48 real applications; 48 wan, 48 lossy).
- **New captures (reps 4–8):** 160 sessions (80 synthetic, 80 real applications; 80 wan, 80 lossy).
- **Total captured sessions on disk:** 256 sessions across 8 repetitions, 2 impairment profiles, and 8 traffic classes.
- Manifest entries: `testbed/captures/exp17/manifest.csv` contains 256 rows (96 existing + 160 new).

## 2. STEP 5 Regression-Gate Outcome

- **Unit test suite (`.venv/bin/python -m pytest`):** 185 passed, 0 failed.
  - `tests/test_ai_layer.py::test_attacker_generalises_to_a_held_out_repetition`: PASS.
  - `tests/test_ai_layer.py::test_attacker_flags_mixed_traffic_uncertain`: PASS.
- **Full validation check (`build/check_all.sh`):** RESULT: PASS (all 9 checks passed: diff guard, unit tests, dashboard tsc/lint/build, ground truth 85/85 captures, dataset integrity, findings differential, external captures).
- **Outcome:** Zero regressions. Nothing required reverting.
- **Shipped vs Reverted:**
  - `tunnelscope/models/traffic_windows.npz`: Shipped (committed).
  - `tunnelscope/models/mixed_windows.npz`: Shipped (committed).

## 3. STEP 6 Evaluation Table

### Traffic Classifier Leave-One-Repetition-Out Macro-F1

Evaluated across all 8 repetitions using the retrained traffic classifier procedure (train on clean data + all EXP-17 reps except $k$, test on rep $k$, per profile):

| Repetition | WAN Macro-F1 | Lossy Macro-F1 |
|---|---|---|
| Rep 1 | 1.0000 | 0.8723 |
| Rep 2 | 0.9824 | 0.9050 |
| Rep 3 | 0.9932 | 0.9190 |
| Rep 4 | 0.9889 | 0.8966 |
| Rep 5 | 0.9591 | 0.9104 |
| Rep 6 | 0.9798 | 0.9653 |
| Rep 7 | 0.9891 | 0.9054 |
| Rep 8 | 0.9820 | 0.9356 |
| **Mean** | **0.9843** | **0.9137** |

*(Reference under isolated single-profile training: WAN mean 0.9710, Lossy mean 0.9055).*

### Mixed-Traffic Detector False-Flag Rate on Single-Class Impaired Sessions

Evaluated on single-class impaired sessions (128 sessions per profile) using the retrained models:

| Profile | Total Sessions | Flagged Mixed | False-Flag Rate | Bar | Status |
|---|---|---|---|---|---|
| `wan` | 128 | 0 | 0.00% (0.0000) | $\le 15\%$ | Met |
| `lossy` | 128 | 19 | 14.84% (0.1484) | $\le 15\%$ | Met |

## 4. Bar Outcomes

- **WAN Macro-F1 $\ge 0.90$ bar:** Reached. Mean macro-F1 is 0.9843 (+0.0843 above 0.90).
- **Lossy Macro-F1 $\ge 0.90$ bar:** Reached. Mean macro-F1 is 0.9137 (+0.0137 above 0.90).
- **Mixed-Traffic False-Flag $\le 15\%$ bar:** Reached on both profiles. WAN is 0.00% (-15.00% below threshold); Lossy is 14.84% (-0.16% below threshold).
