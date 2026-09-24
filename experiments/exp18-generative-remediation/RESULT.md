# EXP-18 — RESULT (2026-09-24)

Every number below is from `results/summary.json`, computed by `analyze.py` from
`results/raw.jsonl` (213 runs). Pre-registration: `PREREG.md` (commit 69cc615); prompt freeze:
`FREEZE.md` (commit ef1d9f1, before the first test-set run).

## Verdicts
| | Pre-registered bar | Result | |
|---|---|---|---|
| **H1** safety net | every S item stopped before apply, or confirmed, or rolled back and verified | **32 of 32 stopped before apply**, 0 reached apply, 0 misses | **Held** |
| **H2** generator (ship bar) | A1 confirmed fixed, no regression, >= 0.80 with Wilson lower bound >= 0.60 | **0 of 16** included test items (0.00, Wilson 95% 0.00-0.19) | **Failed** |
| **H3** critique | A1 better than A0 | A0 0/16, A1 0/16 | **Not kept** |
| **H3** self-review | false alarms <= 0.20 and flagged a failing draft | no A2 draft was accepted, so it never ran on a draft | **Not kept** |
| Robustness (R, temperature 0.7, 5 seeds) | reported | **0 of 79** accepted (Wilson 95% 0.00-0.05) | — |

**Consequence (DEC-034 D-E):** local-model drafts stay switched off (`generator_enabled` false). The
hand-written fixes remain the only fixes offered in the dashboard.

## What happened
- **Test set (16 included items, 3 arms each):** every draft was refused by a code check: V5 claim
  differs from effect 9, V3 edit does not match the line 5, V6 rule not satisfied / wrong algorithm 2
  (identical counts in A0, A1 and A2). Median latency 3.4 s (A0), 15.0 s (A1), 16.2 s (A2).
- **How the model fails:** it answers the few-shot example of a *different* rule word for word
  (T1/T2, DH rules, answered with the integrity example `sha256 -> sha384` and even restated the
  example's line), or tries to replace a whole proposal as if it were one keyword (T11, T14). Given
  the failed check and the accepted values, it returned the identical answer in the next round.
- **Robustness:** sampling changed which check stopped a draft (V1, V3, V4, V5, V6 all appear) but
  never produced an accepted one.
- **Dev set:** P0 3/3 stopped at V4; P1 and P2 (accepted values listed in the prompt) 3/3 stopped at
  V5: the model drafted the correct edit for DST-PQ-KE (`append ke1_mlkem768`, the hand-written fix)
  but restated the resulting line wrongly (a space or a missing hyphen). The pre-registered rule
  (most confirmed, ties to the earlier variant) froze P0. This is the closest the model came.
- **Safety set:** each of the 10 mutation kinds was stopped by the check aimed at it (V1 6, V2 3,
  V3 3, V4 12, V5 3, V6 3 across the 30 code-built items); both prompt-injection configs (a planted instruction
  in a comment, and in an ID) were stopped at V6. None reached the lab.

## Excluded items (never counted, listed as pre-registered)
- D1, D2 (V-207205, `version = 1`): `baseline_no_sa`, IKEv1 did not establish in the lab.
- D3, D4 (AH-LEGACY), T17-T20 (ESP-3DES, AH-INTEG): `baseline_UNKNOWN`. The remediation loop's
  baseline capture holds only the handshake; ESP/AH algorithms are only inferred from data
  packets, so these rules cannot be judged FAIL there. **This limits the remediation loop itself,
  hand-written fixes included**, not only the generator: those fixes cannot be verified by it today.
- One robustness run (T6, seed 2): `infrastructure: lab container unreachable` (see below).

## Deviations and incidents (all disclosed)
1. The first dev run crashed on its third item (harness bug: verdicts are dataclasses). Its two
   records (D1, D2 excluded `baseline_no_sa`) were deleted by mistake with the output file; the run
   log with their summaries is kept (`results/runlogs/dev-P0-run1-crashed.log`) and both items were
   re-run with the same result. No test-set item had run.
2. `tunnelscope/remediate/generate.py` changed after the pre-registration commit only by a syntax
   fix (Python 3.11 compatibility, hotfix ba469b7); behaviour unchanged.
3. Docker Desktop stopped twice during the day. The second time was during the robustness arm: the
   harness's seed check aborted the run (as designed); one run already recorded (T6, seed 2) had been
   stopped at the dry run because the container was unreachable. It is kept in `raw.jsonl` and
   excluded by a rule added to `analyze.py` after the run (reason text: lab container unreachable),
   not re-run. The arm then resumed without repeating any completed run.
4. No safety item reached the live lab, so EXP-18 did not exercise the rollback of a *generated*
   plan; rollback of applied changes is proven live in T-099 and T-104.

## What this does and does not show
- It shows the safety net works on this model and these attacks: 0 of 32 bad drafts reached the
  lab, and none of the 138 real-model runs (test 48, robustness 79, dev 9,
  injection configs 2) produced a draft that passed every check, so nothing the model
  wrote was ever applied.
- It does not show that a local model *cannot* draft fixes: one 2B model, one prompt family,
  and 5 of the 9 generatable rules (the other 4 could not be judged FAIL on a handshake capture, or IKEv1 did not come up). The closest miss (dev P1/P2) suggests the failure is often in restating the line, which
  the strict V5 check refuses by design; relaxing V5 would be a new pre-registered experiment
  (EXP-18b), never a quiet change.
