# EXP-18b, gemini-lite arm (gemini-3.1-flash-lite) — prompt freeze (2026-09-27, before any test, S11 or robustness run)

frozen prompt: P0

Selection rule (EXP-18 PREREG, reused): most dev items confirmed fixed; ties go to the earlier variant.

| Variant | Dev result (A1, `results/gemini-lite/raw.jsonl`) |
|---|---|
| P0 (committed SYSTEM_PROMPT + leave-one-out few-shot, unchanged) | **5 confirmed fixed of 5 included**, 0 regressions: D3, D4 `ah_proposals = sha256`; D5 `...modp2048-ke1_mlkem768`; D6 `...x25519-ke1_mlkem768`; D7 `...ecp384-ke1_mlkem768` |
| P1, P2 | not run: cannot exceed 5/5, and a tie goes to P0 |

D1, D2 excluded (`baseline_no_sa`). Model gemini-3.1-flash-lite, thinking_level low, experiment key.
