# EXP-18b, Groq arm — prompt freeze (2026-09-27, before any Groq test, S11 or robustness run)

frozen prompt: P0

Selection rule (EXP-18 PREREG, reused): the variant with the most dev items confirmed fixed; ties go to the
earlier variant.

| Variant | Dev result (A1, `results/groq/raw.jsonl`, after ADDENDUM B's client fix) |
|---|---|
| P0 (committed SYSTEM_PROMPT + leave-one-out few-shot, unchanged) | **5 confirmed fixed of 5 included**, 0 regressions: D3, D4 `ah_proposals = sha256`; D5 `...modp2048-ke1_mlkem768`; D6 `...x25519-ke1_mlkem768`; D7 `...ecp384-ke1_mlkem768` |
| P1, P2 | not run: they cannot exceed 5/5, and a tie goes to the earlier variant (P0), so running them cannot change the selection |

D1, D2 excluded (`baseline_no_sa`: IKEv1 does not establish in the lab), as in EXP-18. Model:
`openai/gpt-oss-120b` via Groq, `reasoning_effort=low`, temperature 0 (A1).
