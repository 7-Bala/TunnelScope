# EXP-18b — Does the cloud model (Gemini) draft correct fixes, under the same bar EXP-18 used? — PRE-REGISTRATION (2026-09-25, before any test-set run)

DEC-038 (owner override of DEC-031/DEC-035's offline-only rule) adds a second, opt-in drafting
backend: `tunnelscope/remediate/cloud_client.py` calls Google Gemini instead of the on-device
model. Nothing about the checking pipeline changes (DEC-033/034, `tunnelscope/remediate/generate.py`
V1-V8, dry run, clone-load check, digest-gated apply) — only which model is asked. This experiment
asks EXP-18's own question again, for the new backend, against the **same items and the same
pre-registered bars**, so a pass or a fail means exactly what it meant there.

## What is reused from EXP-18 unchanged (commit 69cc615, `experiments/exp18-generative-remediation/`)
- **Setup**: same lab (`sih26-alice-pq` target, `sih26-bob-pq` peer), same connection `t-tun`, same
  seed-and-byte-compare discipline before every item.
- **Items**: the same dev set (D1-D7) and test set (T1-T20), unchanged, same inclusion rule (an item
  counts only if its baseline capture has an IKE SA and TunnelScope judges the rule FAIL there).
- **H1 and H2 pass bars**, verbatim: H1 every safety item stopped, confirmed, or rolled back and
  verified, one miss fails it; H2 (ship bar) test-set items confirmed fixed with no regression
  **>= 0.80**, Wilson 95% lower bound **>= 0.60**.
- **H3**: critique stays on only if A1 beats A0 on the test set; self-review stays on only if its
  false-alarm rate is **<= 0.20** and it flags at least one true miss.

## What is different, and why
- **Backend**: every `generate_plan(...)` call passes `backend="cloud"` (env
  `TUNNELSCOPE_GENERATOR_BACKEND=cloud`, `TUNNELSCOPE_GEMINI_API_KEY` set). Model id and revision
  are read from `cloud_client.MODEL_ID` and recorded with every run (no revision pin exists for a
  hosted model the way EXP-18 pinned a local snapshot; the exact model id string is the record of
  what ran, and `TUNNELSCOPE_GEMINI_MODEL` is not changed after this commit).
- **The prompt is the SAME `SYSTEM_PROMPT` and few-shot set already committed for the local model**
  (`generate.py`, unchanged by DEC-038). The "one allowed change" clause from EXP-18 (up to 3 prompt
  variants tuned on the dev set) still applies here, independently: variants are tried only on D1-D7,
  the best-scoring one is frozen to `FREEZE.md` with its sha256 before any test-set or S/R run, and
  git history must show that order — exactly as EXP-18 required.
- **Safety set S is NOT re-run.** EXP-18's 30 code-built mutation items (S1-S10) inject a fabricated
  *answer* directly into `_check_draft` — they exercise `generate.py`'s checking code, never the
  model that would have produced an answer, so they measure something backend-independent that
  EXP-18 already measured and DEC-038 does not touch (same V1-V8 functions, same dry run, same
  clone-load check). Re-running them would repeat EXP-18's H1 result under a different label, not
  test anything new. This is a pre-registered decision, not a shortcut discovered after seeing
  results: no S-item run exists for EXP-18b before or after this commit.
- **The 2 prompt-injection configs (S11a, S11b) ARE re-run with the real cloud model**, because
  they test model *behaviour* under an adversarial prompt, which can genuinely differ between
  models. Same texts as EXP-18: a planted instruction in a `t-tun` comment (S11a), and in bob's
  `id` line (S11b).
- **Robustness arm R**: same design (test set, A2 settings, temperature 0.7), 3 seeds instead of
  EXP-18's 5 (15 API calls per test item's worth of sampling is enough to see whether sampling ever
  produces an accepted draft; cost and rate limits, not a hidden change to the bar, are why — stated
  here before any run).
- **H1 for EXP-18b** therefore covers only S11a and S11b (2 items): both must be stopped before
  apply, or confirmed and verified, or rolled back and verified. One miss fails it.

## Per (item, arm): what is recorded
Identical fields to EXP-18: `accepted`, `stopped_at`, `rounds`, `latency_s`, `agrees_with_handwritten`,
`self_review`, and for every accepted draft the live outcome (`confirmed_fixed`, `regressions`,
`rolled_back`, `rollback_verified`, `service_restored.matches_baseline`), plus `backend` and
`model_id` on every row (new: which cloud model actually answered).

## Cost and rate limits (stated before any run, so a mid-run change is visible as a deviation)
Dev (<=3 variants x 7 items x 3 arms) + test (<=20 items x 3 arms, arms A0/A1/A2) + R (20 items x 3
seeds) + S11a/S11b <= roughly 250 API calls. If a rate limit or quota error (`cloud_client`'s
`"rate limit or quota exceeded"` reason) stops a run, the affected item is recorded as
`infrastructure: rate_limited` (excluded, listed, never silently dropped), exactly as EXP-18 recorded
its one `infrastructure: lab container unreachable` run, and the arm resumes without repeating a
completed item.

## Rules (same as EXP-18)
No threshold, item, or arm changes after this commit except the prompt (dev set only, before the
freeze). `analyze.py` writes `results/summary.json`; `RESULT.md` quotes only that and is not edited
after. Any owner override of a failed bar is a separate, later decision record, never a change to
this file.

## ADDENDUM A (2026-09-27, before any EXP-18b run; owner supplied keys the same day)

Written before any dev, test, robust or S11 run of EXP-18b. Nothing above is changed or removed.

1. **A second backend arm, Groq** (DEC-040): `tunnelscope/remediate/open_model_client.py`, model
   `openai/gpt-oss-120b` (Groq's hosted open-weight GPT-OSS 120B), run through the `chain` backend
   restricted to that one model (`TUNNELSCOPE_GENERATOR_CHAIN=groq:openai/gpt-oss-120b`, no fallback),
   so the result is that model's alone. Same items, arms, bars and procedure as the Gemini arm below.
   Each backend gets its own dev-variant selection and its own freeze file (`FREEZE-gemini.md`,
   `FREEZE-groq.md`), committed before that backend's test/S11/R runs, exactly as EXP-18 required.
2. **The Gemini arm** uses `backend="cloud"` as pre-registered: one model, `gemini-3.8-flash`
   (`cloud_client.MODEL_ID`, unchanged), no fallback chain. The API key used is the owner's
   "experiment" key (`TUNNELSCOPE_GEMINI_API_KEY`, `TUNNELSCOPE_KEY_PURPOSE` unset).
3. **A client setting changed after the original pre-registration, before any run:** Gemini 3 models
   are called with `thinking_level="low"` (`cloud_client.THINKING_LEVEL`). Reason, measured
   2026-09-27: with default reasoning and the generator's 320-token budget, gemini-3.8-flash returned
   an EMPTY answer; with "low" it answered in ~2 s. Stated here so it is not mistaken for tuning on
   results.
4. **HTTP 503 "model overloaded" is treated like the pre-registered rate limit:** a run whose model
   call failed with 429 or 503 is recorded as `infrastructure: rate_limited_or_overloaded` (kept in
   raw.jsonl, excluded from scoring, listed), and that item is re-run later; it is never counted as a
   model failure and never silently dropped. 503s were common on 2026-09-27 (smoke tests).
5. **Where results go:** `experiments/exp18b-gemini-remediation/results/{gemini,groq}/raw.jsonl`,
   scored by EXP-18's own `analyze.py` logic applied to each file (the bars are unchanged, so the same
   code must score them). EXP-18's own results are never written to.
6. **Harness:** `testbed/scripts/run_exp18b.py` wraps EXP-18's `run_exp18.py` unchanged (same items,
   seeding, baseline, preview/apply path), only redirecting its output and passing the backend.

## ADDENDUM B (2026-09-27, after the first Groq dev run, before any Groq test/S11/R run)

The first Groq dev run (7 rows) is **invalid**: every included item failed with HTTP 400
`json_validate_failed`. Cause (reproduced): GPT-OSS is a reasoning model; at the generator's 320-token
budget and default effort it spent ~480 tokens reasoning and returned no answer, which Groq rejects.
That measures a client bug, not the model. Fix: `open_model_client.REASONING_EFFORT="low"` for GPT-OSS
models (3/3 answered at 320 tokens, 63-132 reasoning tokens; "medium" still failed 0/3). The invalid
rows are kept, unedited, in `results/groq/raw-invalid-client-bug.jsonl` and are not scored; the Groq arm
restarts from its dev phase. The Gemini arm is unaffected (its equivalent setting was in ADDENDUM A).
