# Task 06: local, on-device rephrase layer (MLX) — first slice only

Purpose: judges asked whether we use AI beyond display, and separately whether we'd use a
local model. Design is settled — `build/10-LOCAL-AI-RUNTIME.md` (DEC-031, DEC-032). This task
builds ONLY the smallest slice: a rephrase module wired into the existing explain panel,
off by default, with the guardrails that make it safe. It does NOT touch remediation
(`build/09-REMEDIATION-ROADMAP.md` — separate, later task) or the "suggest" triage tier
(DEC-032 — separate, later task).

- Branch: `task/local-rephrase-mlx`
- You may create/edit: `tunnelscope/rephrase/__init__.py`, `tunnelscope/rephrase/rephrase.py`,
  `tunnelscope/explain/explain.py`, `tunnelscope/cli.py`, `tests/test_rephrase.py`,
  `tests/test_ai_layer.py`, `TODO.md`
- Do NOT edit: anything under `tunnelscope/assess/`, `tunnelscope/rules/`, `tunnelscope/risk/`,
  `tunnelscope/leakage/`, `tunnelscope/anomaly/` — none of this touches verdicts.
- Run checks as: `ALLOW="tunnelscope/rephrase/ tunnelscope/explain/explain.py tunnelscope/cli.py tests/test_rephrase.py tests/test_ai_layer.py TODO.md" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md` and `.agents/rules/10-python-package.md`
first. Then read `build/10-LOCAL-AI-RUNTIME.md` completely — it is the design this task builds,
including DEC-031's boundary (a model may reword an already-computed fact, never originate one)
and the five guardrails. Do not deviate from that design; if something in it seems wrong, stop
and say why rather than building around it.

Create branch `task/local-rephrase-mlx` from `main`.

STEP 1. `pip install mlx-lm` into `.venv` (it is Apple-Silicon-only; if this machine cannot
install it, STOP and report the exact error — do not fake the feature with a stub).

STEP 2. Write `tunnelscope/rephrase/rephrase.py`:

  a. `MODEL_ID = "openbmb/MiniCPM5-2B-MLX"` (the publisher's own official MLX release — confirmed
     to exist 2026-09-22; do not substitute a third-party re-conversion). A module-level
     `FALLBACK_MODEL_ID = "unsloth/gemma-4-E4B-it-UD-MLX-4bit"` for later, not used by this task.

  b. `available() -> bool`: True only if `sys.platform == "darwin"` AND
     `platform.machine() == "arm64"` AND `mlx_lm` imports successfully (lazy import inside the
     function, wrapped in try/except ImportError, never at module level — this file must import
     cleanly on Linux CI and on an Intel Mac, it just reports `available() == False` there).

  c. A fact-extraction helper, e.g. `_facts(text: str) -> set[str]`, using regex, that pulls out:
     rule IDs (pattern used elsewhere in this codebase for IDs like `V-207193`, `RFC8247-DH-MUST`,
     `CVE-2026-78135` — look at `tunnelscope/explain/explain.py`'s `GLOSSARY` keys for the exact
     shapes), any number (`\d+(\.\d+)?`), and any token from a closed list of cipher/algorithm
     names you collect from `tunnelscope/rules/*.yaml` (e.g. `AES-GCM`, `3DES`, `SHA-1`, `MODP-1024`,
     `ML-KEM`, etc. — read the YAML files, do not hand-guess the list).

  d. `rephrase(text: str, timeout_s: float = 3.0) -> str | None`:
     - Returns `None` immediately if `available()` is False.
     - Loads the model lazily (module-level cache so it loads once per process, not per call).
     - Prompts the model to reword `text` into more natural prose, returning ONLY the reworded
       text — no preamble, no markdown. Keep the prompt short; do not ask the model to add
       anything, only to reword.
     - Enforces the `timeout_s` cap (run generation in a thread with a join timeout, or use
       `mlx_lm`'s own max-token limit sized so generation cannot run long on a short input —
       pick whichever is simpler to implement correctly).
     - **Guardrail 2, mandatory, not optional:** compute `_facts(text)` and `_facts(result)`.
       If they are not EXACTLY equal, discard the result and return `None`. Do not log the
       rejected text anywhere a judge or user would see it — log only that a rephrase was
       discarded and why (fact-set mismatch), for our own debugging.
     - Any exception anywhere in this function (model load failure, generation error, timeout)
       is caught and returns `None`. This function must never raise.

  e. Do not call this function on ANYTHING originating outside `tunnelscope/explain/explain.py`'s
     own generated text in this task — that is the whole boundary DEC-031 draws.

STEP 3. Wire it into `tunnelscope/explain/explain.py`. Read the whole file first — it is short.
Add an optional parameter to `explain_sa` (or wrap its output after the fact, whichever is a
smaller diff) that, when a new flag is on, calls `rephrase()` on the `summary` field and each
`points[i]["text"]` field individually (never the whole blob at once — keeps guardrail 2's
fact-check meaningful per-sentence rather than diluted across a paragraph). Store the result
in a NEW field, e.g. `points[i]["text_rephrased"]`, alongside the original `text` — never
replace the original. Same for `summary_rephrased`. When `rephrase()` returns `None` for any
field, that field's `_rephrased` key is simply absent — the caller always has the original.

STEP 4. Add a flag: `--local-llm` on the CLI (`tunnelscope/cli.py`, look at how `--llm` worked
before it was removed in T-082's history if any trace remains, otherwise add cleanly) and an
equivalent env var or server-side flag so the API can also opt in. Off by default — calling
`explain_sa` without the flag must produce byte-identical output to before this task, with no
`_rephrased` keys at all.

STEP 5. Test-suite split (this is the part that must not be done carelessly):

  a. In `tests/test_ai_layer.py`, `test_no_outside_model_is_used` currently scans the WHOLE
     `tunnelscope/` package for banned words including `"huggingface"` and `"transformers"`.
     Since `mlx_lm` legitimately downloads from Hugging Face Hub, this task's new module will
     trip that check as written. Fix it correctly: exclude ONLY `tunnelscope/rephrase/` from
     this scan (not the whole package, not other banned words — `"anthropic"`, `"openai"`,
     `"ollama"`, `"gemini"`, `"urllib.request.urlopen"` must still be banned everywhere
     including `tunnelscope/rephrase/`, since this feature must never call a network API).

  b. Add a NEW test, e.g. `test_rephrase_is_never_imported_by_fact_producing_code`, that scans
     `tunnelscope/assess/`, `tunnelscope/rules/` (the `.py` loader, not the YAML data),
     `tunnelscope/risk/`, `tunnelscope/leakage/`, `tunnelscope/anomaly/` and asserts none of
     them contain the string `rephrase` — this is the one-directional check DEC-031 promises:
     a finding can never depend on the rephrase module.

STEP 6. Write `tests/test_rephrase.py`:
  a. `available()` returns a bool without raising, on any platform.
  b. `rephrase()` on a platform/environment where `available()` is False returns `None`
     (this test must pass in CI, which is Linux — do not skip it, it is the fail-closed proof).
  c. The fact-extractor: construct a string with a known rule ID, a number, and a cipher name;
     assert `_facts()` finds all three.
  d. A discard test: call the internal guardrail-2 comparison directly (not the live model,
     to keep CI fast and not require MLX) with two fabricated fact-sets that differ, and assert
     the function that decides "keep or discard" returns discard — you may need to factor the
     compare-and-decide step into its own small function to test it without invoking the model.
  e. With the flag off, `explain_sa()`'s output must be byte-identical to a captured baseline
     from before this task (diff the JSON).

STEP 7. If MLX is actually available on this machine (it is a Mac), do ONE live end-to-end
check by hand: run `explain_sa` on a real capture with the flag on, print both the original and
rephrased text for a couple of findings, and confirm by eye that the facts match and the wording
differs. Paste this output in your report — it is the only place a live model call is expected
to appear at all. If MLX is not available in this environment, say so plainly and skip this step;
do not fake output.

STEP 8. `ALLOW="tunnelscope/rephrase/ tunnelscope/explain/explain.py tunnelscope/cli.py tests/test_rephrase.py tests/test_ai_layer.py TODO.md" build/check_all.sh --fast` must be `RESULT: PASS`.
Add one line to `TODO.md`. Commit: `T-093: local on-device rephrase layer (MLX, off by default)`,
with no Co-Authored-By line.

REPORT: the check table, the new test file's pass output, confirmation that the flag-off path
is byte-identical to before, and — if MLX was available — the live rephrase example from STEP 7.

## DONE WHEN

- Default (flag off) behaviour is provably unchanged (byte-identical JSON).
- Guardrail 2 (fact-set match) is implemented as the mandatory gate, not a suggestion, and has
  a real test proving a mismatch gets discarded.
- The one-directional import test (STEP 5b) passes — no fact-producing module mentions
  `rephrase`.
- `test_no_outside_model_is_used` still bans every network AI client everywhere, including in
  the new module — only the Hugging Face/transformers substrings are scoped out, and only for
  `tunnelscope/rephrase/`.
- `RESULT: PASS`.
