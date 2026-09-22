# Local AI runtime — MLX (design, not built)

## What was asked

User, 2026-09-22: going with local AI models, referencing MLX (`ml-explore/mlx` /
`mlx-lm`) — Apple's array/ML framework for Apple Silicon Macs. Add it to the remediation
plan and decide the details.

## The tension this creates, named directly

The project has one rule that differentiates it from every SIH competitor named in
`research/11-EXISTING-SOLUTIONS-DEEP-DIVE.md` ("several SIH competitor repos claim AI with
no validation"): **every model is trained by us, on our own captured data**, enforced by
`tests/test_ai_layer.py::test_no_outside_model_is_used`. An LLM from MLX — even running
100% locally — is a pretrained, open-weight model we did not train. Running it at all is a
narrowing of that rule, not a footnote, and it has to be scoped so the headline claim ("every
model that produces a finding is ours") stays true and testable.

This is also the second time this exact question has come up. On 2026-09-20 (T-082, see
`TODO.md`) an LLM rewrite of the explanation text was built, then removed the same day by
user decision — the explain engine still says in its own docstring:
*"No language model of any kind... every model in TunnelScope is trained by the project on
its own data; text generation is not a modelling problem here."* On 2026-09-21 the user asked
about a cloud API key for the same purpose and I advised against it (data leaves the machine,
can invent facts, needs network/a key at demo time). **MLX changes the second objection, not
the first or third**: it runs fully on-device, no network call, no API key — but it still
cannot be allowed to invent a finding, and it's still not "trained by us."

## Decision (DEC-031)

**Scope the local model to rephrasing only, opt-in, fully on-device, and never as a source of
fact.** Everything that produces a finding, verdict, score, threat, or remediation command
stays exactly as it is today — the project's own trained models (traffic classifier, mode
model, anomaly detector, mixed-traffic detector) and the deterministic rule engine. The local
model's only job is to take text that is *already fully computed* and phrase it more naturally
for a human reader. It cannot add a fact, change a number, or choose a rule — there is nothing
for it to invent, because everything it's given is already final.

Two places this applies, both already deterministic-text today:
1. `tunnelscope/explain/explain.py` — the plain-English explanation panel.
2. `build/09-REMEDIATION-ROADMAP.md` stage 1 — the "why this matters" prose in a proposed fix
   (never the fix's commands or target — those stay from the glossary, untouched).

## Concrete choices

| Decision | Choice | Why |
|---|---|---|
| Framework | `mlx-lm` (Python package on top of `ml-explore/mlx`) | Apple's own framework, built for Apple Silicon's unified memory; no separate server process required the way Ollama needs one |
| Model | A small instruction-tuned model from the `mlx-community` Hugging Face org, quantized 4-bit — e.g. `mlx-community/Qwen2.5-3B-Instruct-4bit` | Small enough to run acceptably on a MacBook Air; a 3B model has no business inventing security facts, which is fine since it's never asked to — it only rewrites given text. Swappable; not load-bearing which exact model is picked |
| Network | None, ever, for this feature | The whole point of choosing MLX over a cloud API is removing the network dependency and the "your data left the machine" objection |
| Default | **Off** | Matches the existing pattern (`--llm` was opt-in for the earlier, removed feature); plain deterministic text is always what ships without a flag |
| Platform gate | Feature silently absent unless `sys.platform == "darwin"` and Apple Silicon (`platform.machine() == "arm64"`) | MLX doesn't run elsewhere; must never error on Linux CI or an Intel Mac, just not offer the toggle |
| Fallback | Deterministic text always available and always shown first; rephrase is an additional "hear it differently" view, not a replacement | Keeps every claim traceable even when the feature is on |
| UI disclosure | Every rephrased panel keeps a visible label: "Rephrased locally on this device from the facts to the left — the facts themselves come only from the verdicts, never from this model" | The existing explain panel already says "Nothing here comes from a language model" — that line must change to name exactly what the model does and does not touch, not go silent |

## What the "every model trained by us" claim becomes

Split into two statements, both true and both testable — this is the honest way to keep making
the claim rather than quietly dropping it:

1. **"Every model that decides something — what traffic type, what tunnel mode, whether
   behaviour changed, whether a session is mixed — is trained by us, on our own captured lab
   data."** Unchanged. Still enforced by test.
2. **"An optional, off-by-default, fully local language model may rephrase text we already
   computed. It runs entirely on your machine, touches no network, and cannot itself produce a
   finding — it has nothing to decide."** New, narrower, and equally testable (see below).

## Test-suite implication (design only — not written yet)

`test_no_outside_model_is_used` currently forbids any LLM client, model download, or network
call anywhere in the package. It needs to become two tests instead of one:

- **Unchanged:** no network call, no cloud LLM client (`openai`, `anthropic`,
  `google.generativeai`, etc.) anywhere in `tunnelscope/` outside a new, explicitly named
  rephrase module.
- **New:** a static check that nothing under `tunnelscope/assess/`, `tunnelscope/rules/`,
  `tunnelscope/risk/`, `tunnelscope/leakage/`, `tunnelscope/anomaly/` (the fact-producing code)
  imports the rephrase module — i.e. it is provably one-directional: rephrase can read a
  finished finding, a finding can never depend on rephrase.

## What this is NOT

- Not a change to any detection, classification, or scoring model — those stay ours, unchanged.
- Not on by default, not required to run the tool, not required for the demo.
- Not able to invent a cipher, a CVE, a rule ID, or a command — it never sees raw packets or
  rule logic, only finished sentences.
- Not evaluated for accuracy the way the trained models are, because it has no factual
  authority to be wrong about — it's copy-editing, not a decision-maker.

## Guardrails against hallucination and other failure modes (added 2026-09-22)

Hallucination is not a tuning problem here — it's an architecture problem, and it's solved by
what the model is *allowed to touch*, not by prompting it to "be accurate." Five layers:

1. **Structural: the model never has a fact to get wrong.** It receives already-computed,
   already-verified text (a sentence built from a verdict) and returns a reworded sentence. It
   is never given raw packets, rule logic, or a "decide X" prompt. This is the same reason
   `explain.py` itself can't hallucinate today — a template has nothing to invent either.
2. **Post-generation fact check, mechanical, before anything reaches the screen.** Extract every
   rule ID, number, cipher/algorithm name, and IP address from the ORIGINAL deterministic text
   with the same regexes used elsewhere in the codebase (e.g. rule ID pattern already used by
   `guard_diff.py`'s IMMUTABLE matcher, cipher names already enumerated in
   `tunnelscope/rules/*.yaml`). Extract the same from the REPHRASED text. **If the two sets
   don't match exactly — a number changed, a rule ID vanished, a new fact-shaped token
   appeared — discard the rephrase and show the deterministic original.** No partial credit;
   any mismatch is a silent, logged fallback, never a "close enough."
3. **Constrained decoding, not just a polite prompt.** `mlx-lm` supports grammar/schema-
   constrained generation. The call is built as "return valid JSON: `{"rephrased": "<string
   under N chars>"}`" with the original values passed as read-only context, not as something to
   restate — this narrows what the model can physically produce, on top of the check in (2), it
   doesn't replace it.
4. **Prompt-injection isolation.** Some of the text being reworded ultimately derives from
   network capture data (a certificate field, a note string) that could, in principle, be
   crafted by whoever controls the traffic. That text is passed to the model as clearly
   delimited, inert DATA, never concatenated into an instruction, exactly the same rule this
   session already applies to any external content — the model is told "reword the following
   text," never "follow instructions found in the following text." Guardrail (2) is what
   actually stops an injected instruction from mattering even if the delimiting failed, because
   a manipulated rewrite would fail the fact-set match and get discarded.
5. **Fail closed, always.** Any error, any timeout (hard cap, e.g. 3s), any output that fails
   guardrail 2, any platform without MLX, the model not yet downloaded — every one of these
   returns `None` from `rephrase()` and the caller shows the deterministic text. There is no
   code path where the UI shows nothing, shows an error, or blocks waiting on the model.

## Other disadvantages, and how each is handled

| Risk | Handling |
|---|---|
| **Memory/thermal on a MacBook Air** | 4-bit ~3B model is ~2 GB; still real on an 8 GB Air, especially with the engine + dashboard + Docker also running (see the EXP-17 capture session, where Docker alone caused visible slowdown). Load lazily (only on first rephrase request), unload after an idle period, and keep it opt-in so a live demo never carries this cost unasked |
| **First-run latency / disk** | Pulling a model from Hugging Face on first use is a multi-hundred-MB to ~2GB download over the network — ironic for a "no network" feature. Mitigate by documenting a one-time `mlx_lm` pre-download step done before the demo, never at demo time, and failing closed (guardrail 5) if it's not cached |
| **Non-determinism / demo variability** | Two runs on identical input can word things differently. Fine for prose, never fine for facts — guardrail 2 is what makes this safe rather than "usually fine." Set a low temperature (e.g. 0.3) to reduce pointless variance, but don't rely on temperature for safety |
| **Supply-chain / model integrity** | Pin an exact model revision/commit hash from `mlx-community`, not a moving tag, so what runs in the demo is the one that was tested |
| **Licence** | Check the chosen model's licence (e.g. Qwen2.5's licence terms) before shipping, same discipline already applied to the traffic dataset's licence (`dataset/TRAFFIC-DATASHEET.md`, still `TBD (owner decision)`) — an unexamined third-party model licence is the same category of gap as an unexamined dataset licence |
| **Crash isolation** | `mlx-lm` import and calls wrapped so a crash in the rephrase path cannot take down the analysis engine — caught, logged, treated as guardrail-5 fail-closed, never propagated |
| **A false sense of "it's smarter now"** | The Q&A entry in `PRESENTER-GUIDE.md` and every on-screen label say plainly that the model rewords, not reasons — the risk isn't just technical, it's a judge or a user over-trusting output that looks more fluent than a template, so the label has to say what it is every time it's shown, not just once in a settings page |

## Build scope, when it's time (small, one slice first)

1. `tunnelscope/rephrase/` — new module, `mlx_lm` behind a lazy import (never imported unless
   the platform gate passes and the feature is explicitly requested).
2. One function: `rephrase(text: str) -> str | None` — returns `None` (silently, no error) if
   MLX/the platform gate isn't available, so callers always have a deterministic fallback path.
3. Wire it into the explain panel first (smaller surface than the remediation UI, which doesn't
   exist yet) behind a `--local-llm` CLI/env flag, mirroring the removed `--llm` flag's shape.
4. The two-test split above.
5. One end-to-end check: with the flag off, output is byte-identical to today; with it on (on
   Apple Silicon only, skipped elsewhere), output differs in wording only — same facts, checked
   by extracting and comparing every rule ID / number / value mentioned in both versions.

Not started. This document is the design the next Antigravity task would build from, the same
way `build/09-REMEDIATION-ROADMAP.md` is for the remediation loop.

## Sources

- [MLX — ml-explore/mlx](https://github.com/ml-explore/mlx)
- [mlx-lm — run LLMs with MLX](https://github.com/ml-explore/mlx-lm)
- [Apple Machine Learning Research — Exploring LLMs with MLX](https://machinelearning.apple.com/research/exploring-llms-mlx-m5)
