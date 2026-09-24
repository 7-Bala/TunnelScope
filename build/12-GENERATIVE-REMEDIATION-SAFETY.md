# Generative remediation, safely — design (safety layers built; generator not built)

> **Status 2026-09-24.** Steps 2 and 4-8 below are built, tested against a fake lab that holds
> real file contents (`tests/fake_lab.py`), and proven in the live Docker lab. **Step 1 (the
> generator) is not built:** every plan and every command is still written by hand in
> `tunnelscope/remediate/plan.py`. Step 3 (self-critique) needs a generator and is not built.
> See "Review of the first build" at the end for what the first implementation got wrong.

## What was asked

User, 2026-09-23: the remediation plan should be AI-generated (problem + solution + real
terminal commands, not just a fixed dictionary), because a fixed 14-rule table can't scale to
every vulnerability — that's the whole point of bridging the gap traditional tools can't. But it
must not hallucinate, and even after every safeguard, there must be a rollback that undoes ANY
size of damage. The user's own proposed design: generate → the agent re-reviews its own plan and
fixes it if wrong → human approves or declines → if it still hallucinates, roll back to the
previous state regardless of how large the damage is.

**The user's design is fundamentally the right shape and is kept.** Two layers are added that
don't depend on the model being right: a deterministic allowlist check, and a sandboxed dry-run
before anything touches the real target. Those are what make "even if it hallucinates" survivable
instead of just less likely.

## DEC-033

**Extends DEC-031/032's boundary.** DEC-031 said a local model may reword a fact, never
originate one. DEC-032 said a local model may suggest an investigation, never assert a fix. This
decision opens a narrow, heavily-guarded exception: a local model MAY draft new remediation
commands for rules outside the Stage-1 dictionary, but a drafted command can only ever reach a
real target after passing three checks that do not depend on the model being correct — a
deterministic allowlist, a sandboxed dry-run whose actual diff is checked programmatically
against the claim, and an explicit human approval shown the real dry-run result, not a promise.
Even after all three, every apply is preceded by a snapshot sufficient to fully undo it.

Rationale: an LLM generating shell commands is a documented hallucination hotspot — the failure
mode isn't "obviously wrong," it's "plausible and wrong," which is the hardest case for a human
reviewer to catch by eye. The mitigation is not "trust the model less" (unmeasurable) but "verify
the model's output against reality before it can matter" (measurable, and provably safe even at
100% model reliability = 0%, since the allowlist and dry-run don't rely on the model at all).

## The pipeline

```
1. GENERATE        Local model (same runtime as DEC-031/032) drafts a schema-locked plan:
                    {problem, why_it_matters, commands: [...], expected_diff, target}.
                    Grounded on the same evidence (rule_id, verdict, observed value) as
                    Stage 1's dictionary entries — never given free rein, always given the
                    specific finding it's explaining.

2. STATIC ALLOWLIST Deterministic code, not a model. Parses each command (a real shell
   (not a model)    parser -- do not regex-guess) and rejects anything that is not
                     `sed`/`swanctl` operating on a path already known to be a config file
                     inside the named target container. No `rm`, no `dd`, no piping, no
                     `docker` subcommands, no network tools, no wildcards outside the
                     specific config directories already used by Stage 3. This step alone
                     makes destructive commands categorically unreachable, independent of
                     model quality.

3. SELF-CRITIQUE    The user's idea, kept as designed: the model re-reads its own drafted
   (the model)      plan against the original problem statement and either confirms or
                     revises. Catches logic errors the allowlist can't (right command, wrong
                     field; a fix that doesn't address the stated problem).

4. SANDBOXED        NEW. `docker commit` the target container to a throwaway image, run the
   DRY RUN          plan against a disposable clone (never the real target), and read back
                     the actual resulting config. Compare it PROGRAMMATICALLY against the
                     plan's own `expected_diff` claim. Mismatch = automatic reject, no human
                     ever sees a plan whose claimed effect isn't what it actually does.
                     Destroy the clone after.

5. HUMAN GATE       Show: problem, solution, exact commands, AND the real dry-run diff (not
   (existing UI,    a promise -- the proven effect from step 4). Approve / Reject, exactly
   extended)         as Stage 2 already works.

6. SNAPSHOT         NEW, this is the rollback plan. Before the REAL target is touched: save
   (before apply)   (a) the exact current content of every file about to change, and (b) a
                     full `docker commit` image of the target container. (b) is what makes
                     "no matter how large the wipeout" literally true -- even a container
                     that won't boot can be discarded and replaced from the image.

7. APPLY + VERIFY   Run for real (Stage 3, unchanged). Re-capture. Check ALL verdicts for
   (existing,       that tunnel, not just the target rule -- a plan that fixes one thing
   widened check)   while silently breaking another must be caught here.

8. AUTO-ROLLBACK    NEW. If the target verdict didn't improve, OR any other verdict on that
                     tunnel got worse, OR the tunnel dropped entirely (no SA): restore from
                     the step-6 snapshot immediately, without waiting for a human to notice.
                     Config-level restore (write back the saved file, reload) for the common
                     case; full `docker commit` image restore for the case where the
                     container itself is broken. Log the rollback with the same audit
                     discipline as every other action, then surface the outcome to the human
                     -- the rollback itself is not optional or asked-for, only reported.
```

## Why this answers "what if it hallucinates and wipes something out"

Every layer that stands between a hallucinated command and real damage (2, 4, 6, 8) is
**deterministic code, not a model** — their correctness doesn't depend on the generator being
good. That's the actual answer to "how do we prevent it," stated honestly: we don't prevent the
model from hallucinating, we prevent a hallucination from ever reaching an unrecoverable state.
Even in the worst case — the model is wrong, self-critique misses it, and a human approves a bad
plan — step 8 catches the result (a verdict got worse or the tunnel dropped) and reverts it
without asking. The snapshot in step 6 means "revert" is never partial: it's the exact
pre-change state, not a best-effort undo.

## The "does not hallucinate (very rarely)" claim — measured, not asserted

Do not ship this claim without a number behind it, per this project's own standing rule. Build an
evaluation harness the same way EXP-16/EXP-17 measured the traffic classifier:

- **Pre-register** (before running): N generated plans across every rule type (including some
  deliberately hard/ambiguous ones), a pass bar for step 4's diff-match rate, and a set of
  deliberately injected bad commands (wrong flag, wrong file, a destructive verb) that the
  allowlist and dry-run MUST catch 100% of — this is the adversarial half of the experiment,
  proving the safety layers work even when the model is deliberately wrong.
- **Report both numbers separately**: "the generator needed no revision in X% of trials" (a
  claim about the model, inherently imperfect) and "the allowlist + dry-run caught Y% of
  injected bad commands" (a claim about the safety net, which should be 100% — if it isn't,
  that is the finding, not something to average away).
- This is a real experiment, `experiments/exp18-generative-remediation-safety/` in the project's
  own convention (`PREREG.md` before running, `analyze.py`, `RESULT.md` after) — not a demo
  anecdote. A judge who asks "how do you know it doesn't hallucinate" gets a measured answer,
  the same way every other claim in this project has one.

## What this is NOT

- Not a replacement for Stage 1's fixed dictionary — that stays as the trusted, fast path for
  the 14 known rules. Generation is for rules OUTSIDE that table, where a fixed entry doesn't
  exist yet.
- Not a claim of zero hallucination — an honest system says "measured at X%, and the layers that
  don't depend on the model catch the rest," never "it doesn't hallucinate."
- Not a smaller blast radius by trusting the model more carefully — the blast radius is bounded
  by code (the allowlist) and recoverable by code (the snapshot), regardless of model behavior.

## Build scope, when it's time (this is large — three separable slices)

1. **Allowlist + dry-run harness** (steps 2 and 4) — buildable and testable without any
   generation at all yet; write it against Stage 3's EXISTING fixed commands first, prove it
   correctly accepts all 9 automated rules and rejects synthetic bad commands, before generation
   is even in the loop.
2. **Snapshot + auto-rollback** (steps 6 and 8) — also buildable and testable independently;
   prove a real rollback works by deliberately applying a bad change to the lab and confirming
   full recovery, config AND container-level.
3. **The generator itself** (steps 1, 3) — only once 1 and 2 exist and are proven, since a
   generator with no safety net under it is the exact risk this document exists to avoid.

Recommended order: 1, then 2, then 3 — the safety net has to exist before the thing it's
protecting against does.

## Review of the first build (2026-09-24)

The first implementation (T-097, T-098) had every layer named, but reading the code and running it
against the real lab showed most of them were weaker than their names. What was found and fixed:

| Layer | What the first build did | What was wrong | Now |
|---|---|---|---|
| 2 command check | A list of banned words (rm, curl, sudo...) plus "starts with sed or swanctl" | A deny-list, not an allowlist. 10 of 12 structural attacks passed: sed's own `e` (runs a shell), `w`, `r`, `;` chaining, backticks, `$(...)`, `&&` after the reload, editing files outside the config set. The "100% catch rate" benchmark only tested commands containing a banned word | An allowlist: the fixed sed template whose script must parse under a small grammar (`s///` with flags g/I, optionally in one address block), or the fixed reload. Plan commands are never given to a shell: sed and swanctl run as argument lists. 30/30 structural attacks refused |
| 4 dry run | Ran the commands on a scratch file in the same container, then `swanctl --load-all` on it | Returned OK on any exception and when no config existed (fail-open). Loading a file registers it with the running daemon, so it was not side-effect free. Checked only swanctl's exit code | Runs only the sed scripts on scratch copies, never loads anything, fails closed, and checks the real diff: must change something, only proposals/version lines, only inside the verified connection |
| 7 regression guard | Any other rule FAIL after the change = regression | Counted failures that existed before the change, so a correct fix on a real capture with pre-existing failures was always rolled back. `verdict_before` was hardcoded "FAIL" | Baseline capture before the change; regression = a rule that was not failing before and is now. `verdict_before` is measured |
| 6/8 snapshot + rollback | Snapshots of `/tmp` and `/etc/swanctl/conf.d` files; restore of `/tmp` only; 30 s watchdog | `/etc` edits were never restored; the 30 s watchdog could fire during a slow verification; its restore was never logged; after restoring files, the already-negotiated SA kept running on the bad settings (seen live: MODP_3072 after "rollback") | Manifest of exact files, restore of all of them, byte-for-byte check (snapshot kept if the check fails), 180 s watchdog, both sides checked intact before either is disarmed, watchdog restores logged via reconcile, and after every rollback the tunnel is re-negotiated and captured against the baseline |
| Plan content | File-wide sed edits | The lab config holds 19 connections (count corrected 2026-09-24; an earlier count of 38 included the secrets entries); the fixes rewrote all of them and renamed auth IDs containing "modp1024" (seen live); only t-tun is verified. The RFC8247-ENCR fix also rewrote esp_proposals and lowered modp4096 to modp3072. The lab-peer step changed nothing on the real config (its range ended inside `local {}`) | Every fix is scoped to the t-tun connection and mirrored on the other end of the lab tunnel; ENCR swaps only non-AES cipher tokens on the IKE line |
| UI | "AI-Assisted" badge, "Rollback Guarantee", checkmarks on layers that had not run, a static example labelled as a preview of the real config | Claims the evidence did not support | Honest labels; a real dry-run preview is required before "Apply in lab" is enabled; the result shows the measured before/after, regressions, and whether the restore and the service were verified |

**Live proof (Docker lab, 2026-09-24):** V-207193 on sih26-alice-pq with two pre-existing failures:
confirmed fixed (FAIL -> PASS), one line changed on each end, no other connection touched, tunnel
up on MODP_4096. A plausible-but-wrong command (lowers the DH group) for V-207223: not fixed and a
new regression detected, both containers restored byte for byte, tunnel re-negotiated back to
MODP_4096, post-rollback capture matches the baseline. The in-container watchdog, with the process
gone, restored a changed file on its own, re-negotiated the tunnel, and its restore was logged.

**Known limits.** Verification captures the initial handshake only: a problem that appears only
at a later child-SA rekey is not seen. The connection scope relies on the lab generator's fixed
indentation (the dry run's independent brace-matching check refuses anything outside the
connection). The Python sed emulation in the tests is not GNU sed; GNU sed 4.9 behaviour is
checked in the live lab only.

**Update 2026-09-24 (T-107, T-108).** The rekey limit is closed as far as the evidence allows: after a
confirmed fix the tunnel is forced to rekey and must stay up (endpoint-reported); what the rekey
negotiated is not observable passively and is reported as such. Verification captures now carry
traffic, so AH-LEGACY fixes are verifiable; AH-INTEG and ESP-3DES are not judgeable passively (several
candidate algorithms fit the wire) and are refused with that reason.
