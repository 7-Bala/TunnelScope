# Remediation loop — roadmap (not built yet)

## Where this came from

Judge feedback, review round, 2026-09-22 (paraphrased): TunnelScope is still "traditional" —
it hands the auditor a report and stops there. The auditor still has to read it, decide what to
patch, and do the patching by hand. The ask: TunnelScope should propose a fix, ask the human to
decide, and — on approval — actually carry it out, the way an agent does, not just display data.

This document is the design for that. **Nothing in it is built.** It is scoped so the next
phase can build it without redesigning the honesty rules the rest of the project already
follows. If SIH round timing allows, this becomes the next set of Antigravity handoff tasks.

## Why this fits the project instead of contradicting it

TunnelScope's whole design is "never claim more than the evidence supports, and label
everything by how it was known." A remediation feature could easily break that — "I patched it"
is a much bigger claim than "OBSERVED: cipher is 3DES." So the design keeps three rules from
the rest of the project and adds one new one:

1. **A plan is still evidence-labelled.** A proposed fix is generated only from the rule that
   failed, never invented. No LLM, same as `tunnelscope/explain/explain.py`.
2. **Nothing executes without a human decision.** This isn't a UX nicety — it's the same
   boundary the whole project draws between "what we found" and "what we're sure of." Acting on
   a live network without a human clicking Approve is a bigger overclaim than any text finding.
3. **A claimed fix must be re-verified from evidence, not assumed.** After a change is applied,
   TunnelScope re-captures and re-analyses the tunnel and reports whether the verdict actually
   flipped to PASS — not whether the command exited 0.
4. **New: default target is the lab only.** Config-changing commands must never point at a
   real, unspecified endpoint by default. A human must explicitly name the target each time.

## The three stages

```
FAIL verdict (already exists)
        │
        ▼
┌───────────────────┐
│ 1. Plan            │  deterministic, from the rule ID — extends the existing glossary
│    (no execution)  │  with a 4th field: remediation_commands
└─────────┬──────────┘
          ▼
┌───────────────────┐
│ 2. Human decision   │  dashboard shows the plan; Approve / Reject buttons;
│    (blocking gate)  │  nothing past this point runs without a click
└─────────┬──────────┘
          ▼ (Approve only)
┌───────────────────┐
│ 3. Execute + verify │  apply the config change to the named endpoint (lab by default),
│                     │  reload the tunnel, RE-CAPTURE, re-run analysis, report the new verdict
└────────────────────┘
```

Reject stops at stage 2 and just records the decision (for the audit trail — "flagged,
human declined, reason: X" is itself useful evidence for a compliance report).

## A note on stage 1's prose (added 2026-09-22)

Stage 1's commands and rule targeting must stay exactly as deterministic as the table below —
that does not change. Its human-facing "why this matters" sentence, however, is a candidate for
the local, on-device MLX rephrasing layer designed in `build/10-LOCAL-AI-RUNTIME.md` (DEC-031):
optional, off by default, rewords only, never touches which command runs or which endpoint it
targets. Read that document before building either this or the rephrase layer, since they share
one boundary — a model may reword a finished sentence, never decide a fact.

## Stage 1: the remediation glossary

Same shape as `GLOSSARY` in `tunnelscope/explain/explain.py`, one dict entry per rule ID, but
with commands instead of prose. Draft below, written from the existing "what to do" text —
this is what stage 1 would ship with. Every command targets `swanctl` (strongSwan) because
that's what the lab runs; a Libreswan or vendor-appliance variant is a second column, later.

| Rule ID | What changes | Draft swanctl fix |
|---|---|---|
| `V-207205` | Move IKEv1 → IKEv2 | set `version = 2` in the connection's `swanctl.conf`, `swanctl --load-all` |
| `V-207193` | Raise the DH group | set `proposals` to include `ecp384` or `modp4096`, remove the weak group, reload |
| `V-207223` | Raise integrity to SHA-384+ | set proposal integrity to `sha384`/`sha512`, reload |
| `RFC8247-DH-MUST` | Drop a forbidden DH group that was picked | remove it from `proposals`, reload |
| `RFC8247-DH-OFFER` | Drop a forbidden DH group still offered | same edit on the OTHER endpoint's config (the one still offering it) |
| `RFC8247-ENCR` | Handshake cipher → AES-GCM | set IKE proposal to `aes256gcm16`, reload |
| `CVE-2026-78135` | Patch, not a config change | this one is a software-patch instruction, not a config diff — plan says so, no auto-execute |
| `DST-PQ-KE` | Add hybrid PQ key exchange | set proposals to include `ke1_ke2 = ke1_mlkem768` (or vendor equivalent), reload |
| `DST-PQ-DOWNGRADE` | Stop allowing classical-only fallback | remove the classical-only proposal from the list entirely (no fallback offered) |
| `RFC4301-CONFIDENTIALITY` | AH → ESP | change `esp_proposals` in place of `ah_proposals`, reload (bigger config change, flagged as such) |
| `RFC8221-AH-INTEG` | AH integrity off MD5 | set AH integrity to `sha256`/`sha512`, reload |
| `RFC8221-AH-LEGACY` | AH integrity off legacy 96-bit | same as above |
| `RFC8221-ESP-3DES` | ESP cipher off 3DES | set `esp_proposals` to `aes256gcm16`, reload |
| `RFC4303-SEQ` | Not a config fix | replay is a symptom (misconfigured anti-replay window, or an attack) — plan says "investigate," no command |

Two rules (`CVE-2026-78135`, `RFC4303-SEQ`) don't get an auto-apply command even in the full
build — they're diagnostic, not configuration, findings. The plan for those stays advisory
text, same as today. That split should stay explicit in the UI (a "Patch" button vs an
"Investigate" note), not hidden.

## Stage 2: the human gate

- Dashboard: each FAIL verdict gets a "Propose fix" action. Clicking it shows the plan
  (which config lines change, the exact commands, which endpoint) — not a black box.
- Two buttons: **Approve** (targets must be explicit — no default endpoint), **Reject**
  (with an optional reason, logged).
- No auto-approve setting, ever, in this design. If a future customer wants unattended
  remediation, that's a different, explicitly-named feature with its own review — not a flag
  on this one.

## Stage 3: execute + verify

- On Approve, TunnelScope connects to the named endpoint (lab: `docker exec`; later: SSH with
  credentials the operator supplies, never stored) and applies the change.
- Reloads the tunnel (`swanctl --load-all` / `--initiate`).
- Re-captures traffic on the same interface for a short window.
- Re-runs the full analysis pipeline on the new capture.
- Reports: did the specific verdict that triggered this flip to PASS? If not — say so plainly,
  the same way a failed experiment prediction is reported today. "Patch applied, verdict still
  FAILS" is a valid, honest outcome, not a bug to hide.

## What "done" looks like for a first prototype

Scoped small, lab-only, one rule end-to-end as a proof before generalising:

1. Extend the glossary (`tunnelscope/explain/explain.py` or a new `tunnelscope/remediate/`
   module) with `remediation_commands` for the rules that have a real config fix.
2. New API endpoint: `POST /api/remediate/plan` (returns the plan, no side effect).
3. New API endpoint: `POST /api/remediate/apply` (requires an explicit `target` and
   `approved: true`; executes stage 3; returns the before/after verdict).
4. Dashboard: Propose fix / Approve / Reject UI, and a stage-3 progress + result view.
5. One end-to-end test: fail a rule in the lab (e.g. force a weak DH group), propose,
   approve, apply, re-capture, confirm the verdict flips — exactly the loop above, automated.
6. Explicit refusal test: `apply` without `approved: true`, or with no `target`, must error
   and change nothing — this is the test that proves the human gate can't be bypassed.

None of this touches the existing passive-analysis pipeline; it's a new, additive module gated
entirely behind human approval, in keeping with the rest of the project's evidence discipline.

## What this is NOT

- Not autonomous remediation. Never executes without a per-action human Approve.
- Not a general SSH/config tool. It only runs the specific, glossary-defined command for the
  specific rule that failed — no arbitrary command execution.
- Not claiming success without re-checking. "Applied" and "fixed" are two different findings,
  and the second one always comes from a fresh capture, never assumed from the first.
