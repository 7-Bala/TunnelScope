# EXP-06 — Failure-Mode Diagnosis: Round 1 Result — **INCONCLUSIVE (testbed design flaw found)**

**Status: not a hypothesis test yet.** The captures are contaminated by a testbed design flaw
discovered while analyzing them. Reported honestly rather than forced into a conclusion, per the
project's own rule that a negative result is a valid result.

## What was attempted

Two deliberate misconfigurations were added between alice and bob (classical arm):
- `fail-proposal-mismatch`: alice offers `esp_proposals = aes256gcm16`, bob only accepts
  `aes128-sha256` → expected `NO_PROPOSAL_CHOSEN`.
- `fail-ts-mismatch`: bob's child config only accepts traffic from `10.10.1.99/32`, but alice is
  `10.10.1.10` → expected `TS_UNACCEPTABLE`.

Both produced the **correct, expected failure notify** at the IKE layer (confirmed via strongSwan's
own log: `received NO_PROPOSAL_CHOSEN notify, no CHILD_SA built` and
`received TS_UNACCEPTABLE notify, no CHILD_SA built` respectively) — the misconfigurations
themselves worked as intended.

## The contamination found

`swanctl --list-sas` during analysis showed **`cs-aes256gcm16` (a fully successful, earlier arm)
still installed** at the same time, with `reqid 1` and the **same traffic selector**
(`10.10.1.10/32 === 10.10.2.10/32`) as both failure arms — because every arm in this testbed
(`experiment_matrix.json`) uses the same two host addresses as its traffic selector.

Consequence: the kernel XFRM policy for that exact selector pair is shared across all arms. When
`run_arm.sh`'s probe loop pinged through the "failed" arms, the ping traffic was actually
**silently routed through the leftover working `cs-aes256gcm16` SA** — producing spurious ESP
traffic in what should have been a no-tunnel capture, and very likely explaining the repeated
IKE_SA_INIT/IKE_AUTH sequences seen in both failure captures (unrelated activity sharing the
capture window, not a retry pattern belonging to the failure itself).

A second, smaller confound was also found: the two failure arms' IKE identities
(`alice-fail-proposal-mismatch` vs `alice-fail-ts-mismatch`) are different lengths, which shifts
the encrypted `IKE_AUTH` message size independently of the failure mode itself — a naive
before/after length comparison would have attributed an ID-string-length artifact to the failure
type.

## Why this is reported now rather than patched and re-run silently

Per the project's honesty requirements: this is exactly the class of result that must not be
smoothed over. The underlying signal (does a failure mode have a detectable structural signature)
may still be real — PE-02 in the research base gives good reason to expect it — but **this round's
data does not test it cleanly**, and reporting a conclusion from it would be indefensible.

## What should change for round 2

1. Give every experiment arm its **own, non-overlapping traffic selector** (e.g. a distinct `/32`
   alias address per arm, or distinct `reqid`s) so XFRM policies cannot cross-route between arms —
   this is a testbed generator change (`experiment_matrix.json` / `gen_swanctl_conf.py`), not a
   protocol question.
2. **Equalize or parametrize ID string length** across compared arms, or exclude `IDi`/`IDr` from
   any length-based comparison, to remove that confound.
3. **Explicitly terminate every OTHER arm's SA**, not just the target arm's own prior instance,
   before each capture — `run_arm.sh` currently only does `swanctl --terminate --ike "$ARM"`.
4. Re-run with a **larger set of failure modes** (PFS mismatch, lifetime-driven rekey race,
   auth failure) once the above is fixed, per the original EXP-06 design intent
   (`registers/EXPERIMENT-REGISTER.md`).

## What is still true and useful from this round

- Both misconfigurations correctly and reliably triggered their intended IKE-layer failure
  (confirmed via `swanctl`/charon logs — T2 evidence, not inferred).
- The specific failure **reason** (`NO_PROPOSAL_CHOSEN` vs `TS_UNACCEPTABLE`) is, as F-01 predicts,
  **only visible in the encrypted `IKE_AUTH` response** and in endpoint logs — not recoverable from
  the raw capture alone. This is a small but genuine reconfirmation of F-01 in a new context (a
  negotiation *failure*, not just a successful one), and is consistent with the practitioner
  evidence in `research/03-DISCOVER-stakeholders.md` (PE-01: *"won't be visible in a packet capture
  unless the pcap is manually decrypted"*).

## Register update

Recorded in `registers/EXPERIMENT-REGISTER.md` as **EXP-06: ROUND 1 INCONCLUSIVE — testbed flaw
identified and documented; round 2 requires generator changes**. Not marked done.
