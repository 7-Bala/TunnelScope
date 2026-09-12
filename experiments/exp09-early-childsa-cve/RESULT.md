# EXP-09 (T-022) — Passive detection of the CVE-2026-78135 pattern (early Child SA before auth)

**Date:** 2026-09-12 (updated) · **Status:** DONE (detector shipped in the package; specificity AND
plaintext-structural sensitivity validated; live-crypto-exploit reproduction still out of scope with
reason) · **Closes:** OQ-31

## The CVE
strongSwan 6.1.0 fixed **CVE-2026-78135**: a peer could obtain a **usable Child SA from a
CREATE_CHILD_SA exchange before IKE_AUTH completed** (affects 5.9.7+). The hypothesis (doc 11,
RL-033): because IKEv2 exchange type, message ID and SPIs are **plaintext**, this pattern should be
visible to a passive observer.

## Detector
For an IKE SPI pair, fire iff **all three** hold on the wire:
1. `IKE_SA_INIT` (exchange type 34) is present — i.e. the observer saw the SA *from birth*;
2. **no** `IKE_AUTH` (type 35) exchange for it;
3. a `CREATE_CHILD_SA` (type 36) appears.
If (1) is false, the SA predates the capture → **UNKNOWN**, never a detection.

## Result — specificity
Scanned **69 legitimate captures** (all testbed captures across EXP-01…08, both implementations):

| Detector | False positives | UNKNOWN (SA predates capture) |
|---|---|---|
| Naïve ("CREATE_CHILD_SA without prior IKE_AUTH") | **2** | — |
| **Vantage-aware (requires IKE_SA_INIT present)** | **0** | 2 |

The two flagged captures under the naïve rule are the EXP-03 `rekey-*` captures, which start
**after** the tunnel is up and so never contain the IKE_AUTH. The vantage-aware detector correctly
returns UNKNOWN for them instead of a false alarm. **This is the project's vantage discipline
(DEC-003/008) catching a real error class**: "I didn't see the handshake" must not read as "the
handshake didn't happen."

## Sensitivity — validated at the plaintext-structural level (T-022, updated 2026-09-12)
The detector reads **only plaintext ISAKMP header fields** — exchange type, message id, SPIs — which
are unencrypted in *every* IKEv2 message (RFC 7296 §3.1), including the ones whose payloads are
encrypted. Its decision surface is therefore the on-wire **exchange-type / message-id sequence**, and
that sequence can be exercised faithfully with a header-only capture.

`testbed/scripts/gen_cve_positive.py` forges exactly that sequence —
`IKE_SA_INIT (msgid 0) → CREATE_CHILD_SA (msgid 1)`, no IKE_AUTH — into
`testbed/captures/synthetic/cve-2026-78135-plaintext-positive.pcap` (tracked in the manifest as
`split=excluded`, never in any ML split). tshark parses it as exchange types 34, 34, 36, 36; the
shipped extractor fires `early_childsa_cve = early-child-sa-before-auth` (OBSERVED, T1) and the
`CVE-WATCH / CVE-2026-78135` rule returns **FAIL (high)**. Confusion matrix now:

| | detector fires | not-detected / n-a | UNKNOWN (guard) |
|---|---|---|---|
| synthetic positive (1) | **1** | 0 | 0 |
| 69 legitimate captures | **0** | 67 | 2 |

Sensitivity 1/1, specificity 69/69, and the 2 UNKNOWNs are the mid-tunnel rekey captures the vantage
guard correctly refuses to judge.

## What is STILL out of scope, and why
A **live cryptographic exploit** capture is not produced. Reproducing the real attack needs a
malicious or patched IKE initiator that emits a genuine, key-valid CREATE_CHILD_SA before IKE_AUTH;
every stock stack refuses, and the post-INIT payloads are encrypted, so a full forgery would need the
IKE key schedule. The synthetic capture proves the detector sees the pattern; it does **not** prove a
real exploit emits exactly this sequence (an assumption grounded in RFC 7296 + the CVE description),
nor that the encrypted payloads would validate. That is the one remaining gap, stated plainly.

## Verdict
A **deterministic, vantage-aware** passive detector for the CVE-2026-78135 pattern exists, fires on
zero legitimate captures, and degrades to UNKNOWN when it cannot see the SA's birth. No AI. It is a
concrete, CVE-anchored capability no surveyed tool has (doc 11). It ships **guarded**: reported only
when the SA is observed from IKE_SA_INIT, else UNKNOWN.

## Root cause located in strongSwan source (2026-09-12, attempted live reproduction)

Attempted to go beyond the plaintext-structural positive and reproduce a genuine live exploit in
the Docker testbed. Cloned strongSwan 6.1.0 (`git b43f6bf`) and traced the actual code path:

**The gate that fixes the CVE** — `src/libcharon/sa/ikev2/task_manager_v2.c`, function
`reject_request()`, line 1736:
```c
case CREATE_CHILD_SA:
case IKE_FOLLOWUP_KE:
    reject = state == IKE_CREATED || state == IKE_CONNECTING;
    break;
```
This is precisely the check RL-033's finding describes: a `CREATE_CHILD_SA` request is rejected
while the responder's IKE_SA is still `IKE_CREATED`/`IKE_CONNECTING` (i.e. before `IKE_AUTH`
completes moves it to `IKE_ESTABLISHED`). Commenting out this case reproduces the described
pre-fix responder behavior.

**Why full reproduction was not completed.** The responder-side gate alone is a one-line, low-risk
patch. But making a *real* initiator emit an out-of-order `CREATE_CHILD_SA` exchange (rather than
one folded into `IKE_AUTH`, which is how a legitimate first Child SA is always created —
`task_manager_v2.c` line ~543) requires also changing which exchange type charon selects for a
task activated mid-negotiation — traced into `initiate_tasks()`'s per-round exchange-type
selection, which turned out to depend on state not fully mapped in this session. Patching it
without full confidence risks a broken, non-representative capture, which is worse than no capture
(this project's own evidence discipline — DEC-008 — treats a wrong claim as worse than an honest
gap). Stopped here rather than ship an uncertain patch as validated evidence.

**Net effect on the finding:** upgraded from "TP validation deferred, no source inspection" to
"root cause located and cited (exact file/function/line) from the actual strongSwan 6.1.0 source
that fixes it; full live-exploit reproduction remains future work, now scoped concretely (patch
`reject_request()` line 1736 + `initiate_tasks()`'s exchange-type selection on the initiator)."
Sensitivity is validated at the plaintext-structural level (above); a live-crypto capture is the
one honestly-stated remaining gap.
