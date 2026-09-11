# EXP-09 (T-022) — Passive detection of the CVE-2026-78135 pattern (early Child SA before auth)

**Date:** 2026-09-12 · **Status:** DONE (detector designed + specificity validated; true-positive
validation deferred with reason) · **Closes:** OQ-31 (partially)

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

## What is NOT done, and why
**True-positive validation is deferred.** Reproducing the actual exploit needs a **malicious or
patched IKE initiator** that emits CREATE_CHILD_SA before IKE_AUTH — every stock implementation
refuses to. Crafting it by hand is hard: all IKEv2 messages after IKE_SA_INIT are encrypted with
negotiated keys, so a Scapy forgery would need a full IKE key schedule. Options for later (T-022
stays open for the TP side): patch strongSwan to send the early exchange, or drive a downgraded
5.9.x pair with a fault injector. The detector's **logic** is deterministic and its **specificity**
is validated; its sensitivity against a live exploit is unproven.

## Verdict
A **deterministic, vantage-aware** passive detector for the CVE-2026-78135 pattern exists, fires on
zero legitimate captures, and degrades to UNKNOWN when it cannot see the SA's birth. No AI. It is a
concrete, CVE-anchored capability no surveyed tool has (doc 11). It ships **guarded**: reported only
when the SA is observed from IKE_SA_INIT, else UNKNOWN.
