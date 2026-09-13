# EXP-12 (T-048) — Rekey-cadence measurement (R9/R12): built, validated, and it found a real security-relevant bug

**Date:** 2026-09-13 · **Status:** DONE · **Data:** `testbed/captures/exp12/rekey-cadence.pcap` +
`groundtruth.json` · **Code:** `tunnelscope/evidence/extract.py::extract_sa_lifecycle`

## Why this experiment exists

Full project audit (2026-09-13). `build/00-ARCHITECTURE.md`'s own component list plans a
`sa_lifecycle` extractor (R9 SA characteristics / R12 key lifetime — IKEv2 negotiates no lifetime,
F-02, so the honest deliverable is a *measurement* of effective rekey behaviour, never a
compliant/non-compliant check). It was never built. Built it.

## Setup

Added a PSK arm (`rekey-cadence`) with `rekey_time=20s` (short, to force several real CHILD_SA
rekeys inside one capture) to the validated Docker testbed. strongSwan's own jitter did not fire the
auto-rekey inside a reasonable window, so triggered it manually via `swanctl --rekey --child
rekey-cadence` at controlled ~15-second intervals (4 triggers) — the same on-wire CREATE_CHILD_SA
exchange either way, and a cleaner, more reproducible ground truth than waiting on internal jitter.

## Result — the measurement itself

```
rekey_cadence: MEASURED {n_rekeys: 7, intervals_s: [18.37, 15.09, 15.09, 11.01, 0.0, 4.09],
                          mean_interval_s: 10.61}
```

Two of the seven measured intervals (**15.09s, 15.09s**) match the manual trigger spacing almost
exactly — direct confirmation the measurement mechanism is correct. The other intervals are genuine,
not noise: the responder's own auto-rekey timer fired independently and interleaved with the manual
triggers (7 rekeys captured from only 4 manual triggers). This is exactly what R12's disposition
asks for — **measured** effective behaviour, warts included, never an idealized or claimed
"configured" number.

## The bug this same capture found

The interleaved responder-initiated rekey exposed a genuine **false positive** in the
CVE-2026-78135 detector (`extract_early_childsa_cve`, EXP-09/T-022): it reported
`early-child-sa-before-auth` on this ordinary, legitimate rekey traffic.

**Root cause, not a parsing artifact:** IKEv2 message IDs are maintained **per originator** (RFC
7296 §2.1) — each peer keeps its own counter for exchanges *it* initiates. Once the peer that
answered `IKE_AUTH` (the original responder) independently initiates its own exchange — a
self-triggered rekey here, but this generalizes to DPD or any responder-initiated activity — that
peer's own message-id counter restarts at 0. The detector's original logic compared
`min(child_message_ids) < min(auth_message_ids)` globally, which silently compares **two different
counters** as if they were one sequence. A responder-initiated rekey's message ID 0 then reads as
"before IKE_AUTH's message ID 1," which is meaningless — message-id ordering is only valid *within*
one originator's sequence.

**Confirmed empirically, not just reasoned about:** inspected the raw `isakmp.flags` on the
anomalous frames — one pair has flags indicating a responder-originated request (Initiator bit
unset) at message id 0, the other the original-initiator's own concurrent rekey at message id 10.
Same IKE SPI pair throughout; not fragmentation, not a tshark artifact.

**Fix:** compare by **frame number** (capture order) instead of message ID — a single, globally
consistent ordering regardless of which side originated which exchange. `tunnelscope/evidence/
extract.py::extract_early_childsa_cve`, with the reasoning recorded inline.

**Re-verified after the fix, not just on the failing case:**

| Check | Before fix | After fix |
|---|---|---|
| This capture (legitimate rekey) | ❌ false positive | ✅ `not-detected` |
| Synthetic plaintext-structural positive (T-022) | ✅ fires | ✅ still fires |
| Live fault-injected exploit (T-022, EXP-09 addendum) | ✅ fires | ✅ still fires |
| Full sweep, all 69 real dataset captures | 0 FP (never exercised responder-initiated activity) | **0 FP**, now exercised |

Added as a permanent regression test (`tests/test_cve.py::
test_responder_initiated_rekey_is_not_a_false_positive`) so this exact class of bug cannot silently
return.

## Net effect

R9/R12's missing capability is now built and validated — and, in the same pattern as EXP-10 and
EXP-11, testing it against real (not just synthetic) traffic found a genuine bug in an *already
shipped, already-claimed-0-FP* security detector before it could surface as a false alarm in the
field. The "0 FP / 69" claim for the CVE detector was true on the corpus it was tested against, and
is now also true against traffic that actually exercises bidirectional, responder-initiated
activity — a realistic case the original 69 captures happened not to include.
