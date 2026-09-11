# EXP-07 — Cross-Implementation (Libreswan 5.4): **protocol facts hold; two signals are implementation-dependent**

**Date:** 2026-09-12 · **Status:** DONE · **Pre-registration:** `research/registers/EXPERIMENT-REGISTER.md`
("EXP-07 — PRE-REGISTRATION") · **Numbers:** `results/exp07_results.json` · **Data:**
`testbed/captures/exp07/` (10 captures + T2 ground truth) · **Code:** `analyze.py` imports the
*same* functions used for EXP-01/02/03/04 on strongSwan.

## Setup
Libreswan 5.4 ↔ Libreswan 5.4 (Fedora rawhide `libreswan-5.4-5.fc46`, NSS 3.127, pinned by digest)
through the same keyless router — the first Libreswan release with RFC 9370 / ML-KEM-768.
Ten arms: six cipher suites, PFS off/on with two forced Child-SA rekeys, classical vs ML-KEM-768.
Ground truth: the configured arm plus pluto's own log of what it negotiated (T2).

## Result

| Signal | strongSwan 5.9.8 / 6.x | **Libreswan 5.4** | Verdict |
|---|---|---|---|
| **P7-1** ESP cipher sieve (EXP-01) | GCM/CTR/ChaCha → 5-member class; CBC → 6 | **identical classes**; true family never eliminated | ✅ **HOLDS** — protocol fact |
| **P7-2** AES-128 vs 256 negative control (EXP-02) | identical length sets | **identical**; classifier ≤ chance | ✅ **HOLDS** — protocol fact |
| **P7-3** PFS rekey gap (EXP-03) | 224/240 → 496/512 B: **gap 256 B** | 220/236 → 492/508 B: **gap 256 B** | ✅ **HOLDS, same gap** — absolute sizes differ by 4 B; the gap is protocol-determined |
| **P7-4a** IKE_INTERMEDIATE present iff ADDKE (EXP-04 S3) | 0 vs 3 messages | **0 vs 6 messages** | ✅ **HOLDS** — protocol fact |
| **P7-4b** IKE_SA_INIT grows with ADDKE (EXP-04 S2) | +16 B | **+8 B** | ✅ **HOLDS IN DIRECTION** — accounted for below |
| **P7-4c** `INTERMEDIATE_EXCHANGE_SUPPORTED` notify (EXP-04 S1) | only when ADDKE is proposed | **in both arms** (whenever `intermediate=yes`) | ⚠️ **IMPLEMENTATION-DEPENDENT** — as predicted |
| **P7-4d** Fragmentation (EXP-04 S4) | ~1280-byte fragments; initiator 2, responder 1 | **576-byte fragments; 3 each way** | ⚠️ **IMPLEMENTATION-DEPENDENT** — as predicted |

**The +16 vs +8 is fully accounted for.** One ADDKE transform substructure is 8 bytes — the protocol
constant. strongSwan's extra 8 bytes is the `INTERMEDIATE_EXCHANGE_SUPPORTED` notify (8-byte
data-less notify), which strongSwan sends only when ADDKE is proposed. Libreswan sends that notify
in both arms, so it cancels out of Libreswan's delta.

## What worked
Every signal the research labelled a **protocol fact** held on an independent implementation, often
to the byte (the PFS gap is exactly 256 B on both). All **seven** pre-registered predictions came out
as predicted, including the two predicted to be implementation-dependent.

## What failed
Nothing failed against the pre-registration. **One analysis bug** was caught and fixed: the first
run compared IKE_SA_INIT sizes by IP address, but in EXP-07 the classical and PQ arms use different
alias pairs, so no address was common to both. That gave an empty delta and a false "FAILS". Sizes
are now compared by role (initiator/responder). Documented in `analyze.py`.

## What was surprising
**A notify-based PQ detector would give false positives on Libreswan.** EXP-04 found that
`INTERMEDIATE_EXCHANGE_SUPPORTED` tracked ADDKE exactly on strongSwan. It does *not* on Libreswan:
there it tracks the `intermediate=yes` capability. Without EXP-07 we would have shipped a detector
that flags every Libreswan tunnel with `intermediate=yes` as post-quantum.

## What should change (feeds DEVELOP and the build)
- **The PQ detector's decisive signals are:** IKE_INTERMEDIATE presence (S3), plus the ADDKE
  transform in IKE_SA_INIT (8 bytes per transform; parseable in plaintext — Wireshark master names
  it). The notify (S1) and the fragmentation pattern (S4) are **corroborating only**, and become
  **implementation fingerprints** rather than PQ evidence.
- Libreswan's 576-byte IKE fragments versus strongSwan's ~1280 are a cheap **implementation
  fingerprint** for the evidence record.
- Claims in the report must carry their scope: the protocol-fact signals are validated on two
  independent implementations (strongSwan 5.9.8/6.0.2/6.1.0 and Libreswan 5.4); vendor stacks
  (Cisco, Palo Alto, Fortinet) are untested.
