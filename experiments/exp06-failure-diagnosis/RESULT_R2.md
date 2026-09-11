# EXP-06 Round 2 — Failure-Mode Diagnosis: **ALL SIX PRE-REGISTERED PREDICTIONS HELD**

**Date:** 2026-09-12 · **Status:** DONE · Supersedes round 1 (`RESULT.md`, inconclusive)
**Pre-registration:** `research/registers/EXPERIMENT-REGISTER.md` → "EXP-06 Round 2 — PRE-REGISTRATION"
(written before any round-2 capture)
**Raw data:** `testbed/captures/exp06r2/` (35 pcaps + 35 T2 ground-truth files) ·
**Numbers:** `results/exp06r2_results.json` · **Code:** `analyze_r2.py`, `testbed/scripts/run_exp06.sh`,
`testbed/scripts/gen_exp06_conf.py`

## Question
From a passive capture with no keys (T0/T1), can an observer tell *which* IKEv2 negotiation failure
occurred — the question practitioners currently answer by reading both endpoints' configs by hand
(PE-01, doc 02)?

## Design (round-1 flaws fixed)
7 arms × 5 repetitions = 35 captures. Each arm had its own alias address pair (no shared XFRM
policies, unambiguous responder selection) and equal-length IKE identities. Every SA was terminated
before each capture, and each capture was filtered to that arm's hosts. Ground truth is the designed
misconfiguration; **all 35 runs were independently confirmed** by the initiator's own charon log (T2).

## Result

Structural signature per arm — **identical across all 5 repetitions** (zero variance):

| Arm | IKE_SA_INIT response | Plaintext NO_PROPOSAL_CHOSEN | IKE_AUTH response | CREATE_CHILD_SA req → resp | ESP pkts | Init retransmits |
|---|---|---|---|---|---|---|
| F0 success | yes | no | **336 B** | — | 10 | 0 |
| F1 IKE-proposal mismatch | yes | **yes** | none | — | 0 | 0 |
| F2 child-proposal mismatch | yes | no | **256 B** | — | 0 | 0 |
| F3 TS mismatch | yes | no | **256 B** | — | 0 | 0 |
| F4 PSK/auth failure | yes | no | **112 B** | — | 0 | 0 |
| F5 PFS mismatch | yes | no | 336 B | **512 B → 112 B** | 10 | 0 |
| F6 peer unreachable | **none** | — | — | — | 0 | 5 |

Classification, leave-one-repetition-out:

| Method | 7 classes (F2, F3 separate) | 6 classes (F2+F3 merged) |
|---|---|---|
| **Hand-written rules** (thresholds from protocol arithmetic, fixed before data) | macro-F1 **0.809** | macro-F1 **1.000** |
| Decision tree (fitted) | macro-F1 **0.809** | macro-F1 **1.000** |

## Predictions vs outcome

| # | Prediction | Outcome |
|---|---|---|
| P-a | F1 separable (plaintext notify) | ✅ 5/5 |
| P-b | F6 separable (no response, retransmits) | ✅ 5/5 |
| P-c | F4 separable from F2/F3 by response size | ✅ 112 B vs 256 B, 5/5 |
| P-d | F0 separable from F2/F3 | ✅ 336 B vs 256 B, and ESP present, 5/5 |
| P-e | **F2 vs F3 NOT separable at T0/T1** | ✅ **Confirmed: identical feature vectors; not one feature ever differs** |
| P-f | F5 separable only at rekey | ✅ 512 B request with a KE payload answered by a 112 B error-only response, 5/5 |

## What worked
- **The protocol arithmetic predicted the data exactly.** The script header derived, before any
  capture, that an encrypted IKE message carrying only one data-less notify is
  `20+8+4+28+4+16+16+16 = 112` bytes. F4's AUTH_FAILED response and F5's rejected-rekey response are
  both **exactly 112 bytes**.
- **Cross-experiment consistency:** F5's CREATE_CHILD_SA request is 512 B, byte-identical to the
  PFS-on rekey request in EXP-03, measured in a different experiment on different addresses.
- The round-1 contamination is gone. Per-arm isolation works.

## What failed
Nothing failed against the pre-registration. The honest limit is the one we predicted:
**proposal-mismatch vs traffic-selector-mismatch cannot be told apart passively.** Both responses are
IDr + AUTH + one data-less notify, so they have identical encrypted lengths. The *reason* is only
visible at T2 (endpoint logs), which is exactly why practitioners resort to reading configs (PE-01).

## What was surprising
- How completely deterministic this is: **zero variance** in every feature across five repetitions.
  There is no noise for a model to learn around.
- MOBIKE's `ADD_4_ADDR` notifies put **every local address** of the initiator into IKE_AUTH (seven
  here, one per alias). Encrypted, so passively invisible, but it is a disclosure *to the peer* that no
  assessment tool reports.

## What assumption was invalidated
**The AI Necessity Matrix entry for failure diagnosis (CS-02), which said "Yes — genuine ML need".**
A fitted decision tree does no better than rules written from the RFC before seeing data. The
features carry exact structural signatures, not distributions. **CS-02 is deterministic.** The matrix
is updated in `research/09-DEFINE.md` (T-014).

## What became more likely
That the whole assessment core — PFS (EXP-03), PQ (EXP-04), cipher family (EXP-01), failure mode
(EXP-06) — is **deterministic structural analysis**. Every structural question tested so far has had
an exact answer or an exact, provable limit.

## What should change
- The failure-diagnosis capability ships as **rules with cited arithmetic**, and reports F2/F3 as one
  class — *"child SA rejected — proposal or traffic-selector mismatch; the reason needs endpoint
  logs (T2)"* — rather than guessing between them.
- The only remaining candidate for a genuinely statistical component is leakage measurement
  (EXP-05 / CS-01).

## Scope and limits
strongSwan 5.9.8 on both ends, PSK authentication, IKEv2, UDP/4500 after IKE_SA_INIT, one network path.
The byte values are implementation- and configuration-specific: IDs, the IKE cipher and MOBIKE settings
change them. The *relations* (notify-only < child-failure < success) are what should generalise; that
is part of what EXP-07 (Libreswan) checks. Not covered: EAP/certificate authentication, lifetime/
rekey-race failures, NAT rewriting.
