# EXP-14 — Tunnel/transport mode — RESULT (2026-09-20)

Pre-registration: `PREREG.md` (+ addendum A before data, addendum B after, post hoc).
Numbers: `results/exp14_results.json`. Data: EXP-15 traffic sessions (96: tunnel, transport, TFC;
AES-GCM-256) + every tracked capture with a ground-truth mode.

## Size-floor rule (confirmatory)
| # | Prediction | Result |
|---|---|---|
| P14-1 | zero tunnel captures called transport | **Held**: 0 of 64 tunnel/TFC sessions, 0 of all tracked tunnel captures |
| P14-2 | the two transport captures are called transport | **Held** (both, from their size-sweep packets) |
| P14-3 | provable on ≥ 90% of ICMP/VoIP/interactive/messaging sessions | **Failed, as addendum A predicted before the data**: 0% on every class. Realistic packets (a 56-byte ping, a TCP ACK with timestamps) are all above the 56-byte GCM floor even in transport mode. The rule fires only on tiny packets |
| P14-4 | TFC sessions never fire | **Held** (0) |

So the floor is a **proof with near-zero coverage** on normal traffic: correct when it fires, rarely fires.

## ACK-size model (exploratory, addendum A)
Held-out repetition, AEAD tunnels, TCP-carrying traffic: **44 of 64 sessions answered, 44 correct
(100%), 0 tunnel sessions called transport** at probability ≥ 0.80. Coverage: bulk, interactive,
messaging, video, web 100%; e-mail 50%; VoIP and ICMP 0% (no TCP ACKs, so it abstains, by design).
It shipped, found a false positive on an out-of-domain capture (addendum B), and now carries a purity
guard; after the guard, every tracked capture's mode claim is correct.

## What this lets us claim
- Mode is **OBSERVED** for AH (plaintext next header, 5/5 EXP-15 AH captures correct).
- For ESP: **transport proven** when a sub-floor packet exists; otherwise a **model estimate with its
  confidence** for TCP-carrying traffic over an AEAD cipher; otherwise **UNKNOWN**.
- Not claimed: mode for UDP/ICMP-only tunnels, CBC tunnels, or implementations other than strongSwan
  6.1 (the ACK buckets follow from IPv4/TCP header sizes, but only one stack was measured).
