# EXP-27 — What can a passive observer tell about RFC 8784 post-quantum pre-shared keys (PPK)? — PRE-REGISTRATION (2026-09-27, before any capture)

Owner, 2026-09-27: roadmap T-136, approved ("go ahead and build the next thing"). EXP-26 could not
test PPK (RouterOS 7.24.4 accepts only `ppk=no`). strongSwan 6.1.0, already in the lab
(`sih26-alice-pq`, `sih26-bob-pq`), implements RFC 8784.

## What RFC 8784 puts on the wire
- IKE_SA_INIT (plaintext): a peer that supports PPK sends a `USE_PPK` notify; the responder answers
  with `USE_PPK` only if it supports PPK too.
- IKE_AUTH (encrypted): `PPK_IDENTITY` and, when PPK is optional, `NO_PPK_AUTH`. Whether the PPK was
  actually mixed into the keys, or the peers fell back to classical authentication, is decided here.
**Prediction from the RFC alone:** a passive observer can see PPK *support/negotiation*, never PPK *use*.

## Setup (fixed before capture)
Existing lab: router (tcpdump on eth0, keyless T0 vantage), alice-pq 10.10.1.20 (initiator), bob-pq
10.10.2.20 (responder), strongSwan 6.1.0. IKE `aes256-sha256-modp2048`, ESP `aes256gcm16`, PSK
authentication (lab throwaway). Per-arm connections loaded at runtime with `swanctl --load-all --file`
from `testbed/configs/exp27/`; the lab's standing configs are not changed. ICMP probes through the tunnel.
Ground truth (T2): both charons' logs for the negotiation (strongSwan states whether a PPK was used)
and `swanctl --list-sas`, saved as `<arm>.groundtruth.json`.

## Arms
| Arm | Initiator | Responder | PPK used (expected) |
|---|---|---|---|
| K0 | no PPK | no PPK | no |
| K1 | PPK id `ppk27`, optional | same PPK, optional | yes |
| K2 | PPK id `ppk27`, required | same PPK, required | yes |
| K3 | PPK id `ppk27`, optional | no PPK configured | no (responder does not support it) |
| K4 | PPK id `ppk27`, optional | PPK configured under a different id `other27`, optional | no (falls back to NO_PPK_AUTH) |
If strongSwan does not behave as "expected" in an arm, the ground truth (its own log) wins and the arm
is scored against what actually happened.

## The finding to build (after this file is committed)
A new finding `pq_ppk` with values **`negotiated`** (USE_PPK in both IKE_SA_INIT messages),
**`offered-not-negotiated`** (only in the request), **`not-offered`** (neither), OBSERVED, never a
claim that the PPK was used; the note says use is decided in encrypted IKE_AUTH. UNKNOWN when no
IKE_SA_INIT is visible. `pq_key_exchange` (RFC 9370 ML-KEM) is not changed.

## Hypotheses and bars
- **H1:** K0 `not-offered`, K1 and K2 `negotiated`, K3 `offered-not-negotiated`.
- **H2 (the honesty test):** K4 shows `negotiated` on the wire although ground truth says the PPK was
  not used. Pass = TunnelScope says `negotiated` and does **not** claim use; any output that implies the
  tunnel is PPK-protected in K4 is a fail.
- **H3:** zero wrong findings in the existing IKE suite fields for K0–K4 (the PPK notifies must not
  disturb other extractors).
- **H4:** no other finding changes on any existing capture (findings differential), apart from the new
  `pq_ppk` finding appearing.

## Not changed during EXP-27
Captures are taken with the finding not yet written; rules and the risk score are not changed to
credit PPK as post-quantum protection, because use cannot be observed.
