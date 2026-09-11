# EXP-08 (T-044 / A7) — Tunnel vs Transport mode inference: **NOT-OBSERVABLE at T0**

**Date:** 2026-09-12 · **Status:** DONE · **Pre-registration:** `research/registers/EXPERIMENT-REGISTER.md`
("T-044 / A7", written before capture) · **Numbers:** `results/exp08_results.json` · **Data:**
`testbed/captures/a7-cs-aes256gcm16.pcap` (tunnel), `a7-cs-transport-aes256gcm16.pcap` (transport)

## Question
Can a passive observer tell tunnel mode from transport mode? This was the one candidate-ML row in
09-DEFINE that had never been tested (marked "I — inferable" in the Observability Matrix, A7).

## Result — both predictions held

- **P44-1 (paired baseline) HOLDS.** Same AES-GCM-256, same host pair, same ICMP size sweep through
  both modes. Tunnel ESP content is larger than transport by **exactly 20 bytes at every size**
  (30 packets, offset = {20}). That 20 bytes is the inner IPv4 header that tunnel mode encapsulates
  and transport mode does not.
- **P44-2 (no baseline) HOLDS — the decisive result.** Every observed ESP length is a valid length
  for **both** modes: both are AES-GCM-256, so every content length is a multiple of 4 above the
  minimum, and the +20 bytes lives **inside the encrypted plaintext**. An observer seeing an ESP
  packet of content length C cannot tell whether it is tunnel mode carrying a small inner packet or
  transport mode carrying an inner packet 20 bytes larger — because the inner size is unknown and
  encrypted. The achievable length sets are identical.

## Conclusion
**A7 mode inference is NOT-OBSERVABLE at T0 from ESP traffic alone.** Mode is recoverable only:
1. with a **paired-traffic baseline** (both modes, same traffic) — an experiment, not a field
   condition; or
2. from **endpoint telemetry** (T2 — `swanctl`/`ip xfrm state` report TUNNEL/TRANSPORT directly); or
3. from **topology** (P44-3): transport mode requires the outer addresses to be the actual
   communicating hosts, while tunnel mode permits gateway addresses. Usable at T0 only when the
   deployment is known to be gateway-to-gateway.

## Consequence for the design
- **No ML component is warranted for mode inference.** The analyzer reports mode from T2 when
  endpoint data is available, applies the topology heuristic (3) with stated confidence when it
  isn't, and otherwise returns **NOT-OBSERVABLE** — never a guess.
- This resolves the **last** candidate-ML row. After EXP-01/03/06/07 moved cipher-family, PFS,
  failure-diagnosis and fingerprinting to deterministic, and EXP-08 removes mode inference entirely,
  the AI Necessity Matrix is left with **exactly one** justified ML component: metadata-leakage
  measurement (CS-01, EXP-05).

## Honesty note
This is a **negative result reported as a positive finding**: knowing precisely what cannot be seen
is what lets the tool avoid a false claim. A competitor that reports "Mode: Tunnel" from a passive
capture (as the observed PS-26160 repo hardcodes) is stating something it cannot know.
