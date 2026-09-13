# EXP-11 (T-048) — Peer auth-method inference (R7/OQ-05): the disposition was half wrong, caught before shipping

**Date:** 2026-09-13 · **Status:** DONE — the honest result is a corrected NOT-OBSERVABLE finding,
plus one genuinely new, validated capability · **Data:** `testbed/captures/exp11/` (2 pcaps + T2
ground truth) · **Code:** `tunnelscope/evidence/extract.py::extract_auth_hint`

## Why this experiment exists

Full project audit (2026-09-13, user: "complete the entire project completely"). `research/09-DEFINE.md`
R7 disposed "identify authentication algorithm" as **RE-SCOPE — disambiguate ESP integrity alg. (I at
T0/T1) vs IKE peer-auth method (I at T1 via CERTREQ/SIGHASH presence)**. The ESP/IKE integrity half
was built (`ike_integ`, via `extract_ike_crypto`). The peer-auth-method half — PSK vs certificate vs
EAP, from CERTREQ/SIGNATURE_HASH_ALGORITHMS presence in plaintext `IKE_SA_INIT` — was never built.
Buildable in principle (both fields are genuinely plaintext, RFC 7296 §3.7 / RFC 7427), so built it —
and tested the assumption before shipping, per this project's standing rule (DEC-008).

## Setup

Generated a real CA + RSA certs for alice/bob (`testbed/certauth/pki/`, via strongSwan's own `pki`
tool) and added a `certauth` connection (pubkey/X.509 auth) alongside the existing 9 PSK arms on the
**same** validated Docker testbed containers (`sih26-alice`/`sih26-bob`). Captured on the same
keyless `router` T0 vantage as every other experiment.

## What happened

**First capture (`certauth.pcap`):** genuine RSA certificate authentication, IKE_SA and CHILD_SA
both established (T2-confirmed via `swanctl --list-sas`: identities are full X.509 DNs). The
plaintext `IKE_SA_INIT` showed exactly what R7's disposition predicted: `isakmp.certreq.type=4` in
the responder's message, and `isakmp.notify.data.signature_hash_algorithms` present in both
directions. Looked like a clean win.

**The check that mattered:** before shipping, ran a **differential test** — the same responder
(`bob`, now with the cert-capable connection loaded alongside its PSK arms), negotiating a plain
**PSK** connection (`cs-aes256gcm16`) instead. Result: **CERTREQ was present again**
(`psk-control.pcap`). Checked further: `SIGNATURE_HASH_ALGORITHMS` is present even in
`classical-baseline.pcap` — a capture taken before this bob container had any certificate
configuration at all. Neither signal discriminates the way the disposition assumed:

| Signal | Present when... | Discriminates per-tunnel auth method? |
|---|---|---|
| `SIGNATURE_HASH_ALGORITHMS` (notify 16431) | **Always** — even with zero cert config anywhere | ❌ No — emitted unconditionally |
| `CERTREQ` (`isakmp.certreq.type`) | Whenever the **responder** has *any* cert trust anchor loaded | ❌ No, at the per-tunnel level — reflects the responder's fleet-wide policy, sent in `IKE_SA_INIT` **before** `IDi` identifies which connection will be matched, so the responder cannot yet know which policy applies |

## Result

The genuinely authoritative signal — which CERT/AUTH payload type this specific tunnel actually
used — is inside `IKE_AUTH`, which is encrypted. **`peer_auth_method` is NOT-OBSERVABLE at T0/T1**,
the same encryption-boundary pattern already established for `mode` (EXP-08). R7's disposition is
corrected: buildable in principle, not reliably observable in practice once a responder serves more
than one policy — which is the normal case for any real gateway, not an edge case.

**Not a wasted build.** `CERTREQ` presence is kept as its own, honestly-scoped finding —
`responder_cert_capability` — because it genuinely is useful, just not for what R7 originally asked:
it tells an auditor scanning many tunnels through the same gateway *"this gateway has certificate
trust configured somewhere in its policy"*, a fleet-level compliance-posture signal, correctly
labelled as such rather than mislabeled as this SA's auth method.

**Also closed R9's other gap in passing:** SPI was tracked internally for SA grouping but never
exposed as a citable `Finding`. Added (`ike_spi`, `OBSERVED`, both directions) — trivial, but a real
completeness gap the audit found.

## Validation

| Capture | `peer_auth_method` | `responder_cert_capability` | T2 ground truth |
|---|---|---|---|
| `certauth.pcap` (real cert auth) | NOT_OBSERVABLE | **True** | X.509 DN identities, RSA auth (swanctl log) |
| `psk-control.pcap` (PSK, same cert-capable responder) | NOT_OBSERVABLE | **True** | PSK identities (swanctl log) |
| `classical-baseline.pcap` (PSK, pre-cert-config responder) | NOT_OBSERVABLE | **False** | PSK identities, no cert config existed |

`responder_cert_capability` tracks exactly what it claims to (the responder's own state, confirmed
by the differential test) in all three cases. 41/41 unit tests pass (was 39), e2e still 69/69.

## Net effect

Upgrades R7 from "half-implemented, half-silently-missing" to "half-implemented, half honestly
NOT-OBSERVABLE with the reason empirically demonstrated — plus one new, correctly-scoped capability
that exists because the first attempt was tested rather than assumed." Same discipline as EXP-07
(notify tracks capability, not outcome) and EXP-10 (a heuristic that looked right on one capture
broke on a second, real test) — a third instance of the same lesson, on a different signal.
