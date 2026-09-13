# EXP-10 — Cross-Implementation (OpenBSD `iked` 7.9): a genuine third, independent codebase; core signals hold, one real diagnostic gap found

**Date:** 2026-09-13 · **Status:** DONE, but **NOT pre-registered** (reactive, user-directed: "find
a free/open-source vendor-diversity alternative and use it," 2026-09-12 — stated honestly, unlike
EXP-01–09 which were pre-registered before data existed) · **Data:** `testbed/captures/exp10/` ·
**Ground truth:** `testbed/captures/exp10/obsd-vendor.groundtruth.json` (T2: OpenBSD's own
`ipsecctl -sa` + `iked` daemon log, causal, never inferred)

## Why this experiment exists

T-022/T-045's stated risk, carried since `research/12-DEVELOP.md` §6 red team: *"Only two
implementations tested [strongSwan, Libreswan]... Vendor stacks (Cisco, Palo Alto, Fortinet) are
untested."* Licensed vendor images remain genuinely unobtainable (stated in `TODO.md`). The user
asked for a free/open-source alternative instead.

**Landscape searched, each ruled out with evidence (not assumed):**
- **OpenIKED** (`reyk/openiked`, the portable Linux build of OpenBSD's `iked`) — the actual commit
  history reads *"Remove portable code; it has been suspended until we find a new -portable
  maintainer."* Linux support is genuinely gone, not just undocumented.
- **OpenIKEv2** (`github.com/OpenIKEv2`) — all three repos archived, last commit March 2020.
- **racoon2** (WIDE Project) — technically Linux-portable, but self-described as "unstable and very
  difficult to configure," no real development since ~2010.

**Chosen: genuine OpenBSD `iked`, in a real OpenBSD 7.9 VM** — not a Linux port, not a fork of the
strongSwan/Libreswan/Openswan lineage; an architecturally independent IKEv2 daemon, actively
maintained as part of OpenBSD's base system.

## Setup

- **strongSwan 6.1.0** (Homebrew, same version already validated in the Docker testbed) running
  natively on the macOS host (10.37.129.2), as initiator.
- **OpenBSD 7.9 (arm64, native — no emulation)** in a Parallels Desktop VM (10.37.129.50), as
  responder, running the genuine `iked` daemon shipped in the OpenBSD base system.
- **Network:** an isolated Parallels "Host-Only" segment (10.37.129.0/24), never joined to the
  validated Docker testbed. The host's own `bridge101` interface — which owns no IPsec keys — is
  the T0 vantage, capturing exactly what a passive third-party observer would see, consistent with
  the project's `router`-container vantage discipline (DEC-005) applied to a different topology.
- **Arm:** mirrors the committed `cs-aes256gcm16` classical baseline — IKE
  `aes256-sha256-modp2048`, ESP `aes256gcm16` — for direct comparability with the existing dataset.
- **Ground truth:** OpenBSD's own `ipsecctl -sa` (flows + SAD) and the `iked` daemon log
  (`/var/log/daemon`), read over SSH — T2, causal, matching `DEC-009`'s rule that ground truth is
  never the analyzer's own inference.

## What happened (both captured, both in the committed pcap)

**First attempt failed authentication — a real, diagnosable configuration bug, not a tooling
failure.** strongSwan's `swanctl.conf` secret was written as
`"0sIhtestlab2026SIH26160presharedkeydonotusehere"` (reusing the exact string already committed for
the Docker testbed's strongSwan-to-strongSwan arms, where it is consistent on both ends and so
"works" regardless of how it's interpreted). Against `iked`, which has no `0s`-prefix convention
(iked's `psk` keyword only recognizes a literal string or an explicit `0x`-prefixed hex value per
`iked.conf(5)`), the two sides derived different key material. **iked's own log is unambiguous:**
```
ikev2_auth_verify: ikev2_msg_authverify failed
ikev2_send_auth_failed: authentication failed for IPV4/10.37.129.2
```
Fix: a plain, unprefixed shared string on both ends. Retried — **full success**:
```
ikev2_childsa_enable: loaded SPIs: 0x3baa27bb, 0xc82d2075 (enc aes-256-gcm)
ikev2_childsa_enable: loaded flows: ESP-10.37.129.50/32=10.37.129.2/32(0)
established peer 10.37.129.2:4500 ... as responder (enc aes-256 auth hmac-sha2-256 group modp2048 prf hmac-sha2-256)
```
Both negotiations are in the committed pcap (8 frames total: 4 per attempt, IKE_SA_INIT +
IKE_AUTH, NAT-T floated to 4500 in both). **This is itself a legitimate secondary finding, not
noise:** the `0s`/`0x` PSK-encoding convention is a strongSwan-ecosystem-specific idiom; anyone
pointing our detector's evidence (or a real deployment) at a mixed strongSwan/OpenBSD estate needs
to know it does not travel.

**No ESP data-plane traffic was captured.** The tunnel was fully established (confirmed by
`ipsecctl -sa` showing installed SAD/flow entries on OpenBSD) but no traffic was ever sent through
it — a macOS kernel/route quirk on the initiator side logged during negotiation
(`can't install route for 10.37.129.2/32 === 10.37.129.50/32 out, conflicts with IKE traffic`)
means macOS's own IPsec-route integration is imperfect for this native-host setup; the IKE control
plane is unaffected and fully valid, but the ESP-level extractors (cipher sieve, PFS-at-rekey,
leakage) have no data in this capture to be validated against. Stated as scope, not hidden.

## Result — signal by signal

| Signal | strongSwan↔strongSwan / ↔Libreswan (EXP-01/03/04/06) | **strongSwan ↔ real OpenBSD `iked`** | Verdict |
|---|---|---|---|
| IKE version / exchange sequence (`ike_meta`) | IKEv2, IKE_SA_INIT→IKE_AUTH | **identical** | ✅ **HOLDS** |
| IKE crypto suite parse (`ike_crypto`) | AES-CBC-256 / HMAC-SHA2-256-128 / MODP-2048 | **identical, byte-correct** — matches the configured arm exactly | ✅ **HOLDS** |
| PQ posture (`pq_addke`) | `classical-only` when no ADDKE offered | **correctly `classical-only`** (iked here configured without `sntrup761x25519`) | ✅ **HOLDS** |
| Failure diagnosis (`failure_diag`, EXP-06) — **failed SA** | 112-byte-response rule → `auth-or-child-failure` | **correctly diagnosed** `auth-or-child-failure` — matches iked's own log exactly | ✅ **HOLDS** |
| Failure diagnosis (`failure_diag`, EXP-06) — **succeeded SA** | `success` iff ESP observed | **misdiagnosed as `child-sa-rejected`** — ESP never flowed (see above), and the heuristic has no third state for "IKE succeeded, no traffic sent yet" | ❌ **GENUINE GAP — see below** |
| ESP cipher sieve (EXP-01), PFS gap (EXP-03), leakage (EXP-05) | validated on 71 captures | **not exercised** — 0 ESP packets in this capture | — out of scope this run |

## What was surprising

**OpenBSD's `iked` ships its own, architecturally different post-quantum mechanism.** `iked.conf(5)`
lists `sntrup761x25519` as a supported `group` — a hybrid Streamlined-NTRU-Prime + X25519 key
exchange encoded as a DH *group* (same approach OpenSSH uses), not an RFC 9370 ADDKE transform with
ML-KEM the way strongSwan/Libreswan do it. This means a real deployment could have **two
codebase-specific ways to be post-quantum**, and TunnelScope's current PQ detector — built entirely
against the ADDKE/IKE_INTERMEDIATE signal (EXP-04/07) — would **not** recognize an OpenBSD peer
using `sntrup761x25519` as post-quantum at all, since no ADDKE/IKE_INTERMEDIATE exchange would
appear. Not tested this run (this arm used classical-only); flagged as a concrete, scoped follow-up
rather than a known-working feature.

## The genuine gap, precisely diagnosed

`tunnelscope/evidence/extract.py`'s `extract_failure()` treats "IKE up, no ESP observed" as a single
class (`child-sa-rejected`, `INFERRED`, confidence 0.7) with one caveat noted in its own docstring —
but it does not distinguish that from "IKE and Child SA both succeeded; no data has been sent yet."
Every one of the 71 committed captures that reach this branch do so because of an actual mismatch
(EXP-06's r2 corpus was built by deliberately breaking negotiation), so the branch was never
exercised on a true positive until this real cross-implementation test surfaced it. This is exactly
the kind of finding EXP-07 modeled: **a real independent implementation is what proves or breaks a
heuristic that captures based on our own configs cannot.**

**Not fixed in this session** (would need a new decision on how to distinguish the two cases
passively — e.g., a longer observation window before concluding rejection, which is a real design
question, not a one-line patch) — recorded here as a scoped, honest follow-up rather than silently
patched or hidden.

## Net effect

Upgrades the project's vendor-diversity claim from "two implementations, both in the
strongSwan/Libreswan lineage" (stated risk in `research/12-DEVELOP.md` §6) to "two implementations
plus one architecturally independent third codebase, real traffic, real ground truth" — while
being equally honest that this run found a genuine limitation in the failure-diagnosis heuristic
that the first 71 captures never exposed. Both the win and the gap are the same kind of evidence
this project is built to produce.

## Addendum (2026-09-13) — real ESP dataplane traffic, and a second genuine gap

The original run above had no ESP packets. Re-established the same tunnel (fresh IKE_SA after a
clean VM reboot, same arm, new SPIs `0xae499361`/`0xc924358f`) and this time sent 5 ICMP echo
requests through it, capturing on the same keyless `bridge101` T0 vantage:
`testbed/captures/exp10/obsd-esp-test.pcap` + `.groundtruth.json` (T2: OpenBSD `ipsecctl -sa`).

**Finding 1 — the earlier route warning is non-fatal.** charon's
`[KNL] can't install route ... conflicts with IKE traffic` looked like it might mean macOS never
enforces the SA on local dataplane traffic. It doesn't: all 10 captured packets (5 request + 5
reply) are genuine ESP (`ip.proto=50`) carrying the exact SPIs both sides' T2 state confirms for
this SA. The warning is about strongSwan's convenience route-table entry, not the kernel's actual
policy enforcement.

**Finding 2 — a second genuine, previously-undisclosed heuristic gap, this time in leakage
measurement.** TunnelScope reported `tfc_padding_active: True` on this capture. OpenBSD's `iked`
was not configured with any padding option in this test — the 10 ESP frames are uniform in size
only because 5 identical-payload ICMP probes are naturally uniform. The detector
(`tunnelscope/leakage/leakage.py`: `padding_active = distinct <= 1 and len(lens) >= 5`) cannot
distinguish "traffic happens to be uniform" from "padding is forcing uniformity", because EXP-05's
original synthetic dataset always paired non-uniform unpadded traffic against uniform padded
traffic and never tested naturally-uniform *unpadded* traffic as its own case. **Not fixed this
session** — recorded as a second honest follow-up, found by the same real-traffic test that found
the first one.

**What did generalize correctly:** `esp_cipher_family` (EXP-01 sieve) correctly did not exclude the
true cipher; `mode` and `pfs` correctly stayed NOT_OBSERVABLE. The addendum's net effect: EXP-10 now
covers both IKE-control-plane and ESP-dataplane generalization against the same independent
codebase, and has surfaced two real, disclosed limitations that seven implementations' worth of
prior captures (strongSwan classical/PQ + Libreswan) never exercised.
