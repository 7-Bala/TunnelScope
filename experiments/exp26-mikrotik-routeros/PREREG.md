# EXP-26 — Does TunnelScope stay right on a different vendor's IKE stack (MikroTik RouterOS)? — PRE-REGISTRATION (2026-09-26, before any capture)

Owner, 2026-09-26: roadmap T-118 step 1, approved ("ok start building it and after downloading it and
using it delete it"). Why: every capture so far comes from strongSwan, Libreswan or OpenBSD `iked`
(EXP-10). VyOS, pfSense and OPNsense run strongSwan inside, so they would re-test the same code.
MikroTik RouterOS has its own IKE implementation and a free licence that runs forever (1 Mbps upload
per interface, enough for handshakes and small traffic).

## Setup (fixed before capture)
- **Software:** RouterOS CHR **7.24.4 (stable)**, arm64 image `chr-7.24.4-arm64.img.zip` from
  `download.mikrotik.com` over HTTPS. SHA-256 of the zip, computed by us:
  `6ba35e64bbfc31283c5b3fc2d4e42500df851362fb8934941436286f8b79ce12` (MikroTik publishes no checksum
  file at the usual paths, so this is not vendor-verified). Deleted after the experiment (owner's rule).
- **Two VMs**, QEMU 11.1.1 on the arm64 Mac, **emulated Cortex-A72** (`-accel tcg`). Finding from setup,
  stated because it matters for anyone reproducing this: with `-cpu host -accel hvf` the RouterOS kernel
  panics ("No working init found") at 0.04 s on every boot; with an emulated Cortex-A72 it boots. The
  likely cause is that RouterOS's arm64 build needs 32-bit ARM support, which Apple Silicon lacks; not
  proven, not needed for this experiment.
- **Wire:** VM A `ether2` 10.99.0.1/30 ↔ VM B `ether2` 10.99.0.2/30, joined by a QEMU UDP cable.
  Protected networks: A 10.1.1.0/24 (bridge), B 10.2.2.0/24 (bridge). Policy between them, tunnel mode.
- **Vantage (T0, keyless):** QEMU's `filter-dump` on VM A's cable NIC writes every frame on the cable
  to a pcap, one pcap per arm. Nothing on the observer side holds keys.
- **Roles:** A initiates, B responds (`passive=yes`). IKEv2, pre-shared key (a lab-only throwaway
  string kept under `testbed/`, as the project rules allow).
- **Traffic per arm:** ICMP from 10.1.1.1 to 10.2.2.1 through the tunnel, mixed sizes
  (56, 200, 500, 1000, 1400 bytes), at least 60 packets, so the ESP extractors have data.
- **Ground truth (T2, from the device, never from TunnelScope):** the arm's configuration (every
  single-offer arm offers exactly one suite, so a successful negotiation can only have selected it),
  plus RouterOS's own `/ip/ipsec/installed-sa` (SPIs, ESP algorithms, key size) and
  `/ip/ipsec/active-peers`, read over the REST API right after the capture, saved as
  `<arm>.groundtruth.json`.

## What RouterOS 7.24.4 accepts (probed on the running VMs before this file; no traffic captured)
IKE encryption: des, 3des, aes-128/192/256 (CBC only, no GCM). IKE hash/PRF: md5, sha1, sha256, sha384,
sha512. Groups: modp768…8192, ecp256/384/521, x25519. ESP: null, des, 3des, aes-cbc, aes-ctr,
aes-gcm, chacha20poly1305, blowfish, twofish. PFS groups: modp and ecp only (not x25519). Post-quantum:
RFC 8784 PPK (`ppk` setting), **no ML-KEM**. Minimum child lifetime accepted: 30 s.

## Arms
| Arm | IKE (enc / hash=PRF / group) | ESP | PFS | Child lifetime | Purpose |
|---|---|---|---|---|---|
| M1 | aes-256 / sha256 / modp2048 | aes-256-gcm | none | 30m | Baseline, mirrors the lab's `cs-aes256gcm16` |
| M2 | aes-256 / sha512 / x25519 | chacha20poly1305 | none | 30m | Modern suite |
| M3 | aes-128 / sha256 / ecp256 | aes-128-gcm | none | 30m | ECP group, 128-bit |
| M4 | 3des / sha1 / modp1024 | 3des + sha1 | none | 30m | Legacy weak: rules must fail |
| M5 | aes-256 / sha384 / ecp384 | aes-256-cbc + sha256 | none | 30m | CBC + HMAC data plane |
| M6 | aes-256 / sha256 / modp2048 | aes-256-cbc + sha256 | ecp256 | 30s | PFS on, with rekeys |
| M7 | aes-256 / sha256 / modp2048 | aes-256-cbc + sha256 | none | 30s | PFS off, with rekeys |
| M8 | initiator offers modp1024 **and** modp2048; responder accepts modp2048 only | aes-256-gcm | none | 30m | Weak group offered but not selected |
| E1 | M1 plus RFC 8784 PPK on both sides | aes-256-gcm | none | 30m | Exploratory, see H7 |

M6/M7 run long enough for at least two child rekeys (about 100 s of traffic). If RouterOS refuses an
arm, it is reported as DROPPED with the error, never silently replaced.

## Scoring (fixed now)
Scored findings: `ike_version`, `ike_encr`, `ike_integ`, `ike_prf`, `ike_dh_group`, `ike_offered_dh`,
`pq_key_exchange`, `ipsec_protocols`, `esp_cipher_family`, `pfs`, `negotiation_outcome`,
`sequence_integrity`, `early_childsa_cve`.
- **Correct:** OBSERVED/MEASURED value names the same algorithm and key size as ground truth
  (spelling ignored); INFERRED set contains the true value (for `pfs`: equals it).
- **Unknown:** UNKNOWN or NOT_OBSERVABLE — never counted as wrong, counted against coverage.
- **Wrong:** anything else. Every wrong finding becomes its own bug-fix task.
Reported, not scored: `mode`, `rekey_cadence`, `traffic_type`, `metadata_exposure`, `peer_auth_method`,
`responder_cert_capability`, and any vendor ID TunnelScope surfaces.

## Hypotheses and pass bars
- **H1 (primary):** zero **wrong** scored findings across M1–M8.
- **H2:** `ike_encr`, `ike_integ`, `ike_prf`, `ike_dh_group` are OBSERVED (not UNKNOWN) in all of M1–M8.
- **H3:** `pfs` is True in M6 and False in M7 (UNKNOWN fails H3 without failing H1).
- **H4:** at least one rekey measured in M6 and in M7, each measured interval ≤ 30 s plus 5 s slack.
- **H5 (specificity):** `early_childsa_cve` is `not-detected` in every arm.
- **H6 (compliance):** M4 fails `RFC8247-DH-MUST`, `RFC8247-ENCR` and `RFC8221-ESP-3DES`; M1 passes all three;
  M8 fails `RFC8247-DH-OFFER` and passes `RFC8247-DH-MUST`.
- **H7 (exploratory, predicted gap):** in E1 TunnelScope reports `classical-only`, because it detects
  RFC 9370 additional key exchanges but has no RFC 8784 PPK detector. If so, that is a documented gap and
  a new task, not a pass or fail.

## What will not change during EXP-26
No TunnelScope code, rule or model changes until RESULT.md is written. Fixes for anything found here
are separate tasks with their own review.
