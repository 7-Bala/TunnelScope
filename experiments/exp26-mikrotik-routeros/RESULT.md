# EXP-26 — MikroTik RouterOS 7.24.4: one wrong finding, and why — RESULT (2026-09-26)

Pre-registration: `PREREG.md` (commit 8893dc3, before any capture). Captures and ground truth:
`testbed/captures/exp26/`. Scoring: `analyze.py` → `results/score.json`. Diagnostic:
`results/m7_padding_diagnostic.json`. Lab: `testbed/mikrotik/boot.sh`, `testbed/scripts/run_exp26_mikrotik.py`.

## Headline
On a vendor stack we had never tested, **97 of 104 scored findings were correct, 6 were UNKNOWN (all
correctly so), and 1 was wrong.** The wrong one is a real generalisation bug: **forward secrecy
(PFS) was inferred ON for a tunnel where it was OFF**, because RouterOS pads its encrypted IKE messages
by up to ~255 bytes and TunnelScope's PFS rule reads message size. Every IKE suite field (encryption,
integrity, PRF, key-exchange group, including x25519 and ECP) was read correctly in all 8 arms.

## Runs
All 8 scored arms ran as pre-registered (1 IKE SA and 1 child SA pair each; M6/M7 with rekeys).
**E1 (RFC 8784 PPK) DROPPED:** RouterOS 7.24.4 has a `ppk` profile setting, but its only accepted value
is `no` (tried yes/allow/require/required/optional/insist/mandatory/auto/…); identities have no PPK
field (CLI completion), and MikroTik's IPsec documentation does not mention PPK. Error kept in
`testbed/captures/exp26/mt-e1.dropped.txt`. H7 therefore could not be tested.

## Hypotheses
| | Bar | Result | Verdict |
|---|---|---|---|
| H1 | zero wrong findings, M1–M8 | **1 wrong** (M7 `pfs`) | **FAIL** |
| H2 | IKE encr/integ/PRF/group OBSERVED in all arms | 32 of 32 correct | PASS |
| H3 | `pfs` True in M6, False in M7 | M6 True (correct), **M7 True (wrong)** | **FAIL** |
| H4 | ≥1 rekey in M6 and M7, each interval ≤ 35 s | M6: 3 rekeys, 31.08 s and 31.09 s. M7: 2 rekeys, **38.03 s** | FAIL as written (see below) |
| H5 | `early_childsa_cve` = `not-detected` in every arm | 0 detections. Literal is `not-applicable` in M1–M5/M8 (no CREATE_CHILD_SA in the capture) and `not-detected` in M6/M7 | FAIL as written, **no false alarm** |
| H6 | M4 fails DH-MUST, ENCR, ESP-3DES; M1 passes them; M8 fails DH-OFFER, passes DH-MUST | M4: DH-MUST FAIL, ENCR FAIL, **ESP-3DES UNKNOWN**; M1 passes all; M8 as predicted | **FAIL** (one UNKNOWN) |
| H7 | exploratory: PPK not detected | E1 dropped | not tested |

### Why each failure happened
- **H1/H3: padding defeats the size-based PFS rule.** A diagnostic re-run of the M7 configuration
  with RouterOS's `ipsec,debug` log (post-hoc, not scored) shows every rekey request holds **132 bytes
  of plaintext** (Nonce 28, Notify REKEY_SA 12, SA 44, TSi 24, TSr 24) and **no KE payload**, yet the
  encrypted part is 388–404 bytes; a 12-byte Delete is sent as 304–320 bytes. RFC 7296 §3.14 allows
  any pad length. `extract_pfs` (calibrated on strongSwan, which pads minimally) treats a request of
  400 bytes or more as carrying a KE payload, so M7's 444-byte padded request read as PFS on.
  **M6's "correct" answer is therefore not evidence:** its requests (476, 444, 444 bytes) are
  indistinguishable from M7's padded ones. Ground truth for the padding: RouterOS's own debug output.
- **H4: TunnelScope measured correctly; my prediction about RouterOS was wrong.** The M7 rekey
  requests sit at 38.44 s and 76.47 s on the wire (tshark), exactly the 38.03 s TunnelScope reports.
  RouterOS simply rekeyed a 30 s child SA after 38 s in that arm. `rekey_cadence` was a reported,
  not scored, field; the bar encoded an assumption about the device, not about the tool.
- **H5: wording.** The detector says `not-applicable` when a capture has no CREATE_CHILD_SA at all,
  which is true for the arms without rekeys. No arm produced a detection.
- **H6: 3DES cannot be singled out by length.** 3DES-CBC+HMAC-SHA1-96 shares its IV/ICV/alignment
  signature with DES, Blowfish and CAST, so the ESP sieve returns a set that contains the truth
  (scored correct) and the 3DES rule honestly says UNKNOWN. The IKE-side 3DES rule did fail as it should.

## Other observations (reported, not scored)
- `mode` UNKNOWN and `traffic_type` UNKNOWN in all arms (short ICMP traffic; consistent with EXP-08/15).
- `peer_auth_method` NOT_OBSERVABLE in all arms (correct: PSK vs certificate is encrypted).
- RouterOS sends **no Vendor ID** payload, so vendor fingerprinting (roadmap T-127) cannot rely on VIDs here.
- RouterOS sends a dead-peer-detection INFORMATIONAL every 8 s by default, also padded (108–172 bytes).
- Setup finding: RouterOS arm64 does not boot under `-cpu host -accel hvf` on Apple Silicon
  (kernel panic "No working init found"); it boots on an emulated Cortex-A72.

## What follows (separate tasks, per the pre-registration)
1. **Fix `extract_pfs` for padding implementations** (new task T-135): the size rule must not claim
   PFS when the capture shows the implementation pads (e.g. same-type messages whose sizes vary by more
   than one cipher block, or a Delete far larger than its content allows). Expected outcome on EXP-26:
   M6 and M7 both UNKNOWN (never wrong), strongSwan/Libreswan results unchanged. Verified against the
   committed EXP-26 captures and the existing dataset.
2. **RFC 8784 PPK detection** (new task T-136): needs an implementation that actually negotiates PPK.
3. FortiGate-VM and Juniper vSRX (T-118 steps 2 and 3) remain, each needing the owner's download.

## Clean-up
The RouterOS image, both VM disks and QEMU were deleted after the run (owner's rule); the captures,
ground truth and scripts in the repo are enough to re-score without the VMs.
