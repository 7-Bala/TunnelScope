# EXP-47 — A FortiGate-VM (FortiOS 7.6.7) as an independent IKE implementation (T-118 step 2) — RESULT (2026-10-04)

Pre-registration `PREREG.md` (28d7ed0) with five dated addenda (A-E, all before the runs they govern); harness, scorer and ground-truth
capture committed before the scored runs. Every number below is from `results/summary-*.json`; the device's own reports (redacted of
key material) are in `results/ground-truth/`, SHA-256 of every capture in `results/capture-manifest.json` (the captures stay local).

## Setup, in one paragraph
FortiGate-VM `FGT_ARM64_KVM` v7.6.7 build 3704 (Fortinet support portal, owner's FortiCloud account), running natively on an Apple M4 under
QEMU 11.1.1 with Hypervisor.framework; peer Alpine 3.24.2 with strongSwan 6.0.7; a virtual wire with a `filter-dump` capture (both
directions); **licence state `Invalid` throughout** (the evaluation licence was never applied; the image offers only DES encryption
with five hashes and DH groups 1, 2, 5, 14-21, 27-32). 18 arms: 10 IKEv2 suites (md5/sha1/sha256/sha384/sha512; groups 2, 5, 14, 15,
16, 19, 20, 21, 31, 28), IKEv1 main and aggressive mode, the FortiGate as responder, three rekey arms (120 s phase-2 lifetime; PFS on,
off, on with ECP-256), and two failures (no common DH group; wrong pre-shared key). (The PREREG heading said 17 arms; the table lists 18.)

## What happened to the lab (disclosed, because it changed the data)
1. First full run: 15 arms formed a tunnel; V01, V02 and P01 did not. Cause found afterwards: a **stale peer configuration** (my harness typed
   `swanctl.conf` through a slow serial console without checking it) and, for V02, strongSwan's default refusal of IKEv1 aggressive-mode PSK
   ("Aggressive Mode PSK disabled for security reasons"). Addenda B and C: harness checks the file by MD5; the peer opt-in was set; arms re-run.
2. First scoring pass (kept as `summary-before-fix-first-pass.json`): **8 of the 16 captures held no handshake** (the FortiGate renegotiated while I
   was still reconfiguring it, before the capture began; its own report still matched the arm). Addendum D: tunnel interface down, cleared and verified,
   peer and FortiGate configured, capture started, only then interface up; the scorer gates H1/H2/H6 on the handshake being in the capture;
   those 8 arms re-run, their first captures kept in `first-run-midstream/` and scored separately.
3. V01 and V02 (IKEv1) in the final set formed the complete phase 1 (six and three messages on the wire, both ends report the IKE SA) but no Quick
   Mode child; they are scored on the IKE SA only (Addendum B). 560 pings were sent in the 14 arms that carried ESP, 4 lost, all while the SA came up.

## Results
Final set (16 arms with the handshake in the capture + 2 failure arms); `before-fix` is TunnelScope as on `origin/main` (7539ca3), `after-fix` adds F1 and F2:

| Bar | before fix | after fix |
|---|---|---|
| H1 handshake values are never wrong (version, PRF, integrity, group, PQ) | **PASS**, 0 wrong in 16 arms | PASS |
| H2 the IKE cipher is named | **FAIL** as predicted: IKEv2 prints `encr-2` (14 arms); IKEv1 already says `DES-CBC` | **PASS** (`DES`, `DES-CBC`) |
| H3 the ESP candidate set contains the true family | **FAIL** as predicted: the 12 SHA-2 arms; md5 and sha1 (96-bit ICV) pass | **PASS** |
| H4 PFS is never wrong | PASS: P01 yes (INFERRED), P02 no (INFERRED), P03 UNKNOWN (ECP-256: the size rule is uncalibrated) | PASS |
| H5 the implementation is not misnamed | PASS (UNKNOWN; scored for the FortiGate's role, see below) | PASS |
| H6 verdicts equal those on the expected values | PASS | PASS |
| H7 failures are diagnosed honestly | PASS: X01 `ike-proposal-mismatch` (OBSERVED), X02 `auth-or-child-failure` (INFERRED, not success) | PASS |
| H8 nothing else changes | not yet | per-arm results outside H2/H3 unchanged (0 differences); corpus differential below |

| Arm | Setup | Handshake values (H1) | IKE cipher before -> after | ESP family before -> after | PFS (rekey arms) |
|---|---|---|---|---|---|
| P01 | v2, des-sha256, group 14, rekey 120 s | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | INFERRED True |
| P02 | v2, des-sha256, group 14, PFS off, rekey 120 s | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | INFERRED False |
| P03 | v2, des-sha256, group 19, rekey 120 s | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | UNKNOWN None |
| R01 | v2, FG responds, des-sha256, group 14 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S01 | v2, des-md5, group 2 | ok | `encr-2` -> `DES` | truth in set -> truth in set | - |
| S02 | v2, des-sha1, group 5 | ok | `encr-2` -> `DES` | truth in set -> truth in set | - |
| S03 | v2, des-sha256, group 14 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S04 | v2, des-sha384, group 15 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S05 | v2, des-sha512, group 16 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S06 | v2, des-sha256, group 19 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S07 | v2, des-sha256, group 20 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S08 | v2, des-sha256, group 21 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S09 | v2, des-sha256, group 31 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| S10 | v2, des-sha256, group 28 | ok | `encr-2` -> `DES` | TRUTH MISSING -> truth in set | - |
| V01 | v1 main, des-sha256, group 14 | ok | `DES-CBC` -> `DES-CBC` | no child SA -> no child SA | - |
| V02 | v1 aggressive, des-sha256, group 14 | ok | `DES-CBC` -> `DES-CBC` | no child SA -> no child SA | - |

| Arm | Setup | | Diagnosis | Bar |
|---|---|---|---|---|
| X01 | v2, des-sha256, group 32 | failure arm | ike-proposal-mismatch (OBSERVED) | PASS |
| X02 | v2, des-sha256, group 14 | failure arm | auth-or-child-failure (INFERRED) | PASS |

## Defects found in TunnelScope (the point of the experiment)
- **D1 (fixed, F1): the IKEv2 cipher DES was an unnamed `encr-2`.** Names for IANA ids 1, 2, 4-9 added from the registry (read 2026-10-03). Not a wrong
  value, but a Fortinet evaluation device can say nothing else.
- **D2 (fixed, F2): the ESP sieve could not contain the truth.** DES-CBC with HMAC-SHA-2 was not a modelled family, so for 12 arms the INFERRED set listed
  AES/NULL families only. Three families added (RFC 4868 truncations). Corpus effect, measured against `origin/main` on the same 163 captures: of 418
  `esp_cipher_family` findings 354 unchanged and 64 gained exactly these three families (12 in exp47); none lost one and no status changed; **6 records move from
  "AEAD/stream (CBC excluded)" to "CBC or AEAD/stream (ambiguous)"**, which is less informative but still true.
- **D3 (found, NOT fixed, needs the owner): `pfs = False` (INFERRED, 0.9) when the IKE group is not visible.** In the first, mid-stream capture of P03 (ECP-256 PFS,
  no IKE_SA_INIT in the capture) TunnelScope called PFS off while the device ran PFS. A short rekey request looks the same with PFS off and with PFS on and a small
  key-exchange group. A drafted change (UNKNOWN when the group is not visible and the request is short) makes exactly two existing tests fail, because they pin
  the lab capture `rekey-cs-pfs-off-aes256gcm16-run2.pcap` (also without IKE_SA_INIT, and truly PFS off) as INFERRED False:
  `tests/test_extract.py::test_finding[rekey-cs-pfs-off-aes256gcm16-run2.pcap-pfs-INFERRED-False]` and
  `tests/test_pfs_padding.py::test_minimal_padding_implementations_keep_their_answer[rekey-cs-pfs-off-aes256gcm16-run2.pcap-False]`. It would turn a correct-by-luck
  answer on that capture into UNKNOWN. AGENTS.md forbids editing a test to make it pass and this changes a specification, so it is **not applied**. The diff is one
  `elif dh_val is None:` branch in `extract_pfs` (before the final `else`), returning UNKNOWN with an explanatory note.
- **D4 (small, not fixed):** DH group 28 (brainpoolP256r1) prints as the unnamed `dh-28`; groups 27, 29, 30 and 32 are likewise unnamed. The rules treat `dh-N` by number, so
  verdicts are right.

## What the FortiGate showed (reported, no bar)
- FortiOS rekeys the child SA about 90 s after a 120 s configured lifetime (measured intervals 89-93 s; three rekey requests per arm), i.e. at roughly three
  quarters of it. TunnelScope reports the measured interval and never the configured lifetime.
- No extra padding was detected in its encrypted IKE messages (the RouterOS trap of EXP-26 does not apply).
- Its IKEv1 messages carry ten vendor IDs (two unknown to strongSwan); its IKEv2 messages the notify set 16388, 16389, 16430 (responder side adds 16418, 16404).
  `implementation` stays UNKNOWN: that set is not in the three-implementation fingerprint table (EXP-29).
- `diagnose vpn tunnel list` gave the ESP SPIs; they matched the SPIs on the wire in every arm that carried ESP.

## Disclosures
- H5 as written ("naming strongSwan fails") would have failed R01, where TunnelScope correctly names the strongSwan *initiator*. It is scored on the FortiGate's role
  (Addendum D) and the literal reading is stored beside it (`literal_reading_pass`: false on R01 only, for that reason).
- The ground-truth gate first demanded an ESP report from phase-1-only arms (scorer bug, fixed before the final scoring; it stopped V01 and V02 and nothing else).
- One throwaway rehearsal (S03) preceded the scored run; it showed the two predicted failures.
- My PREREG named ids "1-6 and 8-10" for the cipher names; the registry has 1, 2, 4-9 (10 is reserved). Corrected in Addendum E.

## What this does not show
One FortiOS build, only the unlicensed DES-only state: **no AES, GCM, certificate-signature or post-quantum suites, and not FortiOS 7.6's hybrid key exchange**; a virtual
NIC (no hardware offload); PSK only, no NAT-T; one peer implementation (strongSwan). Licensed and physical FortiGates are untested. No Juniper device (T-118 step 3
is dropped: the owner could not register, Juniper requires a company email).

## Decision
DEC-060: FortiOS (unlicensed evaluation image 7.6.7, DES-only) is added to the validated implementations for the handshake, IKEv1, rekey and failure findings; F1
and F2 ship; **D3 awaits the owner's decision** (apply the `elif` and change the two pinned expectations, or keep the current rule and document the limit).

## Addendum, 2026-10-04: D3 resolved by the owner (option a)
The owner approved the fix. PREREG addendum F (written before the code change) predicted exactly 4 changed records over the 175-capture local corpus; the findings
differential (`build/findings_diff.py --base HEAD`) showed 4 changed findings, the same 4, all `pfs` INFERRED False (0.9) to UNKNOWN: `exp47/first-run-midstream/P02`,
`exp47/first-run-midstream/P03`, `rekey-cs-pfs-off-aes256gcm16-run2`, `synthetic/cve-2026-78135-plaintext-positive`. P03 (PFS on, ECP-256) is no longer wrong; P02 and the
rekey-cs capture (PFS really off) lose a correct answer, because without the IKE group a short rekey request cannot separate PFS-off from a small-KE PFS rekey. A request of
400 B or more still reads INFERRED True. Mutation check: restoring the old branch fails three tests (the changed pin in `test_extract.py`, the new unit test, the new
`test_pfs_padding.py` test). Full pytest after the change: 654 passed, 1 skipped. The scored sets above are unchanged; this addendum does not alter their numbers.
