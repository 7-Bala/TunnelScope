# EXP-47 — A FortiGate-VM (FortiOS 7.6.7) as an independent IKE implementation (T-118 step 2) — PRE-REGISTRATION (2026-10-03, before any scored capture)

## Why
Every capture so far comes from strongSwan, Libreswan or RouterOS (EXP-26). T-118 asks for implementations with genuinely
different IKE code, and the rule that decides every such experiment: **each TunnelScope finding either equals the device's own
report or is UNKNOWN; never wrong.** Fortinet's IKE daemon is a different code base again, and FortiOS is the gateway the
judges' critique named. This experiment captures a real FortiGate-VM against a strongSwan peer, with the device's own
diagnostics as ground truth.

## Lab (built before this registration; nothing scored yet)
- **Device under test:** `FGT_ARM64_KVM-v7.6.7.M-build3704-FORTINET.out.kvm.zip` (Fortinet support portal, FortiCloud account of
  the owner; 108,605,838 bytes; SHA-512 `d9284b8b546abcd90e5be7b2b76f56d641c7966065c46b4d4345878a97a3acc2444052213b2b3e2fb1293db718cd870cc8ce258d7e7f21e86a03019ae8db48e8`
  verified against the portal), run natively on an Apple M4 under QEMU 11.1.1 with Hypervisor.framework, 1 vCPU, 2 GB.
  **Licence state: `Invalid` (the permanent evaluation licence was never applied).** FortiOS offers, in this state, only the
  IKE/ESP proposals `des-md5`, `des-sha1`, `des-sha256`, `des-sha384`, `des-sha512` (DES encryption, five hashes) and DH groups
  1, 2, 5, 14-21, 27-32 (read from the device CLI).
- **Peer:** Alpine Linux 3.24.2 aarch64 (official ISO, SHA-256 `a57ba668...dbf6` verified), strongSwan 6.0.7, on a virtual
  Ethernet wire (10.50.0.1 FortiGate `port2` <-> 10.50.0.2 peer `eth1`). The capture is QEMU's `filter-dump` on that wire (both
  directions, identical to a SPAN), started and stopped per arm through the QEMU monitor.
- **Scripts:** `testbed/fortigate/lab.sh`, `fgt_console.py`. Lab files live outside the repository; captures stay local, the
  repository gets a manifest (SHA-256 per capture) and the ground-truth JSON per arm.
- **Exploratory, unscored, done before this file:** three probe captures (an IKEv2 tunnel `des-sha256`/group 14). They showed
  that FortiOS needs a firewall policy before it initiates, that the unlicensed VM negotiates IKE and ESP, and that TunnelScope
  labels IKE encryption id 2 (DES) as the unnamed string `encr-2`. The arms below were fixed after that, from what the device offers.

## Arms (17; each = configure both ends, record the wire, bring the tunnel up, send 40 pings in the tunnel, read the ground truth)
Common: PSK, tunnel mode, no NAT, selectors 10.61.0.0/24 (FortiGate loopback) <-> 10.62.0.0/24 (peer loopback), pings between
the two loopbacks (28 at 56 bytes and 12 at 1000 bytes), FortiGate initiates unless noted, IKE and ESP use the same hash.

| Arm | IKE | Proposal (FortiOS name) | DH (IANA id) | Role / extra |
|---|---|---|---|---|
| S01-S05 | v2 | des-md5 / des-sha1 / des-sha256 / des-sha384 / des-sha512 | 2 / 5 / 14 / 15 / 16 | PFS on, same group |
| S06-S09 | v2 | des-sha256 | 19 / 20 / 21 / 31 | PFS on, same group |
| S10 | v2 | des-sha256 | 28 (brainpoolP256r1) | PFS on; the peer may be unable (then see "unnegotiable") |
| V01, V02 | v1 | des-sha256, main mode / aggressive mode | 14 | PFS on |
| R01 | v2 | des-sha256 | 14 | the peer initiates, the FortiGate responds |
| P01, P02, P03 | v2 | des-sha256 | 14 / 14 / 19 | phase-2 key lifetime 120 s, 5 minutes recorded; P01 PFS on, P02 PFS off, P03 PFS on |
| X01 | v2 | des-sha256 | 32 (Curve448, FortiGate offers only this; the peer has no such group) | failure: proposal mismatch |
| X02 | v2 | des-sha256 | 14 | failure: wrong pre-shared key on the peer |

An arm whose tunnel cannot form for a reason other than X01/X02 is reported as **unnegotiable** with the device's and the
peer's own error text, and counts toward no bar except H8 (the failure diagnosis).

## Ground truth (read from the device and the peer, never from TunnelScope)
FortiGate: `diagnose vpn ike gateway list` (version, proposal, lifetime, PPK, PQC), `diagnose vpn tunnel list name <p1>`
(`esp=`, `ah=`, SPIs, life, replay window, `mode=`, `encap=`), the phase-1/-2 configuration. Peer: `swanctl --list-sas` and the
loaded connection. Expected suite per arm is also written down here from the arm table:

| Hash | IKE integrity (id) | PRF (id) | ESP integrity | ESP cipher |
|---|---|---|---|---|
| md5 | HMAC-MD5-96 (1) | PRF-HMAC-MD5 (1) | HMAC-MD5-96 | DES-CBC |
| sha1 | HMAC-SHA1-96 (2) | PRF-HMAC-SHA1 (2) | HMAC-SHA1-96 | DES-CBC |
| sha256 | HMAC-SHA2-256-128 (12) | PRF-HMAC-SHA2-256 (5) | HMAC-SHA2-256-128 | DES-CBC |
| sha384 | HMAC-SHA2-384-192 (13) | PRF-HMAC-SHA2-384 (6) | HMAC-SHA2-384-192 | DES-CBC |
| sha512 | HMAC-SHA2-512-256 (14) | PRF-HMAC-SHA2-512 (7) | HMAC-SHA2-512-256 | DES-CBC |

IKE encryption is DES-CBC (IANA id 2) in every successful arm. A disagreement between the FortiGate's report, the peer's report
and this table stops the arm: it is reported, not scored.

## Hypotheses and bars (fixed here)
- **H1 (handshake values are never wrong):** in every established arm, `ike_version`, `ike_prf`, `ike_integ`, `ike_dh_group`,
  `pq_key_exchange` (= classical-only) each equal the expected value or are UNKNOWN. One wrong value fails H1.
- **H2 (the IKE cipher is named):** `ike_encr` names DES-CBC in every established arm. **Predicted to fail before any change**
  (all arms report `encr-2`, because the name table has no entry for IANA id 2). It is a defect found by this experiment, not
  a wrong value; the fix (names for the missing IKE encryption ids 1-6 and 8-10 of the IANA registry that have a defined name) is
  made after the result and re-scored on the same captures.
- **H3 (ESP family candidates are honest):** when `esp_cipher_family` is INFERRED, its candidate set contains the true family
  (DES-CBC with the arm's integrity). **Predicted to fail for sha256, sha384 and sha512 arms**: the sieve table has
  `DES-CBC+HMAC-96` (md5, sha1) but no DES-CBC family with a 16-, 24- or 32-byte ICV, so the truth cannot be in the set.
  Fix after the result: add the three families; re-score.
- **H4 (PFS is never wrong):** in P01-P03 and S-arms with a rekey observed, `pfs` equals the ground truth (P01 yes, P02 no, P03
  yes) or is UNKNOWN; a wrong value fails H4. (EXP-26's lesson: some stacks pad IKE messages, which fooled the size rule.)
- **H5 (the implementation is not misnamed):** `implementation` is UNKNOWN or `FortiGate`/`FortiOS`; naming strongSwan,
  Libreswan or RouterOS fails H5. Predicted UNKNOWN (Fortinet's notify set is not in the fingerprint table).
- **H6 (verdicts follow the facts):** every default-rule verdict equals the verdict the same rules give when fed the expected
  values (table above) directly. One disagreement fails H6.
- **H7 (failures are diagnosed honestly):** X01 -> `negotiation_outcome` reports a proposal mismatch (or UNKNOWN); X02 -> not
  reported as a successful tunnel (ambiguous or UNKNOWN). Never "success".
- **H8 (nothing else changes):** the findings differential over the existing corpus before/after the H2/H3 fixes shows only
  (a) IKE encryption id 2 named and (b) the sieve table's new families, with the corpus's existing results otherwise identical
  (as `build/findings_diff.py` checks).
Reported, without a bar: the `rekey_cadence` measured against the configured 120 s; FortiOS's padding of encrypted IKE messages;
the notify types and vendor IDs Fortinet sends.

## Not claimed
Only one FortiOS build, only the unlicensed DES-only state (no AES, GCM, ECP-signature or post-quantum suites, no FortiOS 7.6
hybrid key exchange, which the evaluation image does not offer), a virtual NIC (no hardware offload), PSK only, no NAT-T, one peer
implementation. Behaviour of licensed FortiGates and physical appliances is not tested. No Juniper device (T-118 step 3 is
dropped: the owner could not register, Juniper requires a company email).

## Rules of this experiment
No arm, bar or prediction above changes after this commit. RESULT.md quotes `results/summary.json` only. Addenda go below,
dated, before the run they govern.

## ADDENDUM A (2026-10-03, after the harness and scorer, after one throwaway rehearsal of arm S03, before the run that counts)
No arm, bar or prediction above changes. Details the scorer needs, fixed here:
1. **H2** passes when `ike_encr` is exactly `DES` or `DES-CBC`.
2. **H3** truth names in the sieve table: `DES-CBC+HMAC-96` (md5 and sha1; already in the table), and `DES-CBC+HMAC-SHA256-128`,
   `DES-CBC+HMAC-SHA384-192`, `DES-CBC+HMAC-SHA512-256` (sha256, sha384, sha512; to be added by the fix after the result).
3. **H6** feeds the same rules a copy of the record whose `ike_encr` is `DES` and whose PRF, integrity and group are the expected ones.
4. **Ground-truth gate:** an arm is scored only if the FortiGate's `proposal`, `esp=` and `ah=` and the peer's IKE suite all equal
   the arm table; the ESP SPIs the FortiGate reports must appear on the wire (reported, not a bar).
5. Peer-side child `rekey_time` is 3000 s so that the FortiGate (phase-2 keylife 120 s) is the side that rekeys in P01-P03.
6. The rehearsal (S03 into a throwaway folder) showed `ike_encr = encr-2` and a candidate set without the true family, i.e. the
   two predicted failures; S03 is captured again in the scored run. 26 of 28 small pings succeeded in the rehearsal (the first
   two are sent while the SA is still coming up); ping loss is reported per arm and is not a bar.

## ADDENDUM B (2026-10-03, after the first full run, before the re-run it governs)
Facts, then the change. The first run captured 18 arms (the arm table lists 18, S01-S10, V01, V02, R01, P01-P03, X01, X02; the
heading "17 arms" above was a miscount). Three did not form a full tunnel:
- **V02 and P01:** the peer replied `NO_PROPOSAL_CHOSEN` ("no IKE config found for 10.50.0.2...10.50.0.1"), which strongSwan
  sends when no loaded connection matches the request's IKE version or aggressive-mode flag. The most likely cause is a **stale
  peer configuration**: the harness types `swanctl.conf` through a slow serial console and did not verify that the file landed
  (inferred from the message and from the neighbouring arms; the peer's own log of that period was rotated away by the X02 flood,
  so this is not directly proven). A lab fault of mine, not a FortiGate behaviour.
- **V01:** the IKEv1 main-mode IKE SA **was** established on both ends (the FortiGate reports `proposal: des-sha256`, the peer
  `DES_CBC/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048`); the Quick Mode child failed. The harness counted only a full tunnel
  as established.
Changes: (1) the harness now verifies the peer's `swanctl.conf` by MD5 (up to 4 writes), empties the peer log before each arm and
keeps the arm's IKE/CFG/ENC/NET log lines in the ground-truth JSON; (2) **V01, V02 and P01 are re-run once**; the first attempts
are kept under `first-attempt/` and reported; (3) the scorer scores the IKE SA (H1, H2, H5, H6) whenever it is established on both
ends even if the child SA failed, and then does not score H3/H4 for that arm. The other 15 arms are not re-run. If the re-run
of an arm fails again it is reported as unnegotiable with the new logs.

## ADDENDUM C (2026-10-03, after the V01/V02/P01 re-run, before the V02 re-run it governs)
The re-run formed V01 and P01 completely. V02 did not, and this time the peer log (kept by the changed harness) names the
reason: `Aggressive Mode PSK disabled for security reasons` -- strongSwan's default refuses IKEv1 aggressive mode with a
pre-shared key. This is a peer policy, not FortiGate behaviour. The peer's deliberate opt-in
(`charon.i_dont_care_about_security_and_use_aggressive_mode_psk = yes`, written to `/etc/strongswan.d/zz-lab-aggressive.conf`)
is set on the lab peer and V02 is run once more with every other parameter unchanged. The first and second attempts are kept
under `first-attempt/` and `second-attempt/`. The setting stays on for the lab's remaining life; no other arm is re-run.

## ADDENDUM D (2026-10-03, after scoring the first complete set once, before the re-run it governs)
A first scoring pass of all 18 arms (label `before-fix-first-pass`, kept) showed that **8 of the 16 established arms' captures do not
contain the handshake**: S04, S07, S09 hold no IKE message at all; V01 and V02 start at the IKEv1 Quick Mode; P01-P03 start at a
rekey (counted with `isakmp.exchangetype`). Cause: the FortiGate renegotiated while the harness was still reconfiguring it, before
the capture started (the device's own report still matched the arm's suite, so the ground-truth gate could not notice). Changes:
1. **Harness:** each arm now (a) takes the tunnel interface down, clears both ends and verifies they are empty, (b) configures
   peer and FortiGate, (c) starts the capture, (d) only then brings the interface up and triggers. Tested: with the interface down,
   cleared SAs stayed cleared for 25 s.
2. **Scorer:** an arm is scored for H1, H2 and H6 only if its capture contains the handshake (IKE_SA_INIT, or IKEv1 main or
   aggressive mode); otherwise it is reported as **mid-stream**, scored for H3, H4 and H5 only (what a mid-stream vantage can say).
   H3-H5 are tallied over every arm with an established IKE SA.
3. **Re-run once:** S04, S07, S09, V01, V02, P01, P02 and P03. The first captures of those eight are kept in `first-run-midstream/`
   and their mid-stream results are reported (P03's first capture is also a regression case for any change to the PFS rule).
4. **H5 clarified, not loosened:** the bar's purpose is that the FortiGate is not misnamed. In R01 TunnelScope names the *initiator*
   strongSwan, which is the peer and correct; the literal reading of H5 would fail that. H5 is scored on the FortiGate's role
   (UNKNOWN or Fortinet passes); the literal reading is reported beside it (it fails on R01 for that reason only).
Not re-run: S01-S03, S05, S06, S08, S10, R01 (handshake present), X01, X02.

## ADDENDUM E (2026-10-03, after the final set was scored once with unchanged code, before any fix is committed)
Facts: `results/summary-before-fix.json` (18 arms, 16 with the handshake in the capture, 2 failure arms) and
`results/summary-midstream-first-run.json` (the eight mid-stream first captures). H1 held (no wrong handshake value in 16 arms,
IKEv2 and IKEv1, groups 2-31); H2 and H3 failed as predicted; H4-H7 passed on the final captures. The mid-stream P03 capture
(ECP-256 PFS, no IKE_SA_INIT in the capture) made TunnelScope report `pfs = False` (INFERRED, 0.9) while the device negotiated
PFS: a wrong value (H4 fails there).
Decisions, fixed before they are committed:
1. **F1 (H2):** `IKE_ENCR` gets names from IANA's "IKEv2 Parameters" registry, Transform Type 1, read on 2026-10-03: 1 `DES-IV64`,
   2 `DES`, 4 `RC5`, 5 `IDEA`, 6 `CAST`, 7 `Blowfish`, 8 `3IDEA`, 9 `DES-IV32`. (This corrects PREREG H2's wording "ids 1-6 and 8-10":
   id 7 is defined, id 10 is reserved.)
2. **F2 (H3):** the sieve table gets `DES-CBC+HMAC-SHA256-128` (IV 8, ICV 16, align 8), `DES-CBC+HMAC-SHA384-192` (8, 24, 8) and
   `DES-CBC+HMAC-SHA512-256` (8, 32, 8), per RFC 4868 truncation. Measured effect on the corpus, stated before commit: of 418
   `esp_cipher_family` findings in 163 captures, 354 unchanged, 64 gain exactly these three families (12 of them in exp47), none
   loses one, no status changes; 6 records move from "AEAD/stream (CBC excluded)" to "CBC or AEAD/stream (ambiguous)" (less
   informative, still true). `build/findings_diff.py` shows the same 64 plus the exp47 `ike_encr` renames.
3. **F3 (found, NOT applied):** the PFS overclaim above. A drafted change (UNKNOWN instead of `pfs=False` when the IKE group is
   not visible and the request is short) makes exactly two existing tests fail, both pinning `rekey-cs-pfs-off-aes256gcm16-run2.pcap`
   (a lab capture without IKE_SA_INIT) as INFERRED False: `tests/test_extract.py::test_finding[...-pfs-INFERRED-False]` and
   `tests/test_pfs_padding.py::test_minimal_padding_implementations_keep_their_answer[...-False]`. Changing a pinned expectation is
   a change of specification and AGENTS.md forbids editing a test to make it pass, so the change stays out of the code and is put to
   the owner with the diff in RESULT.md.
After-fix prediction (stated now): scoring the same captures again as `after-fix` differs from `before-fix` in H2 and H3 only, both
becoming PASS; nothing else moves.

## ADDENDUM F (2026-10-04, written before the code change): D3, the PFS rule must not assert "no PFS" when the IKE group is invisible
Owner decision 2026-10-04: option (a), fix D3 (see RESULT.md, defect D3).
Change: in `extract_pfs`, when the IKE DH group is not a visible string and no rekey request reaches 400 B, `pfs` is UNKNOWN (was INFERRED False).
A request of 400 B or more still reads INFERRED True with the existing caveat (a large request cannot come from a missing KE payload; padding is handled earlier).
Prediction, computed before the change from the current code over the whole local corpus (450 records with a `pfs` finding): exactly 4 records change from INFERRED False to UNKNOWN and nothing else moves:
`exp47/first-run-midstream/P02.pcap`, `exp47/first-run-midstream/P03.pcap`, `rekey-cs-pfs-off-aes256gcm16-run2.pcap`, `synthetic/cve-2026-78135-plaintext-positive.pcap`.
P03 (PFS on, ECP-256) stops being wrong; P02 and the rekey-cs capture (PFS really off) stop being right: the rule cannot tell them apart without the group, and that is the honest answer.
Two pinned expectations change by this decision, as a documented edit and not a silent one: `tests/test_extract.py` (pfs-off row) and `tests/test_pfs_padding.py` (pfs-off row of the minimal-padding test).
Bar: the corpus differential equals the 4 predicted records exactly; a mutation that restores the old branch fails the new test.
