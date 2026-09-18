# TunnelScope — Review-Panel Adjudication & Implementation Plan

**Tasks:** T-051 (adjudication + first implementation) → T-052 (adversarial review) → T-053 (fixes, merge)
**Last revised:** 2026-09-17
**State of the code this document describes:** branch `antigravity` after T-053, merged to `main`.
**Suites at that state:** 69/69 unit tests · 69/69 E2E captures, 0 mismatches · dataset validator PASS (78 pcaps).

This document does two jobs, kept apart on purpose:

1. **A record of decisions** — every item in the 5-model review dossier, with a verdict and the
   evidence behind it (§3).
2. **A plan** — what is implemented now (§4), and what is still to do, in priority order, with
   acceptance criteria (§5).

Nothing in §5 is done. A verdict of ADOPT means "we agree it should happen", not "it shipped".

---

## 1. Evidence standard

- **RFC text** was fetched from rfc-editor.org on 2026-09-17 (RFC 5903, 7296, 8247, 9242, 9329,
  9370, 9395, 5879) and quotes below are verbatim. Anything cited from memory is marked
  *(not re-fetched)*.
- **Code claims** name a file and line in the merged tree.
- **Behaviour claims** come from running the extractor, not from reading it. The merge gate was a
  full differential: `build_records` over all 130 pcaps under `testbed/captures/`, on `main` and on
  the branch, comparing every finding's status, value and confidence (§4.2).
- **Attribution.** The dossier attributes positions to individual models. This document does not
  repeat those attributions: the T-051 draft attributed positions the dossier does not contain, and
  who proposed an idea does not change whether it is correct.

---

## 2. Verified ground truths

### 2.1 ECP key-exchange values are x | y (ECP-256 = 64 octets)
RFC 5903 §7: *"The Diffie-Hellman public value is obtained by concatenating the x and y values."*
Only the shared secret is x-only: *"The Diffie-Hellman shared secret value consists of the x value
of the Diffie-Hellman common value."* So ECP-256 = 64 octets, ECP-384 = 96, ECP-521 = 132 (each
component zero-padded to 256/384/528 bits per the §7 table). Curve25519 = 32 octets *(RFC 8031,
not re-fetched)*. The dossier's "ECP-256 = 32 bytes" is wrong.

### 2.2 The IKE_SA_INIT transcript is authenticated end to end
RFC 7296 §2.15: *"InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI"* and
*"RealMessage1 = RealIKEHDR | RestOfMessage1"*. Each side verifies the peer's AUTH over the
message as it received it, so an in-path edit of the initiator's SA payload makes the initiator's
AUTH fail. Proposal stripping is therefore not a silent downgrade.

### 2.3 Error notifies are unauthenticated, and retries are mandatory
RFC 7296 §1.2, on INVALID_KE_PAYLOAD (notify 17): *"The initiator MUST again propose its full set
of acceptable cryptographic suites because the rejection message was unauthenticated"*. §2.21.1:
*"all error notifications are completely unauthenticated"*. So a retry after INVALID_KE_PAYLOAD is
normal protocol behaviour; it can also be induced by an attacker, and a passive observer cannot
tell which.

### 2.4 RFC 9370 additional key exchanges
- Transform Types: *"Additional Key Exchange 1 (ADDKE1) with IANA-assigned value 6"* through *"Additional Key Exchange 7 (ADDKE7) (12)"* — checking only type 6 misses 7–12.
- NONE (Transform ID 0) marks an additional exchange as optional; if the responder selects NONE,
  *"any corresponding additional key exchanges MUST NOT take place."*
- The additional exchanges run in IKE_INTERMEDIATE, and each such message *"is protected with the
  current SK_ei/SK_ai keys."* ML-KEM ciphertexts exchanged this way are **not plaintext** at T1.
- In CREATE_CHILD_SA, extra key exchanges use IKE_FOLLOWUP_KE, *"Exchange Type value is 44."*
  (TunnelScope's exchange map does not name 44 yet — §5, P2.)

### 2.5 Rekeys
RFC 7296 §1.3.2: an IKE SA rekey request is `HDR, SK {SA, Ni, KEi}` — the KE is mandatory. A Child
SA request is `HDR, SK {SA, Ni, [KEi,] ...}` — the KE (i.e. PFS) is optional. Both are inside
`SK {}`, so neither the KE nor N(REKEY_SA) is visible at T1.

### 2.6 NAT traversal changes the port mid-SA
RFC 7296 §2.23: *"Port 4500 is reserved for UDP-encapsulated ESP and IKE"*; an endpoint behind a
NAT *"MUST send all subsequent traffic from port 4500"*. Any session key containing the source
port splits one SA in two.

### 2.7 Tier numbering is the codebase's, not the dossier's
`tunnelscope/evidence/record.py:27-32`: **T0** passive ESP only · **T1** passive + IKE visible ·
**T2** endpoint telemetry (swanctl/pluto/config) · **T3** keying material · **T4** authorized
active probe. The dossier's T0–T4 (policy / wire / active prober / gateway agent / reconciler)
does not match; policy baselines are `rules/*.yaml`, and reconciliation is
`tunnelscope/crosstier/`, not a vantage. All statuses in this document use the codebase numbering.

### 2.8 The live CVE-2026-78135 exploit capture contains no IKE_AUTH
`testbed/captures/exploitlab/cve-2026-78135-live.pcap` (EXP-09) is
IKE_SA_INIT → IKE_SA_INIT → CREATE_CHILD_SA → CREATE_CHILD_SA. Any rule that requires an IKE_AUTH
response to fire would miss the real exploit.

### 2.9 Zero observed failures: what the number means
The rule of three is from Hanley & Lippman-Hand, *JAMA* 1983 ("If nothing goes wrong, is
everything all right?"), not Hanley & McNeil (1982, ROC curves). With 0 events in n independent
trials, the one-sided 95% upper bound on the event rate is 1 − 0.05^(1/n), approximated by 3/n:

| n | 3/n | exact |
|---|---|---|
| 67 | 4.48% | 4.37% |
| 69 | 4.35% | 4.25% |
| 78 | 3.85% | 3.77% |

Three caveats bound what this may be used to say:

- **n must be the detector's own judgeable negatives.** For the CVE detector that is 67, not 69:
  2 captures are UNKNOWN (EXP-09).
- **The captures are not independent.** They come from one lab, a few configurations and shared
  generators, so the true bound is wider than the table.
- **It is an upper confidence bound, not a guarantee** — and not a claim about production traffic.

---

## 3. Adjudication

**Verdicts:** ADOPT · ADAPT (right goal, corrected mechanism) · REJECT · DEFER (valid, out of current scope).
**Status:** *Done (T-05x)* = in the merged code with a test · *Planned P1–P3* = §5 · *Existing* = was already true before T-051.

### 3.1 Post-quantum negotiation and downgrade

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| PQ-1 | Read the responder's selected proposal (SAr1), matched to the initiator's proposal number | ADOPT (adapted) | The responder's IKE_SA_INIT response carries only the proposal it selected, so the selection is read directly; proposal-number matching adds nothing. `extract_pq_addke` decides from the last selecting response. | Done (T-053) |
| PQ-2 | ADDKE = `transform_type == 6 and id != 0` | ADAPT | Types 6–12 (§2.4); NONE removed. `_addke_ids` in `extract.py`. | Done (T-053) |
| PQ-3 | Classical selection when PQ was offered = PQ_NOT_SELECTED (OBSERVED), never "attack" | ADOPT | Value kept as `offered-but-not-used` (shared contract with `rules/dst-nqm-pq.yaml`, `pq/cbom.py`, `crosstier`); status INFERRED 0.9 → **OBSERVED**. Note says the cause is not attributable at T1. An error-only response (no selection) → UNKNOWN. **Not done:** the consumers still word this as "downgrade" (rule title, CBOM posture, demo script) — P1. | Done (T-053), wording P1 |
| PQ-4 | INVALID_KE_PAYLOAD → UNAUTH_DOWNGRADE_PRESSURE (INFERRED), severity by resulting group vs floor | ADAPT | The notify→retry *sequence* is OBSERVED (plaintext header + notify 17); intent is not attributable (§2.3). A stronger OBSERVED indicator: two different responses (a selection and an error) to the same request. The retry can only use groups the initiator already offered, so the root-cause finding is a below-floor offer. No capture in the testbed contains notify 17 (scanned 2026-09-17). | Planned P2 (needs capture) |
| PQ-5 | In-path proposal stripping is not caught by IKE_AUTH; wire is blind | REJECT | The initiator's AUTH covers RealMessage1 (§2.2), so stripping breaks authentication. The realistic vector is error injection (PQ-4), which yields a self-consistent, authenticated retry. | Rejected |
| PQ-6 | ML-KEM-768 1184 B / 1088 B asymmetry is an unforgeable wire fingerprint | ADAPT | The sizes are ML-KEM parameters *(FIPS 203, not re-fetched)*, but under RFC 9370 those values travel in encrypted IKE_INTERMEDIATE (§2.4): only message lengths are visible, i.e. an INFERRED size channel, as EXP-04 measured. Corroboration, never proof. | Existing (EXP-04); P3 to use as corroboration |

### 3.2 PFS and key-exchange sizes

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| PFS-1 | CREATE_CHILD_SA is encrypted at T1; reading its KE is invalid | ADOPT | Already true: `extract_pfs` uses IP length only. | Existing |
| PFS-2 | At T1, infer PFS from ESP SPI shifts | REJECT | A new SPI shows a rekey happened, not whether a KE was included (§2.5). | Rejected |
| PFS-3 | Use the KE payload's explicit length; delete the length-gap heuristic | REJECT at T1 | The KE length field is inside `SK {}` at T1. The length gap is the only T1 signal, and it is measured (EXP-03/07). Explicit lengths apply only with keys (T3). | Rejected (T1) |
| PFS-4 | RFC 5903 sizes are x-only (ECP-256 = 32 B) | REJECT | §2.1. | Rejected |
| PFS-5 | Separate IKE SA rekeys from Child SA rekeys via N(REKEY_SA) | ADAPT | N(REKEY_SA) is encrypted. An IKE SA rekey shows up afterwards as a new SPI pair in plaintext IKE headers, and always carries a KE (§2.5) — today it would read as PFS = true. | Planned P2 |
| — | T-051's 255 B / 280 B thresholds for Curve25519 / ECP | REJECT (T-052) | No capture calibrates them: every PFS capture is MODP-2048 (PFS-off requests 236–240 B, PFS-on 508–512 B). A 255 B cut is 15–19 B above measured PFS-off, inside one traffic selector's variance. **Now:** the 400 B rule applies only to MODP groups; other known groups → UNKNOWN ("threshold uncalibrated"); unknown group → 400 B rule with an explicit caveat. | Done (T-053) |

### 3.3 Session state and correlation

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| SES-1 | UNAUTHENTICATED → AUTHENTICATED → ESTABLISHED | ADAPT | A passive observer cannot verify AUTH, and AUTHENTICATION_FAILED is encrypted. Name states by what was seen (e.g. init-completed / auth-exchange-seen / traffic-correlated). No current consumer needs it. | Planned P3 |
| SES-2 | LRU quarantine, 10,000 sessions, 30 s TTL, against state-exhaustion DoS | DEFER | TunnelScope is offline by default (`build/03-USAGE-AND-OPERATIONS-PLAN.md` §2); `cli.py` has no live capture. If a live mode is built: bound state, use capture time not wall time, count evictions, and do not use 30 s (EAP rounds, IKE_INTERMEDIATE chains and retransmissions run longer). | Deferred |
| SES-3 | Quarantined sessions get zero posture weight | REJECT as stated | A responder's plaintext selection is a fact about *responder policy* whether or not auth completes — it is what an active probe measures. Distinguish responder-capability findings from established-tunnel findings instead of zeroing them. | Planned P2 |
| SES-4 | ESTABLISHED requires bidirectional ESP on the negotiated SPIs | REJECT mechanism | Child SA SPIs are inside encrypted payloads; SA↔ESP linkage is address + time only (INFERRED). T-051/T-053 implement that linkage (§4.1). | Done (linkage) |
| SES-5 | Flood of unauthenticated expiring sessions → POSSIBLE_INJECTION | DEFER | Needs live or long captures; no data. | Deferred |
| SES-6 | Key by (iSPI, src IP, src port) pre-response; iSPI alone collides under CGNAT | REJECT | The port changes to 4500 mid-SA (§2.6). iSPI is 8 random octets, so accidental collision is negligible; deliberate reuse is an injection question, not a keying one. Keying by iSPI stays. | Existing |
| SES-7 | Deduplicate retransmits by message ID and direction | ADAPT | Match (SPIs, message ID, flags) **and** identical bytes; never merge IKE fragments (RFC 7383), which share a message ID. Today a retransmitted CREATE_CHILD_SA request would add a ~0 s interval to rekey cadence. | Planned P2 |

### 3.4 CVE-2026-78135 detector

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| CVE-1 | Bug = CREATE_CHILD_SA arriving while IKE_AUTH is in flight | REJECT description | Repo evidence (EXP-09, strongSwan `task_manager_v2.c` `reject_request()`) is a CREATE_CHILD_SA accepted *before IKE_AUTH completes*; the live capture has no IKE_AUTH (§2.8). | Rejected |
| CVE-2 | Fire only if an IKE_AUTH response appears later; else "SUSPECT 0.50" | REJECT | Would miss the real exploit (§2.8). SUSPECT is not a status in `record.py`. The frame-ordered, vantage-guarded detector stays. | Existing |
| CVE-2b | (residual risk behind CVE-2) capture loss of the whole IKE_AUTH exchange | ADAPT | Guard by message-ID accounting: a CREATE_CHILD_SA request whose message ID directly follows the last pre-auth exchange from the same originator proves no IKE_AUTH was sent in between → OBSERVED; a gap → UNKNOWN. Must be run against every capture before shipping. | *Done (T-055)*: `_msgid_gap_before_child`, 4 tests; 0 finding changes on the other 130 captures |
| CVE-2c | (panel missed) attempt vs acceptance | ADAPT | The responder's reply is encrypted, so whether the Child SA was *accepted* is NOT_OBSERVABLE at T1. The live lab responder actually rejected (TS_UNACCEPT, EXP-09). The rule text "matches CVE-2026-78135" should say "pre-auth CREATE_CHILD_SA attempt (CVE-2026-78135 pattern); acceptance requires T2". | Planned P1 (wording) |
| CVE-3 | Composite keying / dedup | — | See SES-6, SES-7. | — |
| CVE-4 | Published 11 Sep 2026, fixed in 6.1.0 on 7 Sep 2026 | UNVERIFIED | Not confirmed in T-052/T-053. The repo relies on the 6.1.0 source trace (EXP-09), not on these dates. Do not quote the dates to the jury. | — |

### 3.5 IKEv1, AH, ESP-NULL, anti-replay

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| MAN-1 | IKEv1 Main Mode lifetimes are cleartext → R12 satisfied at T1 | ADAPT | Phase 1 SA attributes are cleartext; Phase 2 (Quick Mode, the IPsec SA) is encrypted *(RFC 2409, not re-fetched)* — R12 is only partly met. T-051 added IKEv1 **version detection** only, noting RFC 9395 (*"IKEv1 has been moved to Historic status"*). No IKEv1 capture exists; the unit test is header-level. | Detection done; lifetimes P2 (needs capture) |
| MAN-2 | Aggressive Mode leaks identity and PSK hash → critical | ADAPT | Severity depends on the auth method: with PSK the exposed hash enables offline guessing; with signatures it is an identity disclosure. | Planned P2 (needs capture) |
| MAN-3 | AH: no confidentiality, inner 5-tuple OBSERVED | ADOPT principle | Not ingested today (tshark `esp` filter only). The T-051 draft's claim that mapping ENCR_NULL (id 11) addresses this was wrong: that table describes the IKE SA; ESP's cipher is negotiated inside encrypted IKE_AUTH. | Planned P2 (needs capture) |
| MAN-4 | ESP-NULL via inner-IP alignment + entropy < 3.5 bits/byte | ADAPT | Use RFC 5879: self-describing padding bytes, plausible next-header, ICV lengths tried shortest first; add an inner IPv4 header-checksum check. Entropy is secondary (encrypted inner payloads such as TLS are high-entropy). | Planned P2 (needs capture) |
| MAN-5 | ΔSeq = Seq_max − Seq_obs lower-bounds the replay window | REJECT | Receiver drops are invisible at T1 and tap-side reordering is not receiver-side reordering. ΔSeq measures the window the network *needs*, not the one configured; the configured window is a T2 fact. | Rejected; P3: report as a MEASURED requirement |

### 3.6 Ingestion, scale, encapsulation

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| ING-1/2 | Pure Python 2–5 Gbps; tshark collapses at 45 kpps; 10 GbE = 14.8 Mpps; XDP needed | REJECT the numbers | Measured once (2026-09-17, development laptop): `build_records` on the largest local capture, 55,042 packets, took 0.92 s ≈ 60,000 packets/s end to end, offline. One capture is not a benchmark. 14.8 Mpps is minimum-size frames at 10 GbE. XDP/eBPF contradicts ADR-001 (tshark ingest) and is out of scope. Say: "offline analyzer; ~60 kpps measured on one capture". | Rejected; P3 benchmark |
| ING-3 | Two-plane split: stateful IKE, 24-byte ESP fast path | DEFER | Sound for a live mode; ESP ingest already extracts header fields only. | Deferred |
| ING-4 | Keep ESP only in 5 s windows around anomalies | REJECT | Metadata leakage (EXP-05) and rekey cadence (EXP-12) need full sequences. Per-SPI aggregates are the memory-safe option if ever needed. | Rejected |
| ING-5 | TCP encapsulation was wrongly dismissed | ADAPT | RFC 9329 (obsoletes 8229): streams begin with the 6-byte magic *"IKETCP"*, and implementations *"MUST support TCP encapsulation on TCP port 4500"*. Today such traffic is silently missed. Minimum: detect it and report a coverage gap. | Planned P2 |
| ING-6 | NAT-T keepalives, IPv6 extension headers, EAP multi-round unaddressed | ADAPT | Static read (T-052, not yet tested): `esp_content = ip.len − 28` assumes native ESP over IPv4 — UDP-encapsulated ESP adds 8 B, IPv6 has no `ip.*` fields. Multi-round EAP only adds IKE_AUTH exchanges, which current extractors tolerate. | *Done (T-057)*: confirmed on 4 real captures (UDP-encap CBC lost CBC; IPv6 had no addresses and misread success as failure); offsets fixed, `testbed/captures/encap/`, `tests/test_encap.py` |

### 3.7 Statistics, standards, confidence

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| STD-1 | "Hanley-McNeil" 3/N bound | ADAPT | §2.9: citation corrected, exact bound, per-detector n, non-independence. | Done (this doc); P1 to apply to jury material |
| STD-2 | CBOM native only in CycloneDX 1.7; dual-target 1.6/1.7 | REJECT premise | CycloneDX 1.6 (released 09 April 2024) introduced CBOM; 1.7 was released 21 October 2025. Export is `specVersion 1.6` (`pq/cbom.py`). Add 1.7 only with official-schema validation. | P3 |
| STD-3/4 | Anchor in DST-NQM 2026; baselines DISA STIG, NIST SP 800-52 | ADAPT | `rules/dst-nqm-pq.yaml` cites the DST Task Force report (Feb 2026); its URL returned HTTP 200 (1.98 MB) on 2026-09-17, contents not re-read here. NIST SP 800-52 is TLS guidance *(not re-fetched)*; the IPsec guide is SP 800-77 Rev. 1. Current baselines: RFC 8247, DISA VPN SRG v2r6, DST-NQM, CVE-WATCH. Do not add SP 800-52. | Existing |
| STD-5 | Dossier tier model | REJECT | §2.7. | Rejected |
| STD-6 | New verdicts with numeric confidences (0.99, SUSPECT 0.50, …) | REJECT | Uncalibrated constants dressed as probabilities. T-053 removed T-051's 0.95/0.9 PQ constants. Older constants remain (sieve 0.9/0.95, PFS 0.9, failure 0.4) with no calibration study. | P2: document provenance or drop |

### 3.8 Refactor and process

| # | Dossier claim | Verdict | Evidence and corrected rule | Status |
|---|---|---|---|---|
| REF-1 | Split a "~1500-line" `extract.py` into sessions/pq/pfs/race/ah modules | REJECT | It was 392 lines; the real defects were in ingest and ESP attribution. Split by layer (ingest → correlation → pure detectors) only when a module actually grows. | Rejected |
| REF-2 | Keep 52 unit / 69 E2E green | ADOPT, strengthened | Green suites did not catch T-051's regressions: E2E checks selected attributes only. The merge gate is now a full-findings differential against `main` (§4.2). | Done manually; P1 script + CI |
| REF-3 | "Anti-hallucination" narrative | ADOPT with a condition | Only as strong as the remaining guesses: PFS on an unknown group and uncalibrated confidences (§3.2, §3.7) weaken it until fixed. | — |

---

## 4. What changed in the code (T-051 + T-053)

### 4.1 Changes
| Change | Files | Test |
|---|---|---|
| Per-SA IKE crypto: `ike_sa_crypto(pcap, ispi)` reads each SA's own IKE_SA_INIT response (the pcap's first response was used for every SA before) | `ingest/tshark.py`, `evidence/extract.py` | `test_ike_crypto_is_per_sa` (real pcap) |
| Several IKE SAs between one host pair: an SA owns the SPIs carrying traffic between its first IKE message and the next SA's | `extract.py` `group_sas` | `test_esp_credited_to_the_sa_that_carried_it` (real pcap) |
| ESP-only capture: one record per host pair **across SPI changes** (a rekey is the same tunnel); directional SPIs in capture order | `extract.py` `group_sas`, `_set_child_spis` | `test_esp_only_rekey_stays_one_tunnel`, `test_esp_only_tunnel_directional_spis` |
| PQ selection read from the responder's proposal (OBSERVED); multi-proposal offers; NONE; error-only responses → UNKNOWN | `extract.py` `extract_pq_addke`, `_addke_ids`; `tshark.KE_METHOD[0] = NONE` | 6 tests incl. `test_pq_downgrade_capture_selection_is_observed` (real pcap) |
| PFS 400 B rule restricted to MODP; other groups UNKNOWN; caveat when the group is not visible | `extract.py` `extract_pfs` | `test_pfs_modp_rule`, `test_pfs_uncalibrated_group_is_unknown` |
| IKEv1 version detection (exchange types 2, 4, 5, 32, 33), RFC 9395 note | `tshark.EXCHANGE`, `extract_ike_meta`, `extract_ike_crypto` | `test_ikev1_legacy_detection` (header-level) |
| Removed: T-051's proposal "unflattening" (transform IDs came back empty on every real pcap) and the test that asserted a note it had written itself | `tshark.py`, `tests/test_extract.py` | — |

The 17 new tests were run against the pre-fix T-051 commit: 11 fail there. The other 6 pass there
too: 3 pin T-051's genuine fixes (per-SA crypto, ESP attribution, directional SPIs) and 3 pin
behaviour that was already correct (MODP PFS rule, NONE-only offer).

### 4.2 Merge gate: full differential against `main`
All 130 pcaps, every finding. Record counts: unchanged everywhere. Status/value/confidence
changes occur in exactly 5 captures, all intended:

| Capture | Change | Why it is correct |
|---|---|---|
| `cs-aes256gcm16-a7.pcap`, `cs-transport-aes256gcm16-a7.pcap` | IKE crypto UNKNOWN → OBSERVED (MODP-2048, AES-CBC-256, HMAC-SHA2-256-128) on the SAs that negotiated; ESP moved to the last SA | The first IKE_SA_INIT response in these pcaps is NO_PROPOSAL_CHOSEN, which used to blank every SA; ESP starts only after the last negotiation |
| `fail-proposal-mismatch.pcap`, `fail-ts-mismatch.pcap` | Failed SAs: ESP 132 → 0, outcome `success` → `post-auth-outcome-ambiguous` (0.4) | The ESP starts after a later, working negotiation; `main` credited it to the failed ones |
| `pq-downgrade.pcap` | `offered-but-not-used` INFERRED 0.9 → OBSERVED 1.0 | The responder's SA contains no additional key exchange — plaintext |

Remaining differences are note text only (new PQ wording, PFS caveat, and notes that follow the
ESP move). T-052's two stress cases: the ESP-only rekey is one record again (timing leakage
1.969 bits, as on `main`); a failed SA negotiated during a live tunnel between the same hosts is
still credited with that tunnel's ESP on both branches — a known limit (§6).

---

## 5. Remaining work

### P1 — before relying on these outputs in front of a jury
1. ✅ *Done (T-054: `build/findings_diff.py`, `build/findings-allow.txt`, CI step).* **Differential script + CI.** Commit the §4.2 differential as a script and run it in CI against
   the merge base. *Accept:* a PR that changes any finding's status/value/confidence on any pcap
   fails unless listed in an allow-file.
2. ✅ *Done (T-055).* **CVE message-ID guard (CVE-2b).** *Accept:* fires on the synthetic and live positives; UNKNOWN
   on a copy of a benign capture with its IKE_AUTH frames deleted; 0 new detections on all other
   captures.
3. **Attempt-vs-acceptance and "downgrade" wording (CVE-2c, PQ-3).** Rule text, CBOM posture label,
   `build/sih/DEMO-SCRIPT.md`, `PITCH-DECK.md`, `JURY-QA.md`. *Accept:* no jury-facing text claims
   a CVE exploitation or an attack where only an attempt or a policy selection is observed.
4. ✅ *Done (T-057).* **Encapsulation length offsets (ING-6).** Build a UDP-encapsulated ESP capture and an IPv6
   capture. *Accept:* `esp_content` and the cipher sieve are correct on both, or the record says
   UNKNOWN.
5. **Statistics wording (STD-1).** Replace any "0 false positives" in README / `build/sih/*` /
   `experiments/RESULTS.md` with the §2.9 form.

### P2 — next capability work (each needs a real capture first)
6. INVALID_KE_PAYLOAD sequence + conflicting-response indicator (PQ-4).
7. IKE SA rekey detection so PFS ignores IKE SA rekeys (PFS-5); name exchange 44 (IKE_FOLLOWUP_KE).
8. Retransmit dedup that preserves IKE fragments (SES-7).
9. Responder-capability vs tunnel-posture tagging of findings (SES-3).
10. RFC 9329 TCP-encapsulation detection as a reported coverage gap (ING-5).
11. IKEv1 phase-1 lifetimes and Aggressive Mode severity; AH; ESP-NULL per RFC 5879 (MAN-1–4).
12. Confidence constants: document where each comes from, or remove it (STD-6).
13. PFS calibration for Curve25519 / ECP groups from real rekey captures on ≥2 implementations.

### P3 — only if the scope grows
Live mode (then SES-2, ING-3); CycloneDX 1.7 export with schema validation; ML-KEM size channel as
corroboration (PQ-6); replay-window requirement as a MEASURED finding (MAN-5); SES-1 state names;
a throughput benchmark over a stated corpus.

---

## 6. Known limitations of the merged code
- **ESP attribution is address + time.** An SA negotiated while an older tunnel between the same
  hosts is still carrying traffic is credited with that traffic (T-052 stress case A2).
- **ESP-only records treat every SPI change between two hosts as a rekey.** Genuinely parallel
  tunnels between the same pair are merged (T-053 decision; overlapping-SPI splitting was not
  implemented because a rekey's drain period also overlaps and no threshold is measured).
- **PFS with an unknown IKE group uses the MODP rule**; a PFS rekey with a smaller group would read
  as PFS-off. The finding's note says so.
- **The IKE SA's group is only a proxy** for the Child SA's PFS group, which is negotiated inside
  encrypted payloads.
- **IKEv1 support is detection only**, with no IKEv1 capture in the testbed.
- **Retries share one record.** After an INVALID_KE_PAYLOAD or COOKIE retry on the same initiator
  SPI, PQ selection uses the last selecting response but `ike_sa_crypto` still returns the first
  responder message for that SPI. No testbed capture contains such a retry (§3.1 PQ-4).
- **Per-tunnel auth method and tunnel/transport mode stay NOT_OBSERVABLE** at T0/T1 (EXP-08, EXP-11).

---

## 7. Review history
- **T-051** (commit `75e4a5e`): first adjudication and implementation. Kept: per-SA crypto, ESP
  attribution across several SAs, NONE handling, IKEv1 detection.
- **T-052** (review): suites confirmed green, but a full differential and three stress cases found:
  ESP-only rekeys split into one-way records (timing leakage 1.97 → 0.0–0.58 bits); proposal
  transform IDs empty on real pcaps; PQ still inferred when the selection is plaintext, with a
  false "possible downgrade" on two-proposal offers; PFS cutoffs with no capture behind them; a
  test asserting its own note; an RFC 5903 "quote" that was not RFC text; unadjudicated dossier
  clusters.
- **T-053** (this revision): each of those fixed or removed (§4), document rewritten from verified
  sources, merged after the §4.2 differential.
