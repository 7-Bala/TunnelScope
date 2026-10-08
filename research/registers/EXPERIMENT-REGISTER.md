# Experiment Register

Every unresolved empirical question from Discover/Define, converted into a runnable experiment.
This register is the DEVELOP/DELIVER entry point — no more literature search should be spent on
these; they require the testbed.

---

### EXP-01 — ESP cipher-suite family sieve (validates F-04)
- **Hypothesis:** the IV/ICV/alignment constraint sieve narrows the candidate ESP cipher-suite set
  to ≤2 members (AES-GCM vs ChaCha20-Poly1305 ambiguity expected) using only observed ESP frame
  lengths, across strongSwan, Libreswan, and the third-party Wireshark test corpus.
- **Variables:** IV independent = cipher suite (AES-CBC-SHA1/SHA256, AES-CTR, AES-GCM-16,
  ChaCha20-Poly1305). Dependent = candidate-set size after N packets.
- **Controlled factors:** fixed inner traffic mix, fixed MTU, no NAT-T for the baseline run (NAT-T
  as a separate arm).
- **Ground truth:** strongSwan `swanctl --list-sas` / vici (T2).
- **Design:** one-factor-at-a-time microscope (05-DISCOVER §5).
- **Expected observation:** candidate set → singleton or {GCM, ChaCha20} pair within ~50–200 packets.
- **Falsification:** if candidate set fails to narrow below 4+ suites even at 1000 packets, F-04 is
  too weak to be a headline finding — demote to a supporting signal only.
- **Success criterion:** ≥90% of runs narrow to ≤2 candidates by packet 200.

### EXP-02 — AES-128 vs AES-256 negative result (validates F-05, doubles as contamination detector)
- **Hypothesis:** no observable ESP-side feature (length, timing, IV structure) distinguishes
  AES-128 from AES-256 at T0/T1.
- **Design:** identical everything else; only ESP key length varies. Attempt every classifier used
  elsewhere in the project against this pair.
- **Falsification:** if any classifier scores meaningfully above chance, the corpus has a leakage
  bug (per-file artifact) — this is the mandatory dataset-integrity check (05-DISCOVER §6), not
  optional.
- **Success criterion:** near-chance accuracy (within CI of 50%) confirms both F-05 and corpus
  cleanliness simultaneously.

### EXP-03 — PFS inference from CREATE_CHILD_SA length (tests A10 hypothesis)
- **Hypothesis:** a `CREATE_CHILD_SA` rekey message with PFS enabled is distinguishable from one
  without, by encrypted-payload length, because of the extra `KEi/KEr` payload.
- **Ground truth:** T2 (`rekey_time`, PFS on/off in swanctl.conf).
- **Falsification:** if length distributions overlap fully (encryption padding/alignment masks the
  KE payload), A10 downgrades from Inferable to Not-recoverable at T0/T1 — a real, reportable limit.

### EXP-04 — PQ key-exchange detection by length asymmetry, no dissector (tests PQ-6)
- **Hypothesis:** ML-KEM-768/512 negotiations are separable from every classical DH/ECDH group by
  initiator/responder KE-payload length asymmetry alone.
- **Design:** strongSwan 6 `x25519-ke1_mlkem768` vs `curve25519` baseline; Suricata rule on
  `ike.key_exchange_payload_length`.
- **Priority:** **highest in the register** — cheapest to run, highest evidentiary value, tests the
  strongest opportunity found in Discover (07-DISCOVER, 08-DISCOVER).
- **Success criterion:** 100% separation on payload length alone (this is a hard, structural claim,
  not a statistical one — it should either clearly hold or clearly fail).

### EXP-05 — Metadata-leakage delta from TFC padding / IP-TFS (tests OQ-17)
- **Hypothesis:** enabling `tfc_padding=mtu` or `mode=iptfs` measurably reduces mutual information
  between ESP length/timing features and inner traffic class, versus `tfc_padding=0`.
- **Ground truth:** T3 (keys available, so true inner traffic is known for MI computation).
- **Design:** identical concurrent multi-app traffic mix; only the padding/mode setting varies.
- **Success criterion:** any statistically significant MI reduction is a headline, previously
  unpublished result regardless of magnitude.
- **Falsification:** if MI is unchanged, either the strongSwan implementation doesn't behave as
  documented, or padding must be combined with rate-shaping to matter — both are reportable findings.

### EXP-06 — Failure-mode diagnosis from structural signature (tests CS-02)
- **Hypothesis:** the five failure modes in PE-02 (proposal mismatch, TS mismatch, PFS mismatch,
  lifetime mismatch/rekey race, auth failure) produce distinguishable structural signatures
  (retransmission count/timing, message sequence, SPI churn) even though payloads are encrypted.
- **Ground truth:** deliberately misconfigured testbed pairs, one failure mode at a time.
- **Success criterion:** macro-F1 ≥ 0.8 across the five classes on held-out configuration seeds
  (leave-one-seed-out, per DEC-009).

### EXP-07 — Cross-implementation generalization (tests H-D, A-05)
- **Hypothesis:** EXP-01/EXP-03/EXP-04 findings hold on Libreswan, not only strongSwan.
- **Design:** repeat EXP-01/03/04 with Libreswan as the second implementation.
- **Falsification:** any result that flips between implementations demotes the corresponding finding
  from FACT to implementation-dependent STRONG evidence — must be stated as such in the final report.

### EXP-08 — Dataset leakage audit (operationalizes DEC-009)
- **Design:** for every model trained in EXP-03/04/06, run three splits — random (baseline, expected
  to over-perform), session-level, configuration-level — and report the gap. A large
  random-vs-session gap is the leakage signature identified in E-02.
- **Success criterion:** session-level and configuration-level performance must be the numbers
  reported in the final submission; random-split numbers may only appear as a labelled contrast
  demonstrating the leakage check was performed.

---

**Sequencing note:** EXP-04 first (cheapest, highest value, needs only strongSwan 6 + Suricata,
no custom tooling). EXP-01/02 next (they share a testbed setup and EXP-02 is a mandatory gate on
everything downstream). EXP-03, 05, 06 require the fuller testbed and traffic generators. EXP-07/08
are generalization passes applied after the primary results exist.

---

## Round 1 status update (2026-09-10)

| Experiment | Status | Result | Details |
|---|---|---|---|
| EXP-01 | **DONE — hypothesis PARTIALLY FALSIFIED** | Sieve converges instantly (packet 1, not 50-200 as predicted) but to a 5-6 member ambiguity class, not <=2. Falsification criterion in this file's own text ("if candidate set fails to narrow below 4+ suites... demote to a supporting signal only") was MET. One-directional containment property discovered: AEAD/CTR/stream evidence excludes CBC; CBC evidence cannot exclude AEAD/CTR/stream. | `experiments/exp01-cipher-sieve/` |
| EXP-02 | **DONE — PASS (critical gate cleared)** | Exact ESP-length sets identical between 128/256-bit key pairs (both GCM and CBC families); best-possible classifier at or below chance. No leakage. | `experiments/exp02-negative-control/` |
| EXP-03 | **DONE — CONFIRMED** | 256-byte gap between PFS-on/off CREATE_CHILD_SA messages, reproduced identically across 2 independent rekey events. | `experiments/exp03-pfs-signature/` |
| EXP-04 | **DONE — CONFIRMED, exceeded hypothesis** | 4 independent deterministic signals found; strongest (IKE_INTERMEDIATE message presence) needs no length arithmetic at all, just the plaintext exchange-type field. Original length-asymmetry hypothesis confirmed but complicated by unanticipated IKE fragmentation of the PQ exchange. | `experiments/exp04-pq-length-asymmetry/` |
| EXP-05 | Not started | — | Needs full traffic-mix testbed (TFC padding / IP-TFS) |
| EXP-06 | Not started | — | Needs deliberate-misconfiguration testbed arms |
| EXP-07 | Not started | — | Needs Libreswan image; prioritized next per RESULTS.md item 4 |
| EXP-08 | Not started | — | Applies to whichever ML models exist after EXP-06 |

Full writeup with honesty-requirement sections: `experiments/RESULTS.md`.

### EXP-06 Round 1 (2026-09-10): INCONCLUSIVE — testbed design flaw found, not a hypothesis result
Both deliberate misconfigurations (proposal-mismatch, TS-mismatch) correctly triggered their
intended failure notify. However, all testbed arms share the SAME traffic selector (the two host
addresses), so a leftover successful SA from an earlier arm (`cs-aes256gcm16`) shared the XFRM
policy with the failure arms during capture, contaminating the capture window with unrelated
traffic. A secondary confound (differing IKE identity string lengths across arms) was also found.
Reported honestly rather than forced into a conclusion. Full writeup, root cause, and the concrete
generator fix needed for round 2: `experiments/exp06-failure-diagnosis/RESULT.md`.

---

## EXP-06 Round 2 — PRE-REGISTRATION (written 2026-09-12, BEFORE any round-2 capture)

**Fixes for round 1's design flaw** (`experiments/exp06-failure-diagnosis/RESULT.md`):
1. **Per-arm isolation:** every arm gets its own alias address pair (alice `10.10.1.10k`, bob
   `10.10.2.10k`) used both as IKE endpoints and as traffic selectors. No two arms share an XFRM
   policy, and responder config selection is unambiguous by address.
2. **Equal-length IKE identities** (`a-f0k` / `b-f0k`, 5 chars each) remove the ID-length confound
   inside encrypted IKE_AUTH.
3. **All SAs are terminated** before every capture, and each capture is filtered to that arm's alias
   hosts only.
4. **5 repetitions per arm**, so evaluation can use a session-level (leave-one-repetition-out) split.

**Arms (ground truth = the designed misconfiguration, confirmed by charon's own log notify, T2):**

| Arm | Misconfiguration | Expected failure |
|---|---|---|
| F0 | none (control) | success |
| F1 | IKE proposal mismatch (bob only accepts aes128-sha256-ecp256) | NO_PROPOSAL_CHOSEN in IKE_SA_INIT |
| F2 | Child (ESP) proposal mismatch (alice aes256gcm16, bob aes128-sha256) | NO_PROPOSAL_CHOSEN in IKE_AUTH |
| F3 | Traffic-selector mismatch (bob only accepts 10.10.1.199/32) | TS_UNACCEPTABLE in IKE_AUTH |
| F4 | PSK mismatch | AUTHENTICATION_FAILED in IKE_AUTH |
| F5 | PFS mismatch (alice esp …-modp2048, bob none) | initial child OK; failure at CREATE_CHILD_SA rekey |
| F6 | Peer unreachable (no host at the remote address) | IKE_SA_INIT retransmissions, no response |

**Predictions, derived from protocol structure before seeing data (T0/T1 = passive, no keys):**

| # | Prediction | Reasoning | Falsified if |
|---|---|---|---|
| P-a | **F1 separable, deterministically** | Its failure notify sits in the **plaintext** IKE_SA_INIT response; no IKE_AUTH follows | F1 confused with any other arm |
| P-b | **F6 separable, deterministically** | Only initiator IKE_SA_INIT retransmissions, zero responses | F6 confused |
| P-c | **F4 separable from F2/F3 by IKE_AUTH response size** | An AUTH_FAILED response carries only a notify (no IDr/AUTH/SA/TS), so it is much smaller | Response sizes overlap |
| P-d | **F0 separable from F2/F3** | A success response carries SA+TSi+TSr, so it is larger, and ESP follows | Overlap |
| P-e | **F2 vs F3 NOT separable at T0/T1** | Both responses are IDr+AUTH+one 8-byte data-less notify, identical encrypted sizes given equal ID lengths. Separable only at T2 (logs) | A passive feature separates F2 from F3 (would point to an unknown channel → investigate) |
| P-f | **F5 separable only at rekey time** | Looks like F0 until a CREATE_CHILD_SA request carrying a KE payload gets a short response and no new ESP SPI | F5 indistinguishable from F0 even after rekey |

**Method comparison (feeds the AI Necessity Matrix, CS-02):** a hand-written deterministic rule set
vs a decision-tree classifier on the same structural features, both evaluated leave-one-repetition-out.
If the rules match the tree's macro-F1, **CS-02 does not need ML** — and that will be reported as such.

---

## EXP-05 — PRE-REGISTRATION (written 2026-09-12, BEFORE any EXP-05 capture)

**Question (CS-01 reframing):** how much can a passive T0 observer learn about the *class of traffic*
inside an ESP tunnel — and how much does padding reduce it? The classifier is used as a
**measuring instrument for adversary capability**, not as a truth oracle.

**Setup:** strongSwan 6.1.0 PQ pair; per-arm alias addresses; capture at the keyless router; AES-GCM-256
tunnel mode. Traffic from one stdlib traffic generator (`testbed/scripts/tgen.py`), seeded per session.
- Classes (5): `voip` (bidirectional 172-B UDP every 20 ms), `web` (HTTP-like request/response,
  lognormal object sizes, exponential think time), `bulk` (one saturating TCP stream),
  `interactive` (1–50-byte keystrokes with exponential gaps, echoed), `video` (250 KB segment each 1 s).
- Arms: **base** (no padding) · **tfc** (`tfc_padding = mtu`) · **mux** (base config, two classes
  concurrently — the G-12 multiplexing case) · ~~iptfs~~ **dropped: kernel lacks CONFIG_XFRM_IPTFS**
  (testbed/NOTES.md #13).
- 4 repetitions × 5 classes × {base, tfc}, 20 s per session; mux: 3 class pairs × 4 repetitions.

**Measures:** windows of 2 s; features = per-direction packet counts, size statistics and size
histogram, inter-arrival statistics, byte rates.
- Adversary capability: Random Forest macro-F1, **leave-one-repetition-out** (session-level split, DEC-009).
- Bayes-error lower bound from leave-one-repetition-out 1-NN error (Cover–Hart bound, Cherubin PETS'17 approach).
- Mutual information, bits per packet: I(class; size bin) and I(class; inter-arrival bin), Miller–Madow corrected. Maximum log2(5) = 2.32 bits.
- **Null control:** permuted labels must score ≈ chance (0.20); otherwise the pipeline leaks (same role as EXP-02).
- Cost: on-wire bytes, tfc ÷ base.

**Predictions:**

| # | Prediction | Falsified if |
|---|---|---|
| P5-1 | **base leaks heavily:** RF macro-F1 > 0.8; size MI > 1 bit/packet | F1 < 0.6 or size MI < 0.5 bit |
| P5-2 | **tfc removes the size channel:** size MI ≈ 0 (all ESP packets one length) | size MI > 0.1 bit under tfc |
| P5-3 | **…but tfc does NOT remove class leakage:** timing/volume still give F1 well above chance (> 0.5) | tfc F1 ≤ 0.35 (then size was the whole story) |
| P5-4 | **multiplexing degrades the adversary:** single-class model's hit rate on mux windows (top-1 ∈ the two present classes; chance 0.4) is below base single-class accuracy | mux hit rate ≥ base accuracy |
| P5-5 | **the metric is stable:** fold-to-fold std of F1 < 0.1, and the permutation null ≈ 0.20 | std ≥ 0.1, or null > 0.3 |

**Why this matters for DEVELOP:** if P5-1/P5-3 hold, a leakage *measurement* tells an operator something
a config check cannot ("your padding hides sizes, but a passive observer still identifies your traffic
N% of the time"). That would be the concrete justification for an ML-based component (CS-01). If the
metric proves unstable (P5-5 fails), CS-01 doesn't earn its place.

### EXP-06 Round 2 — RESULT (2026-09-12): DONE — all six pre-registered predictions held
35 captures (7 arms × 5 reps), all T2-confirmed. Rules written from protocol arithmetic before any
data = decision tree: macro-F1 1.000 with F2/F3 merged, 0.809 with them separate (the ceiling, since
F2 and F3 have identical feature vectors, as predicted by P-e). The notify-only response is exactly
112 bytes, as derived beforehand. **CS-02 needs no ML.** `experiments/exp06-failure-diagnosis/RESULT_R2.md`.

---

## EXP-07 — PRE-REGISTRATION (written 2026-09-12, BEFORE any EXP-07 capture)

**Question:** which of our structural findings are *protocol facts* and which are *strongSwan
behaviour*? Re-run EXP-01/02/03/04 on a second implementation — **Libreswan 5.4** (Fedora rawhide
`libreswan-5.4-5.fc46`, NSS 3.127, image pinned by digest; `testbed/images/libreswan/`), Libreswan to
Libreswan through the same keyless router. Arms: `testbed/configs/exp07/arms.json`.

**Already observed while setting up (not yet a measurement, recorded here so it can't be quietly
absorbed):** Libreswan's ML-KEM IKE_INTERMEDIATE response arrived *"reassembled from 3 fragments"*;
strongSwan's initiator split its KE message into 2 and its responder sent 1. Libreswan also negotiates
ESN by default (strongSwan: none) — this doesn't change wire lengths.

**Predictions** (from protocol structure: which quantities the RFCs fix vs leave to the implementation):

| # | Prediction | Reasoning | Falsified if |
|---|---|---|---|
| P7-1 | **EXP-01 sieve ambiguity classes identical** on Libreswan: GCM/CTR/ChaCha → the same 5-member class; CBC → the same 6-member class; the true family never eliminated | IV/ICV/alignment are fixed by RFCs 3602/4106/3686/7634, not by implementations | A different class, or a false elimination |
| P7-2 | **EXP-02 holds:** AES-128 vs AES-256 ESP length sets identical; classifier ≤ chance | Key length never reaches the wire | Any separation |
| P7-3 | **EXP-03 holds in direction, not magnitude:** PFS-on CREATE_CHILD_SA is larger than PFS-off by at least the MODP-2048 KE payload (≥ 264 B before encryption); the exact byte gap may differ from strongSwan's 256 B | KE size is fixed by the group; the other payloads and padding are implementation choices | PFS-on not larger, or overlap |
| P7-4a | **EXP-04 Signal 3 holds:** IKE_INTERMEDIATE present iff ADDKE negotiated | Exchange type is fixed by RFC 9242 | Present in classical or absent in PQ |
| P7-4b | **EXP-04 Signal 2 holds in direction:** IKE_SA_INIT grows when ADDKE is proposed; the byte delta may differ from +16 | An extra transform substructure must be encoded | No growth |
| P7-4c | **EXP-04 Signal 1 is IMPLEMENTATION-DEPENDENT:** whether INTERMEDIATE_EXCHANGE_SUPPORTED appears in the *classical* arm depends on Libreswan's policy (our classical arm sets `intermediate=yes`) | RFC 9242 makes it a capability notice, not a commitment | — (descriptive; whichever way it falls, the verdict is "implementation-dependent" unless it tracks ADDKE exactly) |
| P7-4d | **EXP-04 Signal 4 (fragmentation pattern) is IMPLEMENTATION-DEPENDENT** | Fragment sizing is local policy (RFC 7383) | — (already indicated by the 3-fragment observation) |

**Method:** captures at the keyless router, filtered per arm; same analysis code as EXP-01/02/03/04,
pointed at Libreswan captures. Verdict per signal: **holds** / **holds in direction only** /
**implementation-dependent** / **fails**.

### EXP-05 — RESULT (2026-09-12): DONE — all five predictions held; P5-3 stronger than predicted
TFC padding to MTU: one ESP length, size MI exactly 0, +54% bytes — and RF macro-F1 0.995 vs 1.000
unpadded (timing ≈ 1 bit/packet either way). Stable folds (std ≤ 0.009); permutation null at chance.
Depth-2 rule measures ~half the leakage (0.51), so the learned instrument is justified (CS-01).
Mixtures: video+interactive labelled "web" in 100% of windows. Absolute F1 is a property of the
synthetic shapes, not of real traffic. Two analysis bugs caught before the final numbers
(direction leaking into size MI; the partial final window). `experiments/exp05-metadata-leakage/RESULT.md`.

### EXP-07 — RESULT (2026-09-12): DONE — 7/7 predictions held
Libreswan 5.4: sieve classes identical; negative control holds; PFS gap exactly 256 B (same as
strongSwan); IKE_INTERMEDIATE presence holds; IKE_SA_INIT grows +8 B (one ADDKE transform;
strongSwan's +16 adds its PQ-only notify). Notify 16438 and fragmentation are implementation-
dependent — a notify-based PQ detector would false-positive on Libreswan. One analysis bug fixed
(address-keyed comparison). `experiments/exp07-libreswan-generalization/RESULT.md`.

---

## T-044 / A7 — Tunnel vs Transport mode inference — PRE-REGISTRATION (2026-09-12, before capture)

**Question:** can a passive observer at T0/T1 tell tunnel mode from transport mode? The Observability
Matrix (01-DISCOVER A7) marked this "I" (inferable); 09-DEFINE lists it as the one candidate-ML row
never tested. This resolves it either to a deterministic signal, a statistical one, or NOT-OBSERVABLE.

**Protocol fact this rests on:** in **tunnel** mode ESP encapsulates a whole inner IP packet, so the
encrypted content includes a 20-byte inner IPv4 header (40 for IPv6). In **transport** mode ESP
protects only the upper-layer payload — no inner IP header. So for *identical inner traffic*, tunnel
ESP content is exactly 20 bytes (v4) larger than transport. The next-header trailer byte also differs
(tunnel: 4=IPv4 / 41=IPv6; transport: 1=ICMP / 6=TCP / 17=UDP) but it is inside the ciphertext.

**Arms:** `cs-aes256gcm16` (tunnel) and `cs-transport-aes256gcm16` (transport) — same AES-GCM-256,
same host pair, same ICMP size sweep.

**Predictions:**

| # | Prediction | Reasoning | Falsified if |
|---|---|---|---|
| P44-1 | **With a paired baseline** (same traffic run through both modes), the ESP content-length sets differ by a **fixed +20 bytes** (tunnel larger) | inner IPv4 header | any offset other than 20, or non-constant |
| P44-2 | **Without a baseline** (a single capture, unknown inner traffic), the two modes' length distributions **overlap** — a transport packet of payload P+20 is indistinguishable from a tunnel packet of payload P | the observer has no way to subtract the unknown inner size | a length or structural feature separates the modes with no shared-traffic assumption |
| P44-3 | The only non-length passive tell is **topology**: transport mode requires outer addresses == the actual talking hosts; tunnel mode permits outer != inner (gateway). At T0 this is only usable when the deployment is gateway-to-gateway | RFC 4301 | — (descriptive) |

**Verdict rule:** if P44-2 holds, **A7 is NOT-OBSERVABLE at T0 from traffic alone** (mode comes from
T2, or from topology context, or is reported UNKNOWN). If P44-2 is falsified, there is a real
inference signal and it may warrant the one statistical component. Either way the ML row is resolved.

### EXP-08 (T-044 / A7) — RESULT (2026-09-12): DONE — mode is NOT-OBSERVABLE at T0
P44-1 held (fixed +20 B with a paired baseline); P44-2 held (without a baseline, every ESP length is
valid in both modes — the +20 B inner header is encrypted). Resolves the last candidate-ML row: no ML
for mode. Only CS-01 leakage measurement remains ML. `experiments/exp08-mode-inference/RESULT.md`.

### EXP-10 — Cross-implementation, third codebase: real OpenBSD `iked` (T-047, 2026-09-13)
**Not pre-registered** — reactive, user-directed ("find a free/open-source vendor-diversity
alternative"), stated honestly rather than retrofitted as if planned. Addresses `research/12-DEVELOP.md`
§6's red-team risk: "only two implementations tested [strongSwan, Libreswan]." OpenIKED-portable,
OpenIKEv2 and racoon2 were each checked and ruled out with evidence (dead/archived/unstable — see
RESULT.md). Ran strongSwan 6.1.0 (macOS host) against a genuine OpenBSD 7.9 `iked` responder (real VM,
arm64 native, isolated network) — an architecturally independent third codebase, not another
strongSwan/Libreswan-lineage fork.

**Result:** `ike_meta`/`ike_crypto`/PQ-posture extraction and EXP-06's failure-diagnosis heuristic all
generalized correctly on a genuine authentication failure (byte-exact match to `iked`'s own log). But
the same heuristic **misdiagnosed a real success** as `child-sa-rejected`, because no ESP traffic was
sent and the heuristic conflates "no ESP yet" with "ESP rejected" — a genuine gap the 71 prior captures
never exercised. Also surfaced that OpenBSD's `iked` supports its own PQ mechanism
(`sntrup761x25519`, a DH-group-encoded hybrid) architecturally different from strongSwan/Libreswan's
RFC 9370 ADDKE + ML-KEM — our PQ detector would not recognize it, flagged as a scoped follow-up, not
silently claimed as working. `experiments/exp10-openbsd-iked-generalization/RESULT.md`.

### EXP-11 — Peer auth-method inference (R7/OQ-05), T-048, 2026-09-13
Full-project audit found R7's auth-method half (PSK/cert/EAP via CERTREQ/SIGNATURE_HASH_ALGORITHMS,
disposed as buildable in `research/09-DEFINE.md`) was never built. Built it, then empirically
falsified the easy version before shipping: SIGNATURE_HASH_ALGORITHMS is unconditional; CERTREQ
reflects the *responder's* fleet-wide cert policy, not this SA's method (differential test: real
cert auth + a PSK control on the identical responder, both showed CERTREQ). Shipped honestly:
`peer_auth_method` NOT-OBSERVABLE at T0/T1 (same encryption-boundary pattern as mode/EXP-08),
`responder_cert_capability` as the correctly-scoped real capability. R7 corrected in 09-DEFINE.md.
`experiments/exp11-auth-method-inference/RESULT.md`.

### EXP-12 — Rekey-cadence measurement (R9/R12), T-048, 2026-09-13
`sa_lifecycle` was planned in `build/00-ARCHITECTURE.md` but never built. Built it: measures
observed CREATE_CHILD_SA inter-arrival times (never a claimed configured lifetime — IKEv2 negotiates
none, F-02). Validated on a real capture with 7 rekeys (manual + interleaved auto-rekey); measured
intervals matched the manual 15s trigger spacing almost exactly. **Also found a real security bug**
in the shipped CVE-2026-78135 detector: message IDs are per-originator (RFC 7296 §2.1), so a
responder-initiated rekey's own counter restarting at 0 produced a false positive when compared
globally against the initiator's sequence. Fixed to compare by frame/capture order; re-verified 0 FP
on all 69 real captures plus both true positives still firing.
`experiments/exp12-rekey-cadence/RESULT.md`.

### EXP-13 — Cloud-VPN-style proposal sets (mentor follow-up C1), PRE-REGISTERED 2026-09-18
AWS Site-to-Site VPN default proposal set emulated on strongSwan; 5 arms (legacy DH 2/SHA-1 with
NAT-T, common MODP-2048, hardened AES-GCM/ECP-384, IKEv1, cloud-initiated offering its full set).
Seven predictions, including three expected gaps (AEAD integrity wording, IKEv1 suite, weak
*offered* algorithms). Full pre-registration: `experiments/exp13-cloud-vpn-proposals/PREREG.md`.

### EXP-13 — RESULT (2026-09-19): DONE — P3–P6 held; P1 failed on one arm (a real bug); 4 fixes
Found and fixed: IKE suite lost after an INVALID_KE_PAYLOAD retry (first, error-only response was
used); unnamed DH groups scored as FAIL (strong 17/18 would have failed); RFC 8247 DH rule compared
group numbers and passed group 22 (MUST NOT); weak *offered* groups invisible. New finding
`ike_offered_dh` + rule `RFC8247-DH-OFFER`: the cloud-initiated arm negotiated MODP-2048 but offered
groups 2 and 22. `experiments/exp13-cloud-vpn-proposals/RESULT.md`.

## EXP-14 — Transport mode from the tunnel-mode size floor — PRE-REGISTRATION (2026-09-20)
Pre-registered in `experiments/exp14-mode-size-floor/PREREG.md` before any capture. Revisits EXP-08's
P44-2: a packet below the tunnel-mode floor cannot be tunnel mode.

## EXP-15 — Eight traffic classes, IKE/DH suite variety, AH — PRE-REGISTRATION (2026-09-20)
Pre-registered in `experiments/exp15-traffic-classes-suites-ah/PREREG.md` before any capture.

### EXP-14 — RESULT (2026-09-20)
Size floor: 0 false transport (P14-1, P14-4 held), both transport captures found (P14-2), but ~0%
coverage on realistic traffic (P14-3 failed, as predicted in addendum A before data). ACK-size model
(exploratory): 44/64 held-out sessions answered, 100% correct, 0 tunnel→transport; one post-hoc false
positive on a ping sweep fixed by a purity guard (addendum B). `experiments/exp14-mode-size-floor/RESULT.md`.

### EXP-15 — RESULT (2026-09-20)
8-class traffic classifier: macro-F1 0.995 tunnel, 0.958 TFC, 0.986 cross-cipher, ECE 0.049. P15-4
failed: mixed traffic abstained in 29%, video+interactive read as web 8/8 (stated in the output).
Suites (9) and AH (5) all match endpoint ground truth. `experiments/exp15-traffic-classes-suites-ah/RESULT.md`.

## EXP-16 — Real applications, cross-implementation, mixed detector — PRE-REGISTRATION (2026-09-20)
Pre-registered in `experiments/exp16-real-apps-cross-impl/PREREG.md` before any capture. Scope of
recording decided first: lab-only clients and servers, no third-party service, account or personal data.

### EXP-16 — RESULT (2026-09-20)
P16-1 **FAILED**: a synthetic-trained classifier scored macro-F1 0.461 on real applications (file
transfer 0.00, messaging 0.18, interactive 0.19) — the lab's 0.995 was a property of the traffic
generator, not of the model. P16-2 held (trained on real sessions: 0.995), P16-3 held
(strongSwan→Libreswan 1.000), P16-6 held (extra repetitions moved nothing, delta 0.000), P16-5 held
(mixed detector 92.9% caught / 8.3% false / video+interactive 100%). Shipped model retrained on all
1,964 windows (LORO 0.986). `experiments/exp16-real-apps-cross-impl/RESULT.md`.

## EXP-17 — Network conditions: delay, jitter and packet loss — PRE-REGISTRATION (2026-09-20)
Pre-registered in `experiments/exp17-network-conditions/PREREG.md` before any capture. The run script
was smoke-tested first (mechanics only; every smoke output was deleted, none was analysed). The smoke
test found and fixed a silent failure in the real-application server setup (Prosody half-starting as
root); `run_exp16.sh` had the same latent pattern and got the same fix.

### EXP-17 — RESULT (2026-09-21)
P17-1 FAILED: the shipped classifier scored window-level macro-F1 0.5257 on the wan profile across 495 pooled windows (syn 0.5453, real 0.5308), falling short of the 0.70 threshold.
P17-2 FAILED: the shipped classifier scored window-level macro-F1 0.3802 on the lossy profile across 519 pooled windows (syn 0.4235, real 0.3440), falling short of the 0.50 threshold.
P17-3 FAILED: leave-one-repetition-out retraining over the three impaired repetitions reached mean macro-F1 0.9533 on wan (rep1 0.9313, rep2 0.9559, rep3 0.9726) but 0.8398 on lossy (rep1 0.8089, rep2 0.8412, rep3 0.8692), missing the 0.90 threshold on lossy.
P17-4 Held: the ACK-size mode model answered zero tunnel-mode sessions as transport across all 96 sessions in both profiles (wan: 8 tunnel, 40 abstained; lossy: 12 tunnel, 36 abstained).
P17-5 FAILED: the mixed-traffic detector wrongly flagged 33.33% of wan single-class sessions (16/48) and 20.83% of lossy single-class sessions (10/48), exceeding the 15% threshold on both profiles.
P17-6 Held: on 100% of established IKE bring-ups under impairment (5 wan, 5 lossy), IKE encryption, DH group and integrity matched swanctl ground truth with zero mismatches, and the CVE-2026-78135 detector produced zero FAIL verdicts (10 PASS).

## EXP-18 — Generative remediation: is the local model's draft right, and does the safety net catch 100%? — PRE-REGISTRATION (2026-09-24)
Pre-registered in `experiments/exp18-generative-remediation/PREREG.md` before any run (DEC-033,
DEC-034, build/13 T-106). H1: every code-built bad draft (30) and 2 prompt-injection configs are
stopped before apply, or confirmed fixed, or rolled back and verified; one miss fails it. H2 (ship
bar for local-model drafts in the dashboard): A1 draft confirmed fixed live with no regression on
>= 0.80 of included test items, Wilson 95% lower bound >= 0.60. H3: critique and self-review are
kept only if they help. Dev set (V-207205, RFC8221-AH-LEGACY, DST-PQ-KE) is the only place the
prompt may be tuned; the chosen prompt is frozen in FREEZE.md before the test set runs.

### EXP-18 — RESULT (2026-09-24)
H1 HELD: all 32 safety items (30 code-built bad drafts across 10 mutation kinds, 2 prompt-injection configs with the real model) were stopped before apply by a code check; none reached the lab.
H2 FAILED: 0 of 16 included test items had an A1 draft confirmed fixed (0.00, Wilson 95% 0.00-0.19); every draft was refused (V5 9, V3 5, V6 2). Local-model drafts stay switched off.
H3: critique not kept (A0 0/16, A1 0/16); self-review not kept (no accepted draft to review). Robustness (temperature 0.7, 5 seeds): 0 of 79 accepted.
Excluded as pre-registered: D1-D2 (IKEv1 did not establish), D3-D4 and T17-T20 (ESP/AH rules are UNKNOWN on a handshake-only capture: the remediation loop cannot verify ESP/AH fixes, hand-written included), one infrastructure failure (Docker stopped). `experiments/exp18-generative-remediation/RESULT.md`.

## EXP-19 — Real public traffic (MIT VNAT) for the traffic classifier — PRE-REGISTRATION (2026-09-24)
Pre-registered in `experiments/exp19-real-public-traffic/PREREG.md` (commit 0e02a6c) before any training.
Data: the 82 OpenVPN tunnel flows of MIT Lincoln Laboratory VNAT (`vpn_*` captures), labels from the file
name keyword only. Q1 lab model on real traffic; Q2 real-only model grouped by capture file; Q3 real
OpenVPN -> our IPsec real applications; Q4 combined model. Ship bar: Q4a >= 0.80, Q4a >= Q1 + 0.10,
Q4b no more than 0.02 worse, file < 5 MB.

### EXP-19 — RESULT (2026-09-24)
4,702 windows from 82 real tunnels. Q1 0.472; Q2 0.744; Q3 0.378; Q4a 0.741 (folds 0.60-0.95); Q4b 1.000 with vs 0.996 without.
Ship bar NOT met (Q4a < 0.80); the other two conditions held. Owner shipped it anyway: DEC-036.
`experiments/exp19-real-public-traffic/RESULT.md`.

## EXP-20 — Real IPsec traffic (USBVPN2022) and real people (WireGuard matched-view) — PRE-REGISTRATION (2026-09-25)
Pre-registered in `experiments/exp20-real-ipsec-and-users/PREREG.md` (commit dc0020f), with a frozen
scoreboard (`build/models/benchmark.py`, T-110) of 4 grouped test sets, before any training. A: real
IPsec traffic (USBVPN2022 L2TP-IPsec, the first the project has). B: real people (WireGuard matched
outer/inner captures), session 1 trains, session 2 tests. C: real OpenVPN (VNAT, EXP-19 continuity).
D: our lab (EXP-16 real apps, leave one repetition out). Five recipes R0-R4; ship bar: A up by >= 0.05,
B/C/D not more than 0.02 down, abstain accuracy not down, files < 5 MB, startup fit (n_jobs=1) < 5 s.

### EXP-20 — RESULT (2026-09-25)
6,069 real-IPsec windows (994 records) + 11,450 real-people windows (1,186 flows). Today's shipped
model (R0) scores 0.174 macro-F1 on real IPsec and answers 0% of the time (always abstains). The
candidate R3 (+ USBVPN + WireGuard without web) reaches **0.757** and answers 93.6% of the time at
99.8% accuracy when answering, with B/C/D flat or improved. Every accuracy condition of the ship bar
passed by a wide margin; **R3 failed the bar on one operational condition**: the shipped code's
single-threaded startup fit measured 5.00 s against the pre-registered < 5 s line (parallel fit of
the same data: 0.68 s, predictions identical to floating-point noise — a separate decision from this
experiment's bar). R4 (+ WireGuard's nDPI "web") was ruled out by its own pre-registered check (Q5):
it lowers A and collapses voip's F1, the label-noise risk stated in advance. Nothing shipped
automatically; owner decision pending. `experiments/exp20-real-ipsec-and-users/RESULT.md`.

## EXP-18b — Generative remediation with the cloud backend (Gemini): same bar as EXP-18 — PRE-REGISTRATION (2026-09-25)
Pre-registered in `experiments/exp18b-gemini-remediation/PREREG.md` before any run (DEC-038). Reuses
EXP-18's items, H1/H2/H3 bars and lab discipline unchanged; the only difference is
`backend="cloud"` (Google Gemini via `tunnelscope/remediate/cloud_client.py`) in place of the local
model. The 30 code-built safety items (S1-S10) are not re-run (they exercise the unchanged checking
code, not the model, per PREREG.md); the 2 prompt-injection configs (S11a/S11b) are re-run live.

## EXP-26 — A different vendor's IKE stack: MikroTik RouterOS 7.24.4 — PRE-REGISTRATION (2026-09-26)
Pre-registered in `experiments/exp26-mikrotik-routeros/PREREG.md` before any capture (roadmap T-118
step 1). Two RouterOS CHR VMs (QEMU, emulated Cortex-A72) on a virtual cable, keyless capture of the
cable; 8 scored arms (baseline, modern x25519/ChaCha20, ECP, legacy 3DES/modp1024, CBC+HMAC, PFS on
and off with 30 s rekeys, weak group offered but not selected) plus one exploratory RFC 8784 PPK arm.
Ground truth from RouterOS's own installed-SA state. Primary bar H1: zero wrong findings; UNKNOWN is
never wrong. Predicted gap H7: no PPK detector.

### EXP-26 — RESULT (2026-09-26)
97 of 104 scored findings correct, 6 UNKNOWN (PFS without a rekey, correctly), **1 wrong**: M7 (PFS off)
inferred PFS on. Cause, from RouterOS's own debug log: RouterOS pads encrypted IKE payloads by up to
~255 B (a 132 B rekey request is sent as 444 B), and `extract_pfs` reads a request >= 400 B as carrying
a KE payload (strongSwan calibration); M6's correct answer is therefore not evidence. All IKE suite
fields (incl. x25519, ECP) correct in 8/8 arms. H1, H3, H6 failed; H4/H5 failed as written only
(TunnelScope's rekey timing matches the wire; no CVE false alarm). PPK arm dropped: RouterOS 7.24.4
accepts only `ppk=no`. Follow-ups T-135 (padding-aware PFS), T-136 (PPK detection).
`experiments/exp26-mikrotik-routeros/RESULT.md`.

## EXP-27 — RFC 8784 PPK: negotiation is visible, use is not — PRE-REGISTRATION (2026-09-27)
Pre-registered in `experiments/exp27-ppk-detection/PREREG.md` before any capture (roadmap T-136).
strongSwan 6.1.0 lab, five arms: no PPK, PPK optional, PPK required, responder without PPK, and a
fallback arm where both sides announce PPK but the responder holds it under another id (PPK not used).
New finding `pq_ppk` (negotiated / offered-not-negotiated / not-offered) must never claim PPK use;
H2 is the honesty test on the fallback arm.

### EXP-27 — RESULT (2026-09-27)
All hypotheses passed. New finding `pq_ppk` read the plaintext USE_PPK notify correctly in every arm
(not-offered / negotiated / offered-not-negotiated) and never claims use. The fallback arm K5 (added after
K4, declared) is the proof: USE_PPK both ways, tunnel up, strongSwan logs "using NO_PPK_AUTH". K4 deviated
from the RFC-based prediction: strongSwan rejects an unexpected PPK_ID (AUTH_FAILED) instead of falling
back. IKE suite fields 0 wrong. Rules and risk score unchanged. `experiments/exp27-ppk-detection/RESULT.md`.

## EXP-28 — Config vs wire reconciliation — PRE-REGISTRATION (2026-09-27)
Pre-registered in `experiments/exp28-config-vs-wire/PREREG.md` before `tunnelscope reconcile` is built
(roadmap T-121). Controls: the lab configs that produced the captures (initiator and responder sides);
drift arms: copies changed in one field (IKE group, IKE cipher, ESP family, PFS, PPK, ML-KEM); honesty arm:
ESP key length only (unobservable, F-05). Bars: 0 false mismatches, 100% of observable drift caught,
key-length changes always "not comparable", no UNKNOWN wire field ever "match".

### EXP-28 — RESULT (2026-09-27)
H1 PASS: 0 false mismatches on 94 real config/capture pairs (52 initiator, 42 responder configs). H2 FAIL
(187/207 as first built, 187/206 after a scoring fix): every exactly-observed field caught all drift (IKE group,
IKE cipher, PFS, PPK, ML-KEM: 161/161), ESP cipher family 26/45; the 19 others are inside the sieve's candidate
set and cannot be ruled out by geometry. H3 PASS (ESP key length 47/47 not comparable), H4 PASS. Disclosed
post-result changes: scorer role fix (a-start's initiator is the cloud side) and a label fix: agreement with an
INFERRED wire finding is "consistent", never "match". `experiments/exp28-config-vs-wire/RESULT.md`.

## EXP-29 — IKE implementation fingerprinting from plaintext — PRE-REGISTRATION (2026-09-27)
Pre-registered in `experiments/exp29-implementation-fingerprint/PREREG.md` before any feature was looked at
(roadmap T-127, Batch A). Split by session and version: train = strongSwan 5.9.8 EXP-01/02, Libreswan EXP-07
(5 arms), MikroTik M1-M4; test = everything else incl. strongSwan 6.1.0, a fresh Libreswan session captured
after the rules are frozen, MikroTik M5-M8, and OpenBSD iked (no training data; must be UNKNOWN).
H1: zero wrong labels.

### EXP-29 — RESULT (2026-09-27)
All hypotheses passed. Rules frozen (271ad83) before scoring. Held-out: 200/218 known-implementation ends named
correctly (91.7%), 0 wrong; strongSwan 6.1.0 (never trained) 74/74; a Libreswan session captured after the freeze
16/20; OpenBSD iked UNKNOWN. Unknowns: 10 strongSwan responders that never answered with a proposal, 8 Libreswan
ends where IKE_INTERMEDIATE support adds a notify the frozen rule does not expect (follow-up, not changed
post-hoc). Disclosed scorer fix (EXP-10 truth per end). `experiments/exp29-implementation-fingerprint/RESULT.md`.

### EXP-18b — RESULT (2026-09-27)
Safety (H1) passed for both cloud arms. Test set confirmed fixed live: Groq gpt-oss-120b 12/16 (0.75, Wilson
[0.505, 0.898]), gemini-3.1-flash-lite 13/16 (0.8125, [0.570, 0.934]) vs local 0/16; ship bar (>= 0.80 and lower
bound >= 0.60) not met by either. All 11 regressions (all on T9: a new group failing DISA's >= 16) were rolled back
and verified. Critique rounds help; self-review stays off. gemini-3.8-flash unfinished (free quota). Addenda A-D
disclosed. `experiments/exp18b-gemini-remediation/RESULT.md`.

## EXP-30 — Other active rules in the drafting prompt — PRE-REGISTRATION (2026-09-27)
Pre-registered in `experiments/exp30-other-rules-context/PREREG.md` before the code change and any run. Prompt P3 =
P0 + a block listing the other active rules judged on the same line + one system-prompt sentence (do not make any
of them fail). Groq gpt-oss-120b and gemini-3.1-flash-lite, arm A1, EXP-18's dev/test items and S11a/b, scored by
EXP-18's analyze.py. Success: 0 regressions (EXP-18b: 1 per backend, T9), at most 1 EXP-18b-confirmed item lost,
H1 safety holds. Disclosed: motivated by EXP-18b's T9 test failures, so T9 is reported separately.

### EXP-30 — RESULT (2026-09-27)
Primary outcome failed. gemini-3.1-flash-lite, shown V-207193 (group >= 16), still fixed T9 with modp3072 (group
15): regression caught live, rolled back, verified (O1 fail). No EXP-18b-confirmed item lost (O2 pass); safety
S11a/b held; one run under P3 confirmed 15/16 (0.9375, Wilson [0.717, 0.989]), gains on items whose EXP-18b failures
were answer shape, not attributable to P3. Groq stopped at the pre-registered dev gate (4/5 vs 5/5, a V5 formatting
slip). P3 not adopted; default stays P0. Next: check the other active rules in code before the dry run. Addenda A-B
and one post-result scorer fix disclosed. `experiments/exp30-other-rules-context/RESULT.md`

## EXP-31 — Code check for other-rule conflicts before the dry run (T-138) — PRE-REGISTRATION (2026-09-27)
Pre-registered in `experiments/exp31-no-trade-check/PREREG.md` before the code and any run. V6 extended: a draft
that makes another active rule on the same line go from not failing to failing (judged by `rule_outcome` on
observed evidence) is refused before the lab and fed back through the critique loop. Prompt P0. Groq and
gemini-lite, A1, EXP-18's items + S11a/b. Success: 0 regressions reach the lab, at most 1 EXP-18b-confirmed item
lost, safety holds. Disclosed: targets EXP-18b's T9, so T9 is reported separately.

### EXP-31 — RESULT (2026-09-27)
All outcomes passed for both backends: 0 drafts that broke another active rule reached the lab (EXP-18b: 1 each,
T9), no EXP-18b-confirmed item lost, safety S11a/b held. T9: Groq's MODP-2048 draft refused at V6, revised to
MODP-4096, confirmed live; gemini-lite kept MODP-3072 and was refused each round before the lab. H2: Groq 13/16
(bar not met), gemini-lite 14/16 (Wilson lower 0.64, met). DEC-042. `experiments/exp31-no-trade-check/RESULT.md`

## EXP-32 — Site sensor: detection latency and what leaves the site (T-139) — PRE-REGISTRATION (2026-09-27)
Pre-registered in `experiments/exp32-site-sensor/PREREG.md` before the code and any run. Live lab, W = 10 s, 10
post-quantum -> classical changes. Bars: 10/10 detected centrally; median latency <= 20 s, max <= 35 s; 0 false
alerts; every report sequence accepted exactly once across a collector outage; 100% of reports pass the strict
allow-list (no packet bytes); tampered / unknown-site / replayed reports rejected (unit tests).

### EXP-32 — RESULT (2026-09-27)
All bars held. 10/10 PQ downgrades on the live lab tunnel reached the central collector: median 8.9 s, max 10.3 s
(W = 10 s); 0 false alerts; 56 reports, each accepted exactly once across a 30 s collector outage; 56/56 passed the
strict allow-list. Disclosed harness logging bug (H4 scored from the collector's state, a PREREG-named source).
DEC-043. `experiments/exp32-site-sensor/RESULT.md`

## EXP-33 — Headers-only capture (T-141) — PRE-REGISTRATION (2026-09-28)
Pre-registered in `experiments/exp33-headers-only/PREREG.md` before the code and any run. One dumpcap, same interface
twice: IKE at full length, ESP/AH stored to 80 bytes; compared with a full capture of the same traffic (10
handshakes A/B, W = 10 s). Bars: 0 finding/verdict differences; 100% of ESP/AH records <= 80 bytes and IKE full.

### EXP-33 — RESULT (2026-09-28)
Both bars held: 0 finding/verdict differences over 11 SAs between a full capture and a headers-only capture of the
same traffic; 732/732 ESP records stored <= 80 bytes, 75/75 IKE whole. ESP bytes stored 112,728 -> 58,560 (small
ping packets). Addenda A (one file per capture) and B (harness crash before any data). DEC-044.

## EXP-34 — Behaviour-based IKE attack-pattern detectors (T-131) — PRE-REGISTRATION (2026-09-28)
Pre-registered in `experiments/exp34-cve-detectors/PREREG.md` before the code and any run. Three exact detectors on
plaintext IKEv2 (RFC 7296 violations matching CVE triggers from NVD): malformed KE data, INFORMATIONAL before
IKE_AUTH, IKE_SA_INIT request missing SA/KE/Nonce. Bars: 0 detections on every benign capture; 18/18 crafted attacks
sent at real strongSwan and Libreswan responders detected by the right detector; UNKNOWN (never PASS) without the
handshake.

### EXP-34 — RESULT (2026-09-28)
Three plaintext-IKEv2 attack-pattern detectors (malformed KE, INFORMATIONAL before IKE_AUTH, IKE_SA_INIT missing
SA/KE/Nonce). H1 specificity: 0 false detections over 695 captures / 668 SAs (159 PASS, 509 UNKNOWN). H2 sensitivity:
decision-function unit tests (ADDENDUM A -- no crafted attack traffic). H3 vantage: UNKNOWN without the handshake. 4
mutation checks caught. DEC-048. `experiments/exp34-cve-detectors/RESULT.md`

## EXP-35 — NIST SP 800-77 Rev. 1 as an opt-in rules profile (T-122 part 2) — PRE-REGISTRATION (2026-09-29)
Pre-registered in `experiments/exp35-nist-800-77r1-profile/PREREG.md` (654e2ff) before any code and any run. 11 rules
from Table 1 and sections 2.2-7.2.6 of the hashed NIST PDF, each with its verbatim quote; the rule-making method
(severity from shall/should) and the requirements not made into rules are fixed there. Bars: default verdicts
identical to main on every capture; every quote verbatim in the PDF; pre-stated verdicts on 10 named captures; no PASS
on missing evidence.

### EXP-35 — RESULT (2026-09-29)
H1: 0 default-verdict differences over 695 captures vs main 85777ca. H2: 20/20 quotes verbatim (PDF SHA-256
bc2a36dc...74bd70). H3: 10/10 captures exactly as pre-registered; the two ESP rules 0 PASS / 0 FAIL on 668 SAs
(UNKNOWN: packet sizes cannot decide). H4: 0 PASS without evidence. 7 mutation checks caught. DEC-049.
`experiments/exp35-nist-800-77r1-profile/RESULT.md`

## EXP-37 — Cross-lab test on two other teams' captures — PRE-REGISTRATION (2026-10-01)
Pre-registered in `experiments/exp37-cross-lab-external/PREREG.md` (df26be3), scorer committed before the run (43dcd82).
Part A: 239 captures of `ipsec-pcap-lab` (commit c0cf256, ESP-only, no licence). Part B: 55 of 60 control-plane captures
of an ML-KEM thesis set (5 not downloadable). 12 predictions; local analysis only; captures deleted afterwards.

### EXP-37 — RESULT (2026-10-01)
Held: no DH/PFS claim on 175 ESP-only captures; the cipher sieve never excluded the true family (175/175); 0 OBSERVED
handshake values contradicted metadata (8/8); 0 false PQ claims on 29 classical runs. Falsified: traffic type answered
5/175 and 0/5 correct (coverage 2.9%); 24 of 26 hybrid files cut short mid-packet and refused by the product. Not scorable
as registered: mode (never committed), P37-9 and P37-11 (scorer defect: wrong record chosen for control-plane files,
found after the numbers, disclosed). Post-hoc, not registered: whole-capture scoring on trimmed copies reads 26/26 hybrid
runs as ML-KEM-768 with the swanctl suite, 0 false PQ. Follow-ups: read cut-short captures, IKEv1 transform coverage,
multi-lab traffic-type test. `experiments/exp37-cross-lab-external/RESULT.md`

## EXP-38 — Why the traffic-type model does not transfer to another lab — PRE-REGISTRATION (2026-10-01)
Pre-registered in `experiments/exp38-traffic-transfer-diagnosis/PREREG.md` (9d7a03c), scorer 584da2f, before any run. Same
175 `ipsec-pcap-lab` captures as EXP-37 (permission relayed verbally; no licence file). Separates three causes: a strict
gate, a model that does not generalise, features that cannot separate the classes. Nothing that ships is changed.

### EXP-38 — RESULT (2026-10-01)
P38-1 falsified: the out-of-distribution gate stops 41 of 175 (23%); 107 (61%) pass it and are stopped by the confidence /
agreement rules, 22 have under 3 windows, 5 answered. Held: ungated shipped model macro-F1 0.262; features separate their
classes inside their lab (R05 1.000, leave-one-profile-out 1.000, caveat: easy distinct generators, 33 test captures);
adding their windows to training scores 1.000 on R05 and changes our grouped-CV macro-F1 by +0.003. Decision: the gates
are right to abstain; training-data coverage is the gap; any training change needs its own PREREG and a third lab.
`experiments/exp38-traffic-transfer-diagnosis/RESULT.md`

## EXP-39 — Does training on one lab help on another? (leave-one-lab-out) — PRE-REGISTRATION (2026-10-01)
Pre-registered in `experiments/exp39-two-lab-transfer/PREREG.md` (d32724e), scorer 66adfc3, before any run. Lab A
`ipsec-pcap-lab` (c0cf256) and lab B `ashwin02-cyber/SIH_2026` (ef0ffe9, manifest hashed); both authors' permission relayed
verbally; no captures or derivatives committed. Shipped forest/gates retrained on other windows via `attacker.DATA`; no
shipped file edited. Six predictions.

### EXP-39 — RESULT (2026-10-01)
Falsified as registered: P39-2 (A->B gain +0.015), P39-3 (coverage 48.6%, 35/35 correct), P39-4 (B->A gain +0.008), P39-5
(2.0%); held: P39-1, P39-6 (no harm, +0.002). Pre-registration flaw found in the data: lab B has 0 windows for
file_transfer and voip and 1 for video (10 MB scp ends inside one 2 s window; SIP is sparse), so only icmp and web can be
scored and macro-F1 over five classes was unattainable. Supported reading: icmp transfers (1.000 for every model); for web,
training on the other lab did not help in either direction. The labs cannot answer the wider question. Nothing ships.
Next: a third lab of our own with sustained traffic per class. `experiments/exp39-two-lab-transfer/RESULT.md`

## EXP-40 — Read the negotiated suite of an IKEv1 session — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp40-ikev1-transforms/PREREG.md` (9d95710) before any capture and any code; lab, 8 Libreswan 5.4
IKEv1 arms (Main and Aggressive Mode, one two-offer arm), captures with pluto ground truth, scorer and before-snapshot committed
in 04a8a27 before the extractor existed. Six predictions plus five named mutation checks.

### EXP-40 — RESULT (2026-10-02)
All six held: 8/8 suites equal pluto's log; the two-offer arm reports the second offer (the selection); 8/8 offer-only cuts give
UNKNOWN; 0 IKEv2 captures changed (701); verdicts as predicted, no RFC 8247 verdict on IKEv1; nothing else changed. The one existing
IKEv1 capture (strongSwan) also matches swanctl. Not exercised: a real failed IKEv1 negotiation. Two earlier pins superseded with owner
approval (EXP-35 NIST row for cloud/c-v1; test_cloud_vpn). DEC-051. `experiments/exp40-ikev1-transforms/RESULT.md`

## EXP-41 — A third lab with sustained traffic and new generators — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp41-lab-c/PREREG.md` (a4521a2, erratum 3b9a94c); scorer and harness d6f43e8 and data f5c9c3f committed before any scoring. Lab C:
eight classes from tools not in our shipped generators or labs A/B (iperf3, wget -r, MQTT, telnet over a pty, MPEG-TS over UDP, Opus RTP, curl SMTP, ping), two
tunnel configurations, 32 captures of 60 s. Test for models retrained on the two public labs. Seven predictions.

### EXP-41 — RESULT (2026-10-02)
Held: shipped model does not transfer (0.442 macro-F1); lab C's classes are fully learnable inside the lab (1.000); no harm to our own CV (+0.001). Falsified: training on
lab A (+0.026) or A and B (+0.026) did not help on lab C; gated coverage 12.5% (4 of 4 answers right); adding lab C lowered lab A (0.262 -> 0.245). Per class: right for
bulk, e-mail, VoIP; wrong for ping, telnet, video. Decision: do not retrain on the public labs; README states the limit. One ICMP capture re-run after a gateway ICMP-redirect
fault (found, fixed, disclosed). `experiments/exp41-lab-c/RESULT.md`

## EXP-42 — Make the traffic classifier generalise to generators it has never seen — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp42-generalise/PREREG.md` (bad8196) before any leave-one-family-out number. Eight families as raw
packet streams (`build/models/corpus.py`); candidates K0-K6 (balancing, augmentation, v2 rhythm/shape features, ExtraTrees,
HistGradientBoosting); selection rule and lab D's tools fixed in advance.

### EXP-42 — RESULT (2026-10-02)
Leave-one-family-out mean macro-F1: K0 0.412 -> chosen K4 (v2 + balancing + augmentation) 0.455 (+0.043; predicted >= +0.10,
falsified). Balancing +0.014, augmentation -0.023, v2 +0.026 (all below +0.03). In-distribution stays 0.977-0.988. Gains on lab C
(0.49->0.66), lab A (0.30->0.45), VNAT (0.44->0.54); losses on lab-tgen and WireGuard; USBVPN 0.03-0.10 for every candidate. One
scorer crash (zero-packet session) fixed before K2 was scored. Decision deferred to lab D (EXP-43). `experiments/exp42-generalise/RESULT.md`

## EXP-43 — Lab D, the final untouched test for EXP-42's chosen model — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp43-lab-d/PREREG.md` (31c3bc5) after EXP-42's selection and before any lab-D capture. Lab D: aria2c,
httrack, GStreamer H.264 and G.711 RTP, IRC, msmtp/OpenSMTPD, mosh, fping; ChaCha20-Poly1305 and AES-CBC/SHA-384; netem 15 ms +- 5 ms,
0.2% loss; 32 captures. Ship rule fixed in advance.

### EXP-43 — RESULT (2026-10-02)
All four predictions held. Shipped model 0.417 macro-F1, K4 0.833 (+0.417; both suites 0.833); gated answers K4 11/11 right vs 7/9.
Interactive still 0/4. Ship rule met; the shipped artifact (5.0 MB) reproduced 0.833 and 11/11 when checked once. DEC-054. Limits: 4
captures per class; built on our gateways. `experiments/exp43-lab-d/RESULT.md`

## EXP-44 — Recalibrate the mixed-traffic check for the new classifier — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp44-mixed-recalibrate/PREREG.md` (23b179f) after a disclosed diagnostic (lab D singles 21/32 wrongly
flagged mixed with K4). Detector retrained on leave-one-family-out probabilities; EXP-16's bar and threshold rule.

### EXP-44 — RESULT (2026-10-02)
P44-1 falsified: best cross-validated catch 78.6% at 2.2% false flags (bar 80%), 28 mixed sessions only. Not shipped; the current
detector stays. Post-hoc for the owner: the near-miss candidate would answer 15/32 lab-D sessions (all right) instead of 11, letting
1/12 EXP-05 mixed sessions through. `experiments/exp44-mixed-recalibrate/RESULT.md`

## EXP-45 — More kinds of real traffic: lab E (training) and lab F (final test) — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp45-more-diversity/PREREG.md` (1acd160). Candidates K4/K7/K8/K9, mixed-check retraining with 92 mixed
sessions, ship rule fixed before any capture. Harness and scorer committed before capture (9477d65).

### EXP-45 — RESULT (2026-10-04)
Nothing ships. Held: P45-1 (+0.059 on the eight-family held-out mean, K8), P45-2 (lab F 0.724 vs shipped 0.603), P45-3 (interactive
0.75), P45-4 (83.7% caught / 7.6% flagged in cross-validation), P45-7 (16 of 16 mixed not answered). Failed: P45-5 (new check flags
32.6% of lab-F singles, bar 25%) and P45-6 (9 of 9 gated answers right but only 9 of 46 answered, bar 50%). The gate, not the
classifier, is the binding limit. Also found: the shipped model's gated answers on lab F are 4 of 6 right (11 of 11 on lab D).
`experiments/exp45-more-diversity/RESULT.md`

## EXP-50 — Per-vendor fix templates: Libreswan and MikroTik RouterOS (T-123) — PRE-REGISTRATION (2026-10-05)
`experiments/exp50-vendor-fixes/PREREG.md` before any template, test or lab run; addenda A-E each dated before the run it governs. 12 config rules x {Libreswan, MikroTik}; the five patch rules get no template. Bars: H1 every keyword documented, H2 Libreswan closed loop
(weak state FAIL on the wire, template applied as written, tunnel up, rule PASS, no PASS -> FAIL elsewhere), H3 RouterOS device check, H4 strongSwan plans byte-identical, H5 provenance on every template, H6 unknown vendor is an error.

### EXP-50 — RESULT (2026-10-05)
Libreswan 5.4: 12 of 12 (10 `lab`, 2 `lab-device-state` because the wire cannot show the weak state). RouterOS 7.24.4 CHR: 10 of 10 on the third run (8, 9 before; faults were in the templates), `lab-device-state`, no tunnel negotiated. 34 strongSwan plan hashes identical to the base.
Found by the labs, not by the documentation: RouterOS accepts `hash-algorithm=sha384` (page omits it); RouterOS refuses GCM next to `auth-algorithms=null` (an empty value works); Libreswan `ipsec replace` (not `ipsec auto`), `keyexchange=`; no post-quantum key exchange on RouterOS 7.24.4. DEC-058.
`experiments/exp50-vendor-fixes/RESULT.md`
## EXP-46 — SIEM export: Elastic ECS JSON and RFC 5424 syslog (T-129) — PRE-REGISTRATION (2026-10-02)
Pre-registered in `experiments/exp46-siem-export/PREREG.md` (991e939) before any code and any run; ADDENDUM A (cb1c69f)
before the run that counts. One event per verdict as ECS 9.5.0 JSON or RFC 5424 syslog, verified against Elasticsearch 9.5.4
and Filebeat 9.5.4 in Docker. Bars: every non-`tunnelscope.*` field valid against the official `ecs_flat.yml`; Elasticsearch
accepts everything with 0 errors and 0 `_ignored` fields; per-rule counts equal the CLI's independent `assess --json`; every
syslog line parses in a strict RFC 5424 parser and in Filebeat with no error and no field changed; no network code; output
deterministic.

### EXP-46 — RESULT (2026-10-02)
767 captures + the ten EXP-35 captures under the NIST profile: 11,290 verdict events + 3 alerts. H1 0 violations; H2 11,293
stored, 0 errors, 0 ignored; H3 0 differences over 73 rule/verdict pairs; H4 11,293 lines, Filebeat 0 errors and 0 differences;
H5 0 network imports, `assess` byte-identical to origin/main; H6 0 differences. Negative controls tripped (a malformed
`source.ip` is dropped silently by Elasticsearch; only `_ignored` shows it). 16 mutation checks caught. DEC-059.
`experiments/exp46-siem-export/RESULT.md`

## EXP-48 — Zeek and Suricata bridge (T-128) — PRE-REGISTRATION (2026-10-04)
`experiments/exp48-zeek-suricata/PREREG.md` before any code or scored run; addenda A-C dated before the scored run. `export --format zeek|eve`; bars H1 (real Zeek reader reads every
row back, hostile values included), H2 (EVE envelope equals Suricata's), H3 (join keys, misses explained), H4 (cross-check with Suricata's IKE algorithms, 0 undiagnosed), H5
(what the sensors cannot see, reported), H6 (no side effects).

### EXP-48 — RESULT (2026-10-04)
145 captures, Suricata 8.0.7 and Zeek 9.0.0 in Docker. H1 2,259/2,259 rows read back exactly; H2 0 violations in 2,246 lines; H3 150/150 by address pair, 130/150 by SPI pair (20 explained);
H4 125 of 126 SAs agree, 1 disagreement diagnosed (Suricata logs the retried offer's last transforms; TunnelScope right); H5 Zeek `service` empty on 235/235 IKE connections, no
KeyExchange payload visible in 18 Suricata CREATE_CHILD_SA events; H6 ecs/syslog byte-identical. DEC-061. `experiments/exp48-zeek-suricata/RESULT.md`
## EXP-47 — A FortiGate-VM (FortiOS 7.6.7) as an independent IKE implementation (T-118 step 2) — PRE-REGISTRATION (2026-10-03)
Pre-registered in `experiments/exp47-fortigate/PREREG.md` (28d7ed0) before any scored capture; addenda A-E before the runs they govern. A FortiGate-VM ARM64
(unlicensed, DES-only evaluation state) against a strongSwan peer on a virtual wire, 18 arms (10 IKEv2 suites, IKEv1 main and aggressive, FortiGate as
responder, three rekey arms, two failures), ground truth from the device's own diagnostics. Bar: every finding equals the device's report or is UNKNOWN, never wrong.

### EXP-47 — RESULT (2026-10-04)
H1 held (0 wrong handshake values in 16 arms; IKEv2 and IKEv1; DH groups 2-31). Predicted failures confirmed: IKE cipher DES printed as `encr-2` (14 IKEv2 arms), and the ESP
candidate set lacked the true DES-CBC+HMAC-SHA-2 family (12 arms). Fixed: names for IANA ids 1, 2, 4-9; three sieve families; after the fix all seven bars pass and nothing else moves
(corpus: 64 of 418 ESP findings gain the three families, 6 lose the "CBC excluded" refinement). D3 (`pfs=False` asserted when the IKE group is not visible, wrong on a mid-stream ECP-256 PFS capture) fixed on the owner's approval 2026-10-04: UNKNOWN there; 4 corpus records change as predicted (addendum F). Lab faults disclosed (stale peer config, handshake outside the capture). DEC-060.
`experiments/exp47-fortigate/RESULT.md`
## EXP-49 — Analysis throughput on one Mac (T-125) — PRE-REGISTRATION (2026-10-04)
`experiments/exp49-throughput/PREREG.md` before any measurement; addendum A (interleaved A/D check) dated before it ran. Window analysis only, synthetic ESP with ground truth, no live capture (no capture permission).
Bars: H1 exact packet accounting at every size, H2 loud timeout, H3 damaged file flagged, H6 product untouched; H4/H5 measured and derived; five predictions.

### EXP-49 — RESULT (2026-10-04)
Apple M4 / 16 GB / macOS 27.0.1. H1 15/15 exact up to 3x10^6 packets; H2 and H3 pass; 32-41 k packets/s = 0.36-0.46 Gbps represented per core; Python memory 1.24 KB/packet; P1-P5 held (P1 by a hair; machine not idle).
Capture-side drops are silent by code reading (T-165). DEC-062. `experiments/exp49-throughput/RESULT.md`

