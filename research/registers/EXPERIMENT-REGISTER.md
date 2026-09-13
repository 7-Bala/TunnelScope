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
