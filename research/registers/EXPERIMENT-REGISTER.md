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
