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
