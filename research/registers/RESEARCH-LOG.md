# Research Log

Format: Question -> Finding -> Evidence/Source -> Confidence -> Implication -> Decision affected.

---
**RL-001 — Is IKEv1 still current?**
Finding: No. RFC 9395 (Apr 2023) deprecates IKEv1 and moves RFC 2407/2408/2409 to Historic; it also deprecates RC5, IDEA, CAST, Blowfish, 3IDEA, ENCR_DES_IV64, ENCR_DES_IV32, and updates RFC 8221/8247 plus the IANA IKEv2 Transform Type registries (new "Status" column).
Source: RFC 9395 (datatracker/rfc-editor). Confidence: FACT.
Implication: Observing IKEv1 is itself a security finding. The IANA Status column gives us a machine-readable deprecation source for the rules engine.
Affects: security engine design; DEC-002.

---
**RL-002 — What are the current ESP/IKEv2 algorithm requirements?**
Finding: RFC 8221 (ESP/AH) and RFC 8247 (IKEv2), both 2017, both updated by RFC 9395. RFC 8247: RSA < 2048 SHOULD NOT be used; AES-GCM in IKEv2 kept at SHOULD, not MUST.
Source: RFC 8221, RFC 8247. Confidence: FACT.
Implication: These are the primary citation anchors for the compliance engine, alongside NIST SP 800-77 Rev 1 (2020).

---
**RL-003 — Does IKEv2 negotiate SA lifetimes?**
Finding: **No.** RFC 7296 §2.4: "there is no reason to negotiate and agree upon an SA lifetime." Lifetime is local policy on each peer.
Source: RFC 7296. Confidence: FACT.
Implication: PS requirement "key lifetime" (§D) cannot be read from IKEv2 traffic. Re-scoped to empirical measurement of observed rekey interval / bytes / packets between SPI changes. Contrast: IKEv1 Main Mode DOES carry lifetime attributes in plaintext.
Affects: Requirement re-scope table (01-DISCOVER §5); finding F-02.

---
**RL-004 — Where are the ESP cipher suite, mode, PFS and identities negotiated?**
Finding: Inside the ENCRYPTED IKE_AUTH and CREATE_CHILD_SA exchanges. IKE_SA_INIT (plaintext) carries only the IKE SA proposal, KE, nonces, CERTREQ and notifies.
Source: RFC 7296. Confidence: FACT.
Implication: The single most consequential finding of Discover so far (F-01). Most of PS §C cannot be *read*, only constrained or inferred, unless we add vantage point V3/V4.
Affects: DEC-002, DEC-003, entire architecture direction.

---
**RL-005 — Are published encrypted-traffic-classification accuracies trustworthy?**
Finding: Largely no. "SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers" (arXiv:2503.20093) finds the majority of proposed classifiers mistakenly used UNencrypted traffic due to legacy datasets, and 348 feature-occlusion experiments show design oversights causing overfitting. Recommends modern encrypted datasets, feature occlusion testing, empirical validation of assumptions.
Source: arXiv:2503.20093. Confidence: STRONG.
Implication: We must not cite SOTA accuracy numbers as our expected performance. Feature occlusion becomes a mandatory part of our validation plan.
Affects: R-02, R-08, validation design.

---
**RL-006 — Is ISCXVPN2016 usable for us?**
Finding: No. Reported ~98.9% unencrypted; covers only OpenVPN in UDP mode; 10 years old; documented data-integrity discrepancies in the VPN captures; imbalance and sampling bias. Contains no IPsec.
Source: multiple 2022-2025 papers incl. arXiv:2205.05628, arXiv:2202.11984, ScienceDirect S1574013725000577.
Confidence: STRONG.
Implication: There is no off-the-shelf IPsec-labelled dataset. We must generate our own; that becomes a genuine deliverable, not a chore.
Affects: OQ-09, dataset design.

---
**RL-007 — What IPsec analysis already exists in open source?**
Finding: (a) `corelight/zeek-spicy-ipsec` — Spicy-based Zeek analyzer supporting ESP, AH, IKEv1 and IKEv2, incl. ESP over UDP and TCP. (b) `ukncsc/zeek-plugin-ikev2` — parses IKE_SA_INIT, logging SPIs, cipher proposals, vendor IDs to ikev2.log. (c) Wireshark: IKEv2 decryption table, IKEv1 decryption table, ESP SAs preference with AEAD/ICV verification incl. AES-GCM. (d) ike-scan: discovery/fingerprinting/PSK-cracking, experimental IKEv2. (e) strongSwan/swanctl+vici: authoritative endpoint telemetry (vantage V3).
Source: project repos + zeek.org (2021) + Wireshark docs. Confidence: STRONG.
Implication: Parsing is SOLVED. Our contribution cannot be a parser. Note Zeek's own caveat: it will not see native ESP unless UDP/TCP-encapsulated in many deployments.
Affects: OQ-06, R-04, novelty claim.

---
**RL-008 — PQC readiness of IPsec.**
Finding: RFC 9370 (May 2023) adds multiple/hybrid key exchanges via IKE_INTERMEDIATE, up to 7 additional KEMs; RFC 8784 adds post-quantum PSKs.
Source: RFC 9370, RFC 8784. Confidence: FACT.
Implication: A 2026 analyzer should detect and assess PQ-readiness. Whether existing tools parse IKE_INTERMEDIATE is OQ-11 — if not, this is clean, current, defensible novelty.

---
**RL-009 — Contradiction watch.**
No source contradictions identified yet. Two tensions to monitor:
(1) RFC 8247 keeps AES-GCM at SHOULD for IKEv2 while operational guidance and CNSA push AEAD harder — our compliance engine must state WHICH authority each verdict comes from rather than merging them into one opinion.
(2) Vendor docs describe negotiated "lifetimes" in IKEv2 UIs, which conflicts with RFC 7296 §2.4; resolution: vendors expose local rekey policy, not a negotiated value. Adjudicated in favour of the RFC.

---
**RL-010 — What does Suricata already detect in IPsec/IKE?**
Finding: 14 shipped app-layer event rules, SIDs 2224000-2224013: malformed request/response, weak encryption, weak PRF, weak auth, weak DH, missing DH, missing auth, no encryption (AH-only), invalid proposal (req/resp), unknown proposal, multiple server proposals. IKE keywords: init_spi, resp_spi, chosen_sa_attribute, exchtype, vendor, key_exchange_payload(_length), nonce_payload(_length).
Source: docs.suricata.io IKE keywords; OISF/suricata rules/ipsec-events.rules. Confidence: FACT.
Implication: A meaningful slice of PS section D already exists in a mainstream IDS. Our contribution must be above the alert layer.

---
**RL-011 — Suricata IKEv2 keyword gap.**
Finding: chosen_sa_attribute supports for IKEv1: alg_enc, alg_hash, alg_auth, alg_dh, alg_prf, sa_group_type, sa_life_type, sa_life_duration, sa_key_length, sa_field_size. For IKEv2 only: alg_enc, alg_auth, alg_prf, alg_dh. No sa_key_length, no lifetime.
Source: docs.suricata.io. Confidence: FACT (documented); empirical confirmation = OQ-15.
Implication: Suricata cannot match AES key length for IKEv2 even though the plaintext transform attribute exists. Concrete implementable gap (not a physical limit). Lifetime gap mirrors RFC 7296 reality (RL-003).

---
**RL-012 — Suricata bug #2861: the weak-DH rule silently failed.**
Finding: sid 2224005 did not alert on modp1024. Three causes (Chifflier): (a) deliberate flow:to_client filter, so weak CLIENT proposals were never alerted; (b) wrong event names in the rules file (fixed in PR #3702); (c) a transaction-handling logic bug causing events raised in the FIRST IKEv2 message to be ignored. Also documented: with multiple chosen SAs only the FIRST is used; events fire at most once per connection.
Source: redmine.openinfosecfoundation.org/issues/2861. Confidence: FACT.
Implication: DESIGN LESSON DL-01 — all three failures are evidence-handling failures. An alert model is the wrong abstraction for posture assessment; build a complete per-SA bidirectional evidence record and reason afterwards. This is a citable argument that our system is not "Suricata rules with a dashboard."

---
**RL-013 — Practitioner corroboration of F-01 (independent of the RFC).**
Finding: Palo Alto guidance on NO_PROPOSAL_CHOSEN: "This encryption mismatch won't be visible in a packet capture unless the pcap is manually decrypted, so it's best to use CLI commands or check both sides' configurations manually." Cisco/Fortinet: "Phase 2 can only complete after Phase 1 because all packets are encrypted, which complicates debugging."
Source: vendor KBs, multi-vendor. Confidence: STRONG (independent corroboration of a FACT derived from RFC 7296).
Implication: F-01 now has two independent source classes (spec + operations). Also reveals unmet need J1: the dominant real-world task is diagnosing WHY a tunnel did not come up, and industry's answer is to abandon the capture. Concept seed CS-02.

---
**RL-014 — The operational failure taxonomy.**
Finding: consistent across Cisco/Fortinet/PaloAlto/F5: Phase-2 proposal mismatch; traffic-selector mismatch (TS_UNACCEPTABLE); PFS mismatch causing flap at every rekey; lifetime mismatch; simultaneous-rekey race when both peers share identical Phase-2 lifetimes (remedy: stagger by 60-300s). Blast radius includes BGP peering drops.
Source: vendor KBs. Confidence: STRONG.
Implication: Each mode has a distinct STRUCTURAL signature observable at V0/V1 even though the reason is encrypted (SPI churn, rekey periodicity, IKE_AUTH-then-delete, retransmission bursts). Ground truth is free from a testbed. Concept seeds CS-02, CS-03.

---
**RL-015 — Active IKE tooling is stuck in the IKEv1 era.**
Finding: ike-scan IKEv2 support experimental, "only tested against strongSwan"; backoff fingerprinting fails under ANY packet loss and cannot fingerprint hosts replying with a notify; GPL-3.0; 19 open issues. Nmap ike-version: "very limited response parser - currently only the VIDs are extracted"; backoff analysis listed as never-implemented future work; fails entirely if no known Vendor ID.
Source: royhills/ike-scan README; nmap.org NSE docs. Confidence: FACT.
Implication: Gap G-07. In 2026, with IKEv1 Historic (RFC 9395) and DISA mandating IKEv2, there is no mature open-source active IKEv2 posture prober.

---
**RL-016 — The credibility crisis in encrypted traffic classification.**
Finding: "Sweet Danger of Sugar" (2025): ET-BERT drops from ~98% claimed to 10.9% under per-flow splits with frozen encoders; all deep models <=40% on complex tasks; randomizing pretrained weights yields nearly identical downstream performance; per-packet splitting leaks flow identity via TCP seq/timestamps; Random Forest on hand-engineered header features reaches 82.0% vs 71.0% for the best representation model on TLS-120. Authors call it a "credibility crisis". Corroborated by SoK arXiv:2503.20093 (majority of classifiers used UNENCRYPTED traffic) and by pretraining/downstream dataset reuse in ET-BERT/YaTC/NetMamba.
Source: arXiv:2507.16438, arXiv:2503.20093. Confidence: STRONG.
Implication: Pretrained traffic transformers are REJECTED as a core engine. Protocol-informed features + shallow models is the evidence-backed choice ("Less is More", arXiv:2502.00586, reaches the same conclusion constructively).

---
**RL-017 — Length side channels genuinely work (the positive result).**
Finding: Wright et al., "Spot Me If You Can" (IEEE S&P 2008): packet LENGTHS alone identify spoken phrases in encrypted VoIP under VBR + length-preserving encryption; ~50% average, >90% for some phrases. Prompted RFC 6562.
Source: oakland08 paper; RFC 6562. Confidence: FACT.
Implication: The metadata channel through ESP is real and citable at the highest tier. Foundation for CS-01.

---
**RL-018 — A mature methodology exists for QUANTIFYING leakage.**
Finding: Cherubin (PETS 2017) estimates the Bayes Error Rate - the smallest error achievable by ANY adversary - via nearest-neighbour error, giving an adversary-independent lower bound. WeFDE (Li/Guo/Hopper, CCS 2018) measures leakage in BITS via mutual information per feature. DeepSE-WF unifies BER + MI. Core position of that community: classification accuracy is NOT a valid metric for evaluating a defence.
Source: arXiv:1702.07707, wefde-ccs2018, arXiv:2203.04428. Confidence: STRONG.
Implication: KEY INSIGHT. This methodology has apparently never been applied to IPsec deployment posture. Transplanting it gives us a rigorous, quantitative "metadata exposure" score (PS section D/E) and makes the ML component necessary AND immune to the credibility crisis - because the classifier becomes a measuring instrument, not a truth oracle, and a LOW score is a GOOD security result. Concept seed CS-01, gap G-04.

---
**RL-019 — Standards-backed remediations exist and are testable in our own lab.**
Finding: RFC 4303 sec 2.7 TFC padding; next-header 59 mandated for dummy packets. strongSwan tfc_padding default = 0 (DISABLED), special value 'mtu'. RFC 9347 (Jan 2023) AGGFRAG/IP-TFS: constant-send-rate, fixed-size ESP tunnel aggregating multiple inner packets, "expected to reduce the efficacy of traffic analysis"; strongSwan supports mode = iptfs. IETF list discussion treats TFC as an emerging research area, not deployed technology.
Source: RFC 4303, RFC 9347, docs.strongswan.org, IETF ipsec archive. Confidence: FACT.
Implication: We can measure leakage with tfc_padding=0 vs mtu vs mode=iptfs, holding everything else constant. Quantified, standards-mapped, reproducible. OQ-17: nobody appears to have published this measurement.

---
**RL-020 — strongSwan defaults relevant to the testbed and the security engine.**
Finding: tfc_padding=0; replay_window=32 (0 disables); mode default=tunnel (options tunnel/transport/iptfs/beet/pass/drop); rekey_time default 1h (or life_time/1.1); life_time = 1.1*rekey_time; rand_time default = over_time, subtracted to PREVENT simultaneous peer rekeying; mobike=yes; fragmentation=yes; dpd_delay=0s.
Source: docs.strongswan.org swanctl.conf. Confidence: FACT.
Implication: rand_time explains why strongSwan avoids the rekey race that PE-02 documents for other vendors - an implementation-difference finding our fingerprinting work can exploit. These are the testbed's control knobs.

---
**RL-021 — A citable government control set exists (DISA VPN SRG V2R6).**
Finding: V-207205 must use IKEv2; V-207193 DH group 16 or greater for IKE Phase 1; V-207223 FIPS-validated SHA-2 at 384+ for IKE; V-207230 AES for the IKE proposal; V-207192 SHA-2 384+ for integrity; V-207212 must use anti-replay mechanisms; V-207184 ESP in tunnel mode.
Source: DISA Virtual Private Network (VPN) Security Requirements Guide V2R6. Confidence: FACT.
Implication: Findings can be traced to government rule IDs - high credibility for an NTRO statement. CONTRADICTION C-2: DISA demands group >=16 while RFC 8247's mandatory baseline is group 14. Not an error - different risk tiers. Forces multi-baseline architecture (S-02). Also: V-207212 anti-replay CANNOT be assessed passively (A13) - a named government control that requires endpoint telemetry or an active test. This is decisive evidence for DEC-005.

---
**RL-022 — Dataset landscape: nothing usable exists.**
Finding: No public dataset contains IPsec traffic labelled with cryptographic configuration. ISCXVPN2016 = OpenVPN/UDP only, ~98.9% unencrypted, integrity discrepancies, 10 years old. VNAT (MIT LL) = 165 pcaps / 36.1 GB / 33,711 connections / ~272h / 10 apps, but not IPsec-config-labelled. CIC family heavily criticised (Engelen 2021; Liu 2022; Lanvin 2023: packet misordering, duplicate flows, undocumented capture gaps, labelling errors that materially change results). Kaggle mostly hosts derived CIC CSVs.
POSITIVE FIND: wireshark/test/captures contains algorithm-labelled IKE/ESP pcaps - ikev2-decrypt-{3des-sha1_160, aes128ccm12, aes128ccm12-2, aes192ctr, aes256cbc, aes256ccm16}, ikev1-certs, ikev1-bug-12610/12620, esp-bug-12671 - plus a Wireshark-wiki Cisco-to-Cisco IKEv2 AES-256-GCM/DH-19 sample.
Source: multiple. Confidence: FACT / STRONG.
Implication: OQ-09 CLOSED. Dataset generation is required and is itself a first-of-its-kind contribution (G-11). The Wireshark corpus is adopted as a third-party validation oracle for the F-04 sieve - immunising it against "you only tested on your own traffic".

---
**RL-023 — Reproducible testbed prior art.**
Finding: ConCap (isolated per-scenario environments with AUTOMATIC labelling), NetSecBed (container-native pipeline automating execution, capture, log collection, probing, feature extraction, dataset consolidation), Gotham Testbed (capture on any link; network + host sources), Clausen et al. containerised generation for ML.
Source: arXiv:2509.16038, arXiv:2604.04121, arXiv:2207.13981, ACM 3464458.3464460. Confidence: STRONG.
Implication: Patterns to copy. OUR ADVANTAGE: those frameworks must INFER attack labels; we COMMAND our labels (config is an input) and CONFIRM them from strongSwan's own SA state. Ground truth is constructed and independently verified - an unusually strong epistemic position. DL-04.

---
**RL-024 — Contradiction: the common "two IP headers" advice.**
Finding: Ubiquitous guidance says to distinguish tunnel from transport mode by looking for two IP headers in the capture. This is only true AFTER decryption; the inner header is ciphertext at V0/V1.
Source: multiple vendor/tutorial pages. Confidence: FACT (by inspection of RFC 4303).
Implication: C-4. A concrete illustration of the expert-knowledge tax and of how widely-repeated advice silently assumes key access.

---
**RL-025 — Negative result worth recording.**
Finding: No published measurement of ESP's share of real backbone traffic was found in CAIDA/MAWI-based literature.
Confidence: UNKNOWN (absence of evidence).
Implication: We cannot make claims about IPsec prevalence. OQ-22.

---
**RL-026 — CORRECTION: multi-flow encrypted traffic classification DOES exist.**
Finding: I overstated G-12. Chen, Cheng, Wei, Niu & Fu, "Classify Traffic Rather Than Flow: Versatile Multi-Flow Encrypted Traffic Classification With Flow Clustering", IEEE TNSM 21(2) 2024, 1446-1466, explicitly names multiplexed streams ("traffic that passes through a tunnel may contain several applications that share the same 5-tuple") and proposes TSHC-SW clustering plus five multi-flow schemas; reports 95% ARI / 98% purity clustering and >99% F1. Also GRAIN (classifier chains), MFSI (Computer Networks 2025), MLP-Mixer multi-label.
Source: IEEE TNSM 10.1109/TNSM.2023.3322861 and related. Confidence: FACT (existence), STRONG->discount (the accuracy numbers, per RL-016).
Implication: G-12 REVISED. The technique family exists but its input assumption fails at our vantage: those methods cluster individually-visible flow objects; inside ESP tunnel mode the flows are SUPERPOSED into one SPI and there are no flow objects to cluster. Narrower but still real gap. We must CITE this work, not claim it is absent.

---
**RL-027 — RFC 9370 / IKE_INTERMEDIATE is implemented in strongSwan and NOT decoded by Wireshark.**
Finding: (a) RFC 9242 defines the IKE_INTERMEDIATE exchange; RFC 9370 defines Additional Key Exchange (ADDKE) transforms, up to 7 additional key exchanges, negotiated in plaintext IKE_SA_INIT and carried in IKE_INTERMEDIATE between IKE_SA_INIT and IKE_AUTH. (b) strongSwan 6.0.0 (Dec 2024) supports RFC 9370 and ML-KEM (FIPS 203) via Botan 3.6.0+ or the oqs plugin/liboqs; proposal syntax e.g. x25519-ke1_mlkem768. (c) Wireshark GitLab issue #21072: "IKEv2 dissector does not display updated field names from RFC 9370"; does not decode PQC algorithms such as ML-KEM-1024; IKE_SA_INIT with ML-KEM-1024 fails to display in Wireshark 4.6.3; repro capture ipsec_mlkem.pcap attached.
Source: RFC 9242, RFC 9370, strongswan.org 6.0.0 release notes, gitlab.com/wireshark/wireshark/-/work_items/21072. Confidence: FACT.
Implication: G-08 upgraded from "no positive evidence" to a CONFIRMED, CITABLE tool gap. We can generate hybrid PQ IPsec traffic in our own testbed that the leading protocol analyzer cannot decode. Observability is O (plaintext IKE_SA_INIT), requires ZERO AI, and supports downgrade/fallback detection (proposed vs selected transforms are both visible). Concept seed CS-05.

---
**RL-028 — India has a dated national mandate that this capability serves.**
Finding: DST, "Implementation of Quantum Safe Ecosystem in India - Report of the Task Force", February 2026, under the National Quantum Mission, chaired by the CEO of C-DOT. Milestone 1 (CII by 2027, enterprises by 2028): "Inventory cryptographic assets and assess quantum risk"; CBOM adoption in procurement; "mandate CBOM submissions from vendors starting FY 2027-28". Names "Interoperability During Transition: Coexistence of classical and quantum-safe cryptography increases complexity and introduces risks of DOWNGRADE OR INSECURE FALLBACK"; "Assurance and Validation Gaps: Independent validation is critical to ensure correct implementation and PREVENT REVERSION TO VULNERABLE CRYPTOGRAPHY"; "Continuous Assurance: Independent validation, monitoring"; "Contingency Planning: Prepare interim quantum-safe solutions (e.g., proxies, TUNNELS, VPNs, GATEWAYS, QRNG, TRNG)". Medium-term: "validate migration through independent testing", "establish national testbeds". CBOM defined as "a detailed inventory of cryptographic components and configurations used by a system, including algorithms, modes of operation, key sizes, protocols, libraries, random number generators, and cryptographic parameters, covering both classical and quantum-safe cryptography". Operates under an "assume breach" principle recognising Harvest Now Decrypt Later.
Source: dst.gov.in Report_TaskForce_PQMigration_4Feb26. Confidence: FACT (primary government document).
Implication: The strongest policy alignment available for an NTRO problem statement. The Task Force's CBOM definition is close to a restatement of PS section C; its named "downgrade or insecure fallback" risk is exactly what CS-05 detects; its "prevent reversion to vulnerable cryptography" is exactly the assurance function. Also connects HNDL to why PFS and PQ key exchange matter now - which makes the PS's PFS requirement policy-relevant rather than academic.
