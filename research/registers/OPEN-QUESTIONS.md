# Open Questions Register

| ID | Question | Why it matters | Resolution method | Blocks | Status |
|---|---|---|---|---|---|
| OQ-01 | Does the ESP length-residue sieve (F-04) reliably narrow cipher-suite family? | Decides whether A5 is I or N at V0 | Testbed experiment across all suites | GATE-1 | OPEN |
| OQ-02 | Can AES-128 vs AES-256 be separated at V0 by ANY channel? | Confirms F-05 impossibility; a publishable negative result | Deliberate falsification attempt | GATE-1 | OPEN |
| OQ-03 | Is PFS inferable from encrypted CREATE_CHILD_SA message length? | Novel capability if yes; honest gap if no | Testbed: PFS on/off, same everything else | GATE-1 | OPEN |
| OQ-04 | Does any credible work handle tunnel-mode MULTI-FLOW mixtures? | Determines whether inner-traffic ML is research or theatre | Literature search | GATE-3 | OPEN |
| OQ-05 | Is auth method inferable from CERTREQ / SIGNATURE_HASH_ALGORITHMS presence? | Adds A8 at V1 | Testbed: PSK vs cert vs EAP | GATE-1 | OPEN |
| OQ-06 | Exactly what do zeek-spicy-ipsec + zeek-plugin-ikev2 already extract? | Decides build vs reuse; sets novelty claim | Install, run on our captures, diff vs Observability Matrix | GATE-2 | OPEN |
| OQ-07 | Do Suricata / commercial NDR already produce IPsec posture findings? | Duplication risk | Docs + rule review | GATE-2 | OPEN |
| OQ-08 | Who actually performs IPsec posture assessment, and in which team? | Product shape (forensic vs monitor vs auditor) | Practitioner contact; else documented proxies + labelled inference | GATE-3 | OPEN |
| OQ-09 | Is there ANY public IPsec capture set with configuration labels? | Determines dataset build cost | Dataset survey D5 | GATE-3 | OPEN |
| OQ-10 | What scoring methodologies are defensible (CVSS-style rationale, NIST mappings)? | Prevents an invented "87/100" | Standards + scoring-methodology review | GATE-4 | OPEN |
| OQ-11 | Do current tools handle RFC 9370 IKE_INTERMEDIATE / hybrid PQ key exchange? | Possible clean novelty for 2026 | Wireshark/Zeek source + release notes | GATE-2 | OPEN |
| OQ-12 | Team size, skills, hardware, and deadline? | Sizes the whole plan | ASK THE USER | GATE-4 | **NEEDS USER** |
| OQ-13 | Is an authorized active-probe capability (V5) in scope, or passive-only? | Unlocks A13 replay enforcement; adds ethical/scope burden | ASK THE USER + NTRO statement re-read | GATE-4 | **NEEDS USER** |
| OQ-13 | Passive-only vs active? | Architecture-defining | RESOLVED BY EVIDENCE | — | **CLOSED → DEC-005** |
| OQ-09 | Any IPsec-config-labelled public dataset? | Dataset build cost | Survey complete | — | **CLOSED — none exists (G-11)** |
| OQ-14 | SIH IP/licensing expectations for submitted deliverables? | Affects which GPL components we may bundle | SIH guidelines / SPOC | GATE-5 | OPEN |
| OQ-15 | Verify empirically that Suricata cannot match IKEv2 sa_key_length despite the plaintext attribute | Confirms a concrete implementable gap | Run Suricata on our IKEv2 captures | GATE-2 | OPEN `[EXP]` |
| OQ-16 | Confirm the problem-statement ID: report.md says SIH26160, one public index suggests SIH26161 | Submission correctness | Check the official portal | Submission | OPEN |
| OQ-17 | How many BITS of leakage do tfc_padding and IP-TFS (RFC 9347) actually remove? | Nobody has published this; it is a headline result if we measure it | Testbed + MI/BER estimation | — | OPEN `[EXP]` **high value** |
| OQ-18 | Does WF security-estimation methodology (BER/MI) transfer soundly when classes are MIXTURES (tunnel-mode multiplexing)? | Determines whether CS-01 is rigorous or hand-wavy in the realistic case | Literature + derivation + experiment | GATE-5 | OPEN |
| OQ-19 | Does conformal prediction give useful set sizes at our feature dimensionality, or degenerate to "all classes"? | Determines the confidence-score mechanism | Experiment | — | OPEN |
| OQ-20 | Licensing of Wireshark/Zeek test captures for redistribution in our dataset | Affects dataset deliverable | Check repo licences | — | OPEN |
| OQ-21 | Realistic capture-volume ceiling on available hardware; does the covering array fit? | Sizes the testbed | Measure once testbed exists | — | OPEN |
| OQ-22 | Any published measurement of ESP's share of backbone traffic? | Would let us state IPsec prevalence; currently we cannot | Searched CAIDA/MAWI lit, found none | — | OPEN (likely UNKNOWN) |
| OQ-23 | Which stakeholder role does NTRO represent? | Prioritisation, not architecture | PS re-read; mentor | — | OPEN |
| OQ-24 | Are there Indian-government IPsec/crypto baselines (CERT-In / MeitY / STQC) to encode alongside NIST and DISA? | High presentational value for an NTRO statement | One more focused pass | GATE-4 | OPEN |
| OQ-25 | Do arXiv:2507.09288 (Hybrid Quantum Security for IPsec) and arXiv:2510.19968 (Q-RAN) already build PQ-IPsec OBSERVABILITY/assessment, or only implementation/performance studies? | Determines whether CS-05's novelty claim survives | Read both | GATE-5 | OPEN **must resolve before claiming novelty** |
| OQ-26 | Do Zeek (spicy-ipsec) and Suricata handle IKE_INTERMEDIATE / ADDKE transforms? | Completes the G-08 gap picture | Read the Spicy grammar and Suricata IKE parser source | GATE-2 | OPEN |
| OQ-27 | Is a fix for Wireshark issue #21072 in flight? If it merges before SIH, part of CS-05's novelty evaporates | Novelty durability | Watch the issue + merge requests | ongoing | OPEN |
| OQ-04 | Multi-flow/multiplexed ETC prior art | — | Literature pass done | — | **CLOSED — prior art EXISTS (RL-026); G-12 narrowed, not removed** |
| OQ-11 | Does any tool parse RFC 9370 IKE_INTERMEDIATE? | — | Wireshark issue #21072 | — | **CLOSED for Wireshark: NO. Zeek/Suricata → OQ-26** |
| OQ-24 | Indian government crypto baselines | — | DST/NQM Task Force report found | — | **CLOSED — DST Feb 2026 Task Force report is the anchor (RL-028)** |
| OQ-28 | Licence of github.com/hypergalois/pqc-tls-observability — can we adopt its JSON schema shapes and registry pattern? | Engineering head start + citation | Check repo | GATE-5 | OPEN |
| OQ-29 | Can PQ key exchange be detected from KE payload LENGTH alone, without transform-ID decoding? | Would work despite Wireshark #21072; cheapest early experiment in the project | Suricata rule on ike.key_exchange_payload_length + strongSwan x25519-ke1_mlkem768 | GATE-1 | **OPEN — DO THIS FIRST** (see PQ-6) |
| OQ-26 | Do Zeek/Suricata handle IKE_INTERMEDIATE/ADDKE? | — | Source read 2026-09-11 | — | **CLOSED — NO for Zeek spicy-ipsec, Suricata/ipsec-parser, nDPI; no ADDKE in Arkime; YES Wireshark master (RL-029/030)** |
| OQ-27 | Is a fix for Wireshark #21072 in flight? | — | GitLab API | — | **CLOSED — fixed 2026-03-14; naming on master, partial in 4.6.4 (RL-029)** |
| OQ-30 | Does Palo Alto's Quantum Readiness view assess THIRD-PARTY IPsec passing through the firewall, or only its own tunnels? | Decides whether a commercial product already covers fleet-wide IPsec PQ assessment | Palo Alto docs / a demo / practitioner | GATE-5 | OPEN |
| OQ-31 | Is the CVE-2026-78135 pattern passively detectable? | A CVE-backed capability no tool has | EXP-09 | — | **PARTIAL — detector designed, 0 FP on 69 captures, vantage-aware UNKNOWN handling; TP validation needs a malicious IKE stack (deferred)** |
