# SIH26164 — ECDAT decision report

**Prepared:** 29 August 2026  
**Problem:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)  
**Organization:** National Technical Research Organisation (NTRO)  
**Category/theme:** Software; Blockchain & Cybersecurity  
**Source:** [SIH 2026 decision page](https://skt.kumaraguru.in/sih2026-review/decide.html)

## Executive decision

ECDAT is a strong problem statement for a team with cybersecurity, program-analysis, DevSecOps and applied-cryptography capability. It is attractive because the first step of post-quantum migration is still a practical visibility problem: organizations cannot prioritize what they cannot locate. It is also unusually well aligned with the NIST NCCoE cryptographic-discovery workstream.

The main warning is scope. A credible enterprise product cannot truthfully promise to discover **all** cryptography from source code, binaries, libraries, containers, cloud services, certificates, protocols, HSMs and hardware in a hackathon prototype. The best competitive strategy is a defensible, read-only MVP with explicit confidence, provenance and “not observable” outcomes, followed by a roadmap for deeper integrations.

**Recommendation: pursue, with a scope-controlled MVP.** Do not build a generic dashboard or claim complete enterprise coverage.

## What the official statement asks for

The page describes four related capabilities:

1. Discover and catalogue algorithms, keys, certificates, protocols, libraries, hardware modules and cloud services across internal and externally facing applications, products and infrastructure.
2. Assess quantum risk and identify systems exposed to future quantum attacks and sensitive-data exposure.
3. Classify artefacts by type, lifetime and business criticality, using a structured method such as Mosca’s inequality: data lifetime plus migration time compared with the expected arrival of a cryptographically relevant quantum computer.
4. Recommend PQC or hybrid alternatives based on risk, latency, cost and related constraints.

Expected deliverables are a CBOM-style report covering cryptographic assets and versions/modes, plus an interactive GUI visualizing scan results and risks. The supplied dataset link points to standard open-source source-code and library datasets, such as GitHub and OpenSSL.

## Verified competition context

The page currently exposes 22 statements when the theme is filtered to Blockchain & Cybersecurity: 20 software and 2 hardware. Their displayed complexity distribution is 1 Starter, 5 Moderate and 16 Advanced. These are counts of statements, **not counts of teams or people**.

The page stores shortlist state only in the user’s local browser. The visible “0 shortlisted” value therefore is not a site-wide popularity metric. I found no public per-statement submission count, team count or vote count. Consequently, the number of people who will choose ECDAT cannot be known from this site and should not be presented as a fact.

### Competition estimate — low confidence

ECDAT should attract above-average interest from cybersecurity, CSE and DevSecOps teams because it has a timely quantum-readiness narrative, a clear government sponsor and a buildable software demo. Its specialist requirements reduce the number of teams able to execute it convincingly. My qualitative estimate is **medium-to-high interest but lower-than-average execution quality**: many teams may select it, while relatively few will produce reliable cross-language, binary and infrastructure discovery with evidence-backed risk scoring. The estimate is a judgment, not a measured headcount.

For planning, use scenarios rather than a fabricated total:

| Scenario | Interpretation |
|---|---|
| Low selection pressure | A few specialist teams; differentiation depends on detection quality and reproducible evaluation |
| Medium selection pressure | Several teams build dashboards around scanners; provenance, coverage and false-positive handling become decisive |
| High selection pressure | Many teams reuse CBOM/scanner components; a novel evidence graph, calibrated confidence and migration validation are required |

## Complexity assessment

Although the portal labels ECDAT **Starter**, the requested product is realistically **Advanced overall**. A narrow source-repository MVP is Starter-to-Moderate; an enterprise-grade implementation is Advanced.

| Dimension | Assessment | Why |
|---|---|---|
| Source-code discovery | Moderate | Algorithms may be direct API calls, wrappers, configuration values, generated code or language-specific abstractions |
| Dependency/library discovery | Moderate | Requires package and binary metadata, version resolution and transitive-dependency correlation |
| Binary/container discovery | Advanced | Stripped binaries, static linking, compiler optimization and custom implementations reduce certainty |
| Certificates/protocols/edge services | Moderate-to-Advanced | Requires authenticated or network-observable scans and careful handling of exposure boundaries |
| Key and HSM inventory | Advanced | Key material must never be collected; metadata often requires privileged connectors and vendor-specific APIs |
| Business criticality/data lifetime | Advanced | Technical scanning cannot infer these reliably without asset-owner or CMDB context |
| Quantum-risk scoring | Moderate | The formula is straightforward; choosing defensible inputs and communicating uncertainty is difficult |
| Recommendations | Advanced | A safe replacement depends on protocol, interoperability, performance, compliance and lifecycle constraints |
| CBOM/reporting | Moderate | The format is manageable; maintaining accurate relationships and provenance is the hard part |

**Estimated implementation effort:** a polished hackathon MVP is feasible in 36–48 hours with a deliberately bounded scope. A production platform requires months of connector, parser, permissions, test-corpus and governance work.

## Existing solutions and where they fall short

There is already a substantial solution landscape. That is good evidence of real demand, but it means ECDAT must differentiate on integration, transparency and evaluation—not merely “scan files and show a chart.”

| Existing solution/category | What it already does | Gap an ECDAT prototype can address |
|---|---|---|
| NIST NCCoE migration/discovery practice | Demonstrates that discovery needs multiple views across code, binaries, dependencies and network-facing services; discusses CBOM-like inventories and PQC migration | It is a reference architecture and practice guide, not a single easy-to-deploy product for a small Indian enterprise or evaluator |
| CodeQL and static-analysis workflows | Finds crypto API use and vulnerable patterns in source repositories and CI pipelines | Static analysis misses runtime behavior, compiled-only dependencies, remote services and cryptography hidden behind wrappers or custom code |
| `pqcscan`, `sslscan2`, certificate transparency/`crt.sh` and similar utilities | Useful edge and TLS/SSH visibility | Each sees a narrow surface; they do not produce one business-aware asset graph or migration backlog |
| CryptoScan and similar open-source scanners | Source discovery, quantum-risk tagging, readiness scoring and CBOM export | Coverage and accuracy vary by language and pattern; source-only findings do not prove deployed behavior or business criticality |
| CipherFlag and CBOM generators | Inventory certificates, keys, algorithms, libraries and protocols; export structured CBOMs and map to frameworks | Often environment-specific or endpoint-focused; broad enterprise correlation, provenance, uncertainty and owner workflow remain difficult |
| AWS CryptaMap | Cloud-specific discovery across many AWS service categories with CBOM and migration-roadmap outputs | AWS-specific; it does not solve multi-cloud, on-premises, source, binary and organizational-ownership correlation by itself |
| Commercial platforms such as SandboxAQ AQtive Guard, Keyfactor AgileSec, Cisco Mercury and Tychon | Broader enterprise inventory and migration-management capabilities | Licensing, deployment complexity, opaque scoring and access constraints create room for a transparent, local-first educational/prototype tool |

The NIST FAQ explicitly lists several of these tools and collaborators and says the list is non-exhaustive. It also identifies the central limitation: a cryptographic inventory is a descriptive record, and it must be correlated with systems, applications, data sensitivity, ownership and lifecycle information.

### Common failure modes of existing approaches

- **False completeness:** a scanner reports “no finding” when it simply could not see a dynamic call, encrypted configuration, remote service or proprietary module.
- **Pattern dependence:** source scanners identify known APIs and strings but miss wrappers, reflection, generated code, custom implementations and indirect dependencies.
- **Binary uncertainty:** detecting a crypto library or primitive in a binary does not always establish which code path is active, for what purpose or with what parameters.
- **Weak business context:** algorithm strength alone does not determine priority. Data sensitivity, retention period, exposure, owner, replacement feasibility and migration time matter.
- **Unsafe key handling:** collecting private key material would create a serious security risk. A correct product inventories metadata and fingerprints, never secret material.
- **Recommendation overreach:** ML-generated “replace RSA with X” advice can break interoperability, compliance, performance or protocol semantics. Recommendations must be rules-based, versioned and reviewable.
- **CBOM ambiguity:** an asset list without relationships, source location, scan time, tool version, evidence and confidence is difficult to trust or act on.
- **Operational friction:** tools requiring broad privileged access are hard to deploy and can be rejected by security teams before producing value.

## Proposed differentiated MVP

Build a local-first, read-only scanner and evidence graph for a controlled corpus:

1. **Inputs:** Git repositories, lockfiles, container images and a small set of TLS/SSH endpoints. Include a synthetic enterprise dataset so evaluation is reproducible.
2. **Detectors:** language-aware crypto API rules, configuration/certificate parsers, dependency resolution, container-layer inspection and TLS/SSH capability probes.
3. **Evidence model:** every finding records exact file/line or binary/library evidence, detector, timestamp, package/version, confidence and limitations.
4. **CBOM:** emit CycloneDX-compatible cryptographic components and relationships where possible; preserve an explicit `unknown` state instead of guessing.
5. **Risk:** separate algorithmic quantum posture from business priority. Let the user enter data lifetime, migration time, sensitivity, exposure and criticality; calculate and explain the result.
6. **Recommendations:** maintain a versioned ruleset mapping use cases to candidate NIST-standardized or hybrid options, with compatibility and human-review warnings.
7. **GUI:** show coverage, findings, confidence, evidence, risk rationale, affected owners and an exportable migration queue—not only a risk heatmap.

### Demo acceptance tests

- Detect RSA/ECDSA/DH and selected TLS certificate uses in at least three languages and one compiled/containerized sample.
- Distinguish a direct API call, a dependency-only presence and an actually observed network protocol finding.
- Correctly report a negative scan as “not observed in scanned scope,” never “absent from the enterprise.”
- Never read or export private-key material; test this with seeded secret files.
- Produce deterministic CBOM output with scan provenance and stable identifiers.
- Change risk ranking when data lifetime, criticality or migration time changes, and explain why.
- Mark unsupported language, binary or service surfaces as coverage gaps.
- Validate recommendations against a small compatibility matrix and require reviewer approval before suggesting a production change.

## Suggested judging and team-choice score

| Factor | Weight | ECDAT view |
|---|---:|---|
| Real-world importance | 20% | 5/5 — PQC migration and crypto visibility are recognized enterprise concerns |
| Technical feasibility of a demo | 20% | 4/5 if scope is bounded; 2/5 if “all enterprise crypto” is attempted |
| Differentiation potential | 15% | 3/5 by default; 5/5 with evidence/confidence/coverage graph and reproducible benchmark |
| Availability of public data | 10% | 3/5 — synthetic and open-source corpora are possible, but enterprise ground truth is scarce |
| Demo clarity | 15% | 5/5 — before/after inventory and prioritized migration queue can be compelling |
| Security and correctness risk | 10% | 2/5 — false negatives, false positives and unsafe key handling are serious concerns |
| Team fit | 10% | depends entirely on static analysis, crypto and DevSecOps experience |
| **Overall** | **100%** | **4.0/5 for a suitably skilled team; 2.5/5 for a generalist team** |

## Final verdict

Choose ECDAT if the team can demonstrate technical depth and disciplined scope. The problem has real institutional relevance, a strong evaluation narrative and clear pathways to a useful prototype. Do not choose it merely because the portal calls it Starter or because a dashboard looks impressive.

The winning thesis should be: **“We can show exactly where cryptography was found, how certain we are, why the risk is prioritized, what cannot be seen, and which migration action is safe to investigate next.”** That directly addresses the weaknesses of existing fragmented scanners and avoids an unverifiable claim of complete enterprise discovery.

## Portfolio report: all 22 Blockchain & Cybersecurity statements

This section covers every statement returned by the live site filter. The “official requirement digest” is a faithful compression of the page’s Background, Description and Expected Solution text; it is not a replacement for the official wording. Complexity and selection views are analytical assessments.

### SIH26019 — National Digital Platform for Research, Policy Innovation, and Evidence-Based Land Governance

**Organization:** Ministry of Rural Development · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Build a secure, scalable, AI-enabled national platform combining land-governance datasets, research, policy documents, legal material, case studies, satellite/GIS data and collaborative workspaces. The requested capabilities include AI search and recommendations, GIS visualization, policy analytics and simulation, research assistance, innovation/grant workflows, dashboards, role-based access and APIs.

**Assessment:** Existing building blocks include data catalogues, digital land-record systems, GIS platforms, research repositories and generic enterprise search. Their weakness is fragmentation, inconsistent metadata, access governance and limited policy-simulation integration. A credible MVP should choose one state/use case, build a provenance-aware catalogue and demonstrate one policy scenario; a national platform is not hackathon-feasible. **Selection outlook:** high because of broad social impact, but competition will be heavy and many submissions will be generic portals. **Verdict:** valuable but high scope and integration risk.

### SIH26020 — Innovative Hand-Spinning Equipment for Khadi Artisan Productivity and Income

**Organization:** Ministry of MSME · **Type:** Hardware · **Portal complexity:** Moderate

**Requirement digest:** Design a lightweight, portable, ergonomic manually operated spinning system that improves productivity and yarn quality, reduces effort, preserves sustainability, and is evaluated against existing charkhas for output, quality, effort, portability, weight and cost. Include field deployment, artisan adoption, vendor development, cost-benefit analysis and scale-up planning.

**Assessment:** Existing charkhas and ergonomic redesigns provide a baseline; the gap is evidence-backed improvement for the target artisan population and decentralized deployment. The hard part is mechanical prototyping and controlled user testing, not software. **Selection outlook:** lower than software-heavy cyber entries but potentially distinctive. **Verdict:** good for a mechanical/product-design team; weak fit for a pure CSE team.

### SIH26041 — AR-Based Vocational Training Simulator for Industrial Safety in Jharkhand

**Organization:** Government of Jharkhand · **Type:** Software · **Portal complexity:** Moderate

**Requirement digest:** Deliver an Android 10+ phone-based AR safety-training and certification platform for mining, steel and mica workers, without a headset. The page calls for modules such as fire/explosion response, gas leak/confined-space procedures and machinery safety, plus assessments, QR certificate verification, Hindi and Santali localization, offline operation, an admin compliance dashboard and at least two complete demo modules.

**Assessment:** Existing LMS, mobile AR libraries and industrial-safety simulations solve pieces, but usually lack regional-language/offline delivery, evidence of comprehension and verifiable certification. Risks are device variation, AR usability in hazardous environments and ensuring training content is approved by safety experts. **Selection outlook:** medium-high; strong demo value. **Verdict:** one of the more feasible statements if the team keeps AR interactions simple and validates learning rather than merely showing 3D models.

### SIH26058 — Low-Power Adaptive Software-Defined Sonar Transmitter for AUVs

**Organization:** Ministry of Earth Sciences · **Type:** Hardware · **Portal complexity:** Advanced

**Requirement digest:** Build a physical embedded sonar transmitter, not only a simulation. It must ingest environmental inputs, adapt chirp bandwidth/center frequency, pulse duration and amplitude, support LFM/geometric/phase-coded pulses, use timers/DMA and a DAC, include analog conditioning and digital windowing, demonstrate FFT/spectrogram quality on test equipment, and fit a field-deployable AUV payload enclosure.

**Assessment:** SDR, FPGA/DSP and sonar prototypes exist, but the gap is an integrated low-power adaptive transmitter with validated analog output and environmental adaptation. Main risks are analog design, transducer/interface assumptions, power budget and real-time waveform fidelity. **Selection outlook:** low-to-medium due to hardware barrier; quality teams will stand out. **Verdict:** excellent for an embedded signal-processing team, unsuitable for a general software team.

### SIH26105 — AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform

**Organization:** AICTE · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Correlate vulnerability, SIEM, IAM, EDR, CSPM, asset and threat-intelligence data with business criticality and control effectiveness. Quantify likelihood and financial exposure using metrics such as Expected Annual Loss and Value at Risk; support predictive analytics, natural-language queries, what-if scenarios, budget-constrained control optimization, ROSI, executive/technical dashboards and mappings to ISO 27001, NIST CSF, CIS, RBI and SEBI frameworks.

**Assessment:** FAIR-style risk quantification, GRC suites, attack-path tools and security dashboards already cover portions. They fail when data is incomplete, monetary assumptions are opaque, telemetry is not normalized or “AI” produces unsupported precision. **Selection outlook:** high because executive storytelling is attractive; differentiation requires explainable uncertainty, calibrated assumptions and a reproducible synthetic dataset. **Verdict:** strategically important but very high scope; build a narrow scenario optimizer, not a full enterprise GRC platform.

### SIH26106 — AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform

**Organization:** AICTE · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Detect phishing, impersonation, BEC, malware and deceptive infrastructure; parse headers, sender identity, links and attachments; trace relay paths and probable infrastructure; geolocate supporting signals; correlate indicators; and provide investigator dashboards and reports. The page expects AI-assisted detection and forensic intelligence rather than a basic spam classifier.

**Assessment:** Secure email gateways, DMARC tools, URL reputation, sandboxing, header analyzers and threat-intelligence platforms already exist. Their gaps include false positives, encrypted/obfuscated content, compromised legitimate accounts, uncertain geolocation and evidence-quality requirements. **Selection outlook:** high; common “AI phishing detector” submissions will be interchangeable. **Verdict:** feasible only with a forensic-evidence graph, calibrated confidence and a clear privacy boundary.

### SIH26125 — Blockchain-Based Secure Platform for Identity, Access Control and Digital Asset Management

**Organization:** Bharat Electronics Limited · **Type:** Software · **Portal complexity:** Moderate

**Requirement digest:** Use decentralized identifiers, cryptographic proofs, NFT-like asset representation, smart-contract-controlled issuance, RBAC roles and tamper-evident ownership/access history. The goal is secure identity, permission management and digital-asset traceability.

**Assessment:** W3C DID/VC ecosystems, enterprise IAM, PKI, smart contracts and permissioned ledgers already solve many components. Blockchain does not automatically solve key recovery, privacy, revocation, insider abuse, oracle truth or authorization policy. **Selection outlook:** high because blockchain is easy to demo, making differentiation difficult. **Verdict:** choose only with a concrete BEL asset/identity workflow and privacy-preserving revocation; otherwise it risks being a ledger wrapper.

### SIH26141 — Quantum-Inspired Cyber Threat Detection for Digital Signature Security

**Organization:** Egreen Quanta · **Type:** Software · **Portal complexity:** Moderate

**Requirement digest:** Develop a non-AI/ML threat-detection framework for teleportation-based quantum digital-signature systems. Detect forgery, impersonation, replay and unauthorized verification using Pauli eigenstates, projective measurements, statistical thresholds and verification-probability analysis.

**Assessment:** Quantum-signature research simulators, protocol verifiers and quantum SDKs provide foundations. The gap is a rigorous, reproducible threat model and measurable detector behavior; “quantum-inspired” must not be used as a substitute for a defined protocol. **Selection outlook:** low because the specialist pool is small, but evaluation may be demanding. **Verdict:** high research risk; pursue only with quantum-information expertise and a simulator/test oracle.

### SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Ingest passive PCAP, NetFlow/IPFIX/sFlow or derived metadata from a one-way monitoring enclave and detect DDoS, botnet beaconing and other threats without probing, handshaking or sending mitigation commands back. Output near-real-time alerts, confidence scores, evidence and a visualization dashboard.

**Assessment:** Zeek, Suricata, flow analytics, IDS products and anomaly-detection research provide baselines. Their weakness in this setting is that active validation and response are impossible; encrypted traffic, concept drift and class imbalance complicate ML. **Selection outlook:** high among cybersecurity teams. **Verdict:** strong statement if the team respects one-way constraints and evaluates detection latency, false positives and explainability on a held-out temporal dataset.

### SIH26148 — JOCKY Language for Forensic Analysis Without Triggering Security Solutions

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** The page asks for a cross-platform language/compiler and forensic scripts that avoid existing antivirus, including polymorphism, custom encryption, in-memory execution, BYOVD techniques, cloud/CDN/domain-fronting communications and centralized multi-system analysis.

**Assessment:** This requirement overlaps with evasion, stealth execution, vulnerable-driver abuse and covert command-and-control techniques. Legitimate forensic tooling should instead use signed, auditable, least-privilege acquisition and documented allow-listing. Existing EDR/AV bypass research demonstrates why “without triggering security solutions” is unsafe and difficult to validate. **Selection outlook:** technically intriguing but high safety, ethics and evaluation risk. **Verdict:** do not implement evasion, BYOVD or domain-fronting capabilities; if pursued academically, restrict the prototype to a benign forensic DSL in an isolated lab with explicit detection and authorization controls.

### SIH26149 — Integrated Secure Data Erasure and Advanced File Recovery Tool

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Moderate

**Requirement digest:** Combine secure drive erasure, selective file/folder erasure and forensic file carving/recovery across HDD, SSD, USB, memory cards, file systems and operating systems. Include verification, metadata/residual-trace handling, audit logs, tamper-resistant reports, standards compliance and recovery from formatted/damaged/corrupted media.

**Assessment:** DBAN/secure erase utilities, manufacturer sanitize commands, NIST media-sanitization guidance and forensic suites already cover parts. SSD overprovisioning, wear levelling, TRIM, encryption and damaged media make “securely erased” or “fully recovered” difficult to prove. **Selection outlook:** medium; strong practical demo potential. **Verdict:** good if the team explicitly separates logical erasure, cryptographic erasure and device-level sanitize capability, with verifiable limitations.

### SIH26150 — Multi-Vendor DVR/NVR Forensic Analysis Tool

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Support major DVR/NVR vendors, identify models, acquire forensic images, parse proprietary file systems/formats, recover deleted or damaged footage, normalize timestamps, correlate events across cameras, preserve chain of custody, add intelligent video analytics and produce standardized reports.

**Assessment:** Vendor utilities, FFmpeg, digital-forensics suites and video-recovery tools provide partial coverage, but proprietary formats, undocumented metadata, clock drift and evidence integrity remain hard. **Selection outlook:** medium-low due to device and sample-access barriers. **Verdict:** attractive for a digital-forensics team with representative images; otherwise narrow to two vendors and make chain-of-custody validation the differentiator.

### SIH26151 — Dark Web Threat-Actor De-anonymization

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Continuously collect dark-web/deep-web marketplace and forum footprints; identify Tor hidden-service misconfigurations; match clearnet infrastructure; link handles, PGP keys, wallets and trust relationships across markets; use stylometry and behavioral profiling to connect rebranded personas; support timeline queries and autonomous collection.

**Assessment:** OSINT platforms, Tor research, blockchain intelligence, stylometry and graph analysis provide components. They fail through unreliable or adversarial data, persona sharing, deliberate deception, legal/ethical collection boundaries and false attribution. **Selection outlook:** high attention but low trustworthy-execution rate. **Verdict:** only pursue with lawful synthetic/public datasets, human review, provenance and probabilistic attribution; never present an inference as identity.

### SIH26153 — AI-Based Network Attack Forecasting from Network Traffic Data

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Learn evolving network state from traffic telemetry, represent it as features or graphs, model temporal transitions with sequence/GNN/latent-state methods, forecast attack progression and map predictions to MITRE ATT&CK with explanations. It should move beyond per-flow benign/malicious classification.

**Assessment:** SIEM/UEBA, IDS, attack-path analytics and academic sequence/GNN models exist. Forecasting is harder than detection because labels are delayed, interventions change the future, environments drift and causal claims are easy to overstate. **Selection outlook:** high among AI teams. **Verdict:** strong research/demo choice if evaluation uses time-split data, calibrated probabilities, lead time and false-alarm cost; weak if it is only a next-event classifier.

### SIH26155 — AI-Driven Multi-Vendor Network Security Compliance Auditor

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Audit heterogeneous firewalls, SASE, routers, switches, cloud firewalls and specialized networking against CIS, NIST SP 800-53, DISA STIGs and ISO 27001. Discover misconfigurations, insecure protocols, weak crypto, ACL issues and missing logging; normalize vendor configurations; produce evidence-based compliance reports and remediation guidance.

**Assessment:** Ansible/NAPALM, vendor APIs, NCCM tools, ScoutSuite/Prowler-like cloud auditors, benchmark engines and GRC products already exist. The gaps are vendor syntax diversity, config-version drift, semantic equivalence, safe remediation and mapping a technical rule to defensible evidence. **Selection outlook:** high; broad vendor claims are not credible in a hackathon. **Verdict:** choose a declarative rule engine and three representative vendors, with read-only parsing and exact evidence links.

### SIH26159 — SecureMailScope: AI-Assisted Cryptographic Posture Assessment for Email

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Passively analyze SMTP/IMAP/POP3 PCAPs; identify protocols and STARTTLS transitions; reconstruct TCP/TLS sessions; extract and validate X.509 certificates; identify TLS versions, cipher suites, key exchange and forward secrecy; detect weak/deprecated configurations; score risk, detect anomalous TLS behavior and export JSON/PDF/HTML reports with an interactive dashboard.

**Assessment:** Wireshark/tshark, Zeek, NetworkMiner, TLS analyzers and email-security products provide most deterministic parsing. Their gaps are posture aggregation, anomaly prioritization, forensic reporting and careful handling of incomplete/ encrypted captures. **Selection outlook:** medium-high; less broad than ECDAT but easier to validate. **Verdict:** excellent focused project if it avoids claiming AI is needed for deterministic protocol facts and uses ML only where a labeled anomaly problem is demonstrated.

### SIH26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Create a laboratory testbed with tunnel/transport modes, AES variants, DH groups, PFS, IPv4/IPv6 and varied traffic. Capture IKE/ESP/AH and normal traffic; identify versions, modes, algorithms, authentication, key exchange, security associations and inner-traffic type; assess strength, compliance, key lifetime, replay protection, PFS, metadata exposure; produce executive/technical reports, risk and confidence scores.

**Assessment:** Wireshark, strongSwan testbeds, packet analyzers and VPN posture tools already solve protocol decoding. The gap is automated interpretation across controlled configurations and a reliable confidence/evidence layer. **Selection outlook:** medium-high among network-security teams. **Verdict:** technically strong and demonstrable; use a finite test matrix and make “unknown” an explicit result when encryption prevents inner-traffic inference.

### SIH26164 — Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

**Organization:** NTRO · **Type:** Software · **Portal complexity:** Starter

**Requirement digest:** Inventory algorithms, keys, certificates, protocols, libraries, hardware modules and cloud services; assess quantum risk; classify by type, lifetime and business criticality using Mosca-style reasoning; recommend PQC/hybrid alternatives; scan source, binaries, libraries and containers; produce a standardized CBOM report and interactive GUI.

**Assessment:** This is the central report subject. NIST NCCoE, CodeQL, CryptoScan, CipherFlag, AWS CryptaMap, edge scanners and commercial inventory platforms already cover pieces. Their common failures are fragmented coverage, false completeness, weak business context, opaque recommendations and lack of evidence/confidence. **Selection outlook:** medium-high interest, with fewer teams able to execute well. **Verdict:** strongest balanced choice for a capable cyber/program-analysis team when scoped to a read-only, provenance-rich MVP.

### SIH26182 — Automated Attribution of Unknown Cryptocurrency Wallets to VASPs

**Organization:** Ministry of Home Affairs · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Integrate with SAHYOG; trace suspect wallets across Bitcoin, Ethereum, Tron, BNB Chain, Solana, Polygon and other chains; identify nearest exchange/custodian/VASP; recognize exchange clusters, deposit wallets, mixers, bridges and cross-chain swaps; provide confidence scoring, graph visualization, investigation reports and routing for lawful disclosure/freezing requests.

**Assessment:** Chainalysis/TRM/Elliptic-style commercial intelligence, public explorers, graph databases and blockchain-indexing systems already exist. Attribution fails with unhosted wallets, mixers, privacy tools, incomplete labels, cross-chain gaps and changing exchange addresses. **Selection outlook:** high due to law-enforcement impact, but access to labeled ground truth and lawful integration is a major barrier. **Verdict:** build a transparent graph and confidence workflow on public/synthetic cases; do not promise beneficial-owner identification.

### SIH26183 — Real-Time Identification of Fraud-Linked Crypto Exchanges

**Organization:** Ministry of Home Affairs · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Ingest victim-reported wallet addresses, trace funds in real time, identify exchanges/VASPs, detect intermediary laundering, support cross-chain movement, integrate NCRP/SAHYOG, alert investigators, categorize risk and produce standardized reports.

**Assessment:** It overlaps heavily with SIH26182 and existing blockchain-intelligence products. The distinguishing angle is complaint-driven response time and fraud typology, but real-time indexing, chain coverage and exchange labeling remain hard. **Selection outlook:** high, with substantial overlap-driven competition. **Verdict:** choose only if the team can demonstrate a measurable response-time improvement and clearly distinguish it from the nearest-VASP attribution problem.

### SIH26184 — Predictive Analytics for Cybercrime Complaints and Cash-Withdrawal Hotspots

**Organization:** Ministry of Home Affairs · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Starting from approximately 8,000 daily complaints, analyze historical cybercrime and financial data, predict likely cash-withdrawal locations, provide GIS heatmaps and drill-downs, secure investigator access, and send real-time alerts to LEAs, banks and I4C through SMS, email, APIs or dashboards.

**Assessment:** Fraud analytics, geospatial hotspot analysis, bank fraud systems and public-safety dashboards provide analogues. Prediction risks spatial bias, feedback loops, privacy harms and false precision; intervention itself changes the observed pattern. **Selection outlook:** high because the heatmap is easy to present. **Verdict:** only defensible with fairness evaluation, uncertainty bands, temporal validation, human review and strict access controls; never frame a hotspot as proof of a crime.

### SIH26189 — AI-Powered Criminal Network Analysis System

**Organization:** Ministry of Home Affairs · **Type:** Software · **Portal complexity:** Advanced

**Requirement digest:** Ingest FIRs, police reports, CDRs, financial transactions, surveillance, social media, criminal histories and intelligence reports; extract people, locations, vehicles, phone numbers and organizations; build relationship graphs; identify influential individuals, suspicious patterns and investigator-facing insights.

**Assessment:** Link-analysis platforms, graph databases, entity resolution, NLP and law-enforcement intelligence systems already exist. Their critical failures are ambiguous identity resolution, missing data, guilt-by-association, biased source records and poor evidentiary provenance. **Selection outlook:** very high attention but high responsible-AI risk. **Verdict:** build an analyst-assistance graph with source citations, alternative hypotheses and access controls; do not produce automated guilt or “criminal” labels.

## Cross-statement comparison and final ranking

| Rank | Statement | Practicality | Differentiation | Main risk |
|---:|---|---|---|---|
| 1 | SIH26164 ECDAT | High with bounded scope | High with evidence/CBOM/confidence | Overclaiming enterprise coverage |
| 2 | SIH26159 SecureMailScope | High with PCAP test corpus | Medium-high | AI adds little to deterministic parsing |
| 3 | SIH26160 IPsec analyzer | Medium-high | High in controlled testbed | Inner traffic and encrypted inference limits |
| 4 | SIH26145 Unidirectional traffic detection | Medium | High if one-way constraints are honored | Drift, false alarms, no active response |
| 5 | SIH26141 Quantum-signature detection | Low-medium | High | Protocol/research validation risk |
| 6 | SIH26149 Erasure/recovery | Medium | Medium | SSD sanitization/recovery claims |
| 7 | SIH26155 Compliance auditor | Medium | Medium | Vendor breadth and rule correctness |
| 8 | SIH26041 AR safety training | High | Medium | Localization and real learning outcomes |
| 9 | SIH26153 Attack forecasting | Medium | Medium-high | Forecasting calibration and causal overclaim |
| 10 | SIH26125 Blockchain IAM/assets | High | Low-medium | Blockchain does not solve IAM fundamentals |
| 11 | SIH26106 Email forensics | Medium | Medium | False positives and attribution uncertainty |
| 12 | SIH26105 Risk quantification | Low-medium | Medium | Unsupported monetary precision |
| 13 | SIH26150 DVR/NVR forensics | Low-medium | High | Proprietary formats and sample access |
| 14 | SIH26182 VASP attribution | Low-medium | Medium | Labels, cross-chain coverage and legality |
| 15 | SIH26183 Crypto fraud exchange ID | Low-medium | Medium | Heavy overlap with SIH26182 |
| 16 | SIH26184 Withdrawal hotspot prediction | Medium | Medium | Bias, privacy and feedback loops |
| 17 | SIH26189 Criminal network analysis | Medium | Medium | Guilt-by-association and sensitive data |
| 18 | SIH26151 Dark-web de-anonymization | Low | High | False attribution and lawful collection |
| 19 | SIH26020 Khadi spinning equipment | Medium for hardware team | Medium | Field validation and manufacturing |
| 20 | SIH26058 Adaptive sonar | Low for general teams | High | Analog/embedded hardware complexity |
| 21 | SIH26019 Land-governance platform | Low as stated | Medium | National-scale data and policy scope |
| 22 | SIH26148 JOCKY forensic language | Low | High but unsafe | Evasion, BYOVD and covert-channel requirements |

**Portfolio conclusion:** For a typical student cybersecurity/software team, the best shortlist is ECDAT, SecureMailScope, IPsec analysis and unidirectional passive detection. For a generalist team, AR safety training is more feasible than most Advanced cyber statements. SIH26148 should be treated as a safety-sensitive specification requiring redesign before implementation.

## Award-winning and maximum-impact ranking (if AI is permitted)

## No-AI decision: adversarial panel conclusion

Your constraint changes the answer. Statements whose central promise is AI/ML—SIH26105, SIH26106, SIH26145, SIH26153, SIH26155, SIH26159, SIH26184 and SIH26189—should not be the first choice if the team will not use AI. A non-AI team should not submit a conventional rule-based substitute under an “AI-powered” title; judges can identify that mismatch quickly.

I evaluated the strongest non-AI candidates as four opposing reviewers:

| Reviewer | Strongest candidate | Argument |
|---|---|---|
| Impact reviewer | SIH26149 | Secure disposal and forensic recovery affect government, enterprises, investigations and privacy; the benefit is concrete and immediate |
| Innovation reviewer | SIH26164 | A provenance-rich CBOM and quantum-migration risk engine can be novel without ML if it handles unknowns honestly and connects technical findings to business lifetime |
| Demo/judge reviewer | SIH26149 | A controlled erase/recover test is visually convincing and easy to verify, while ECDAT’s enterprise completeness is harder to prove |
| Technical-risk reviewer | SIH26164 | A bounded rule-based scanner is safer than disk-wiping software, which can destroy evidence or make claims that SSD technology cannot support |

### Final decision under the no-AI constraint: SIH26164 — ECDAT

**Choose SIH26164 if your team is serious about winning without AI.** It is the best compromise between sponsor relevance, true engineering novelty, feasibility, future value and responsible execution. The problem statement does not require machine learning; it requires discovery, classification, structured quantum-risk analysis, recommendation and CBOM/reporting. Those can be implemented with deterministic program analysis, parsers, dependency graphs, protocol inspection, a versioned rules engine and transparent scoring.

The winning angle is not “we built an AI crypto scanner.” It is:

> **A trustworthy, explainable cryptographic inventory that proves where each finding came from, distinguishes observed from inferred assets, calculates migration urgency from explicit inputs, and produces a machine-readable CBOM without ever collecting secret key material.**

That is genuinely innovative relative to a typical hackathon dashboard because the differentiator is trust and evidence, not a chatbot or an accuracy claim that cannot be audited.

### Why the other non-AI choices lose the argument

- **SIH26149** has an excellent live demo, but mature tools already cover secure erase and file recovery. The difficult SSD, wear-levelling, TRIM and damaged-media cases also make absolute claims dangerous. It is the best backup choice for a digital-forensics team with test hardware.
- **SIH26125** can be built without AI, but decentralized identity, RBAC and tokenized assets are crowded patterns. Without a specific BEL deployment and privacy/revocation innovation, it can look like a blockchain wrapper.
- **SIH26141** is genuinely novel but has high protocol/research risk, a narrow evaluator pool and no easy real-world validation path.
- **SIH26160** and **SIH26159** are technically strong, but both explicitly emphasize AI-assisted/AI-powered assessment. A deterministic analyzer can be excellent, yet the proposal would need to explain why it is not fulfilling the intended intelligent-analysis portion.
- **SIH26041** is very feasible and can avoid AI, but it is outside the cybersecurity focus and its novelty depends more on content/localization and learning validation than on a distinctive security technology.
- **SIH26148** should be rejected despite technical novelty because its stealth, BYOVD, polymorphism and domain-fronting requirements create unacceptable misuse and trust risks.

### Exact non-AI MVP to maximize winning probability

Build only three surfaces:

1. **Repository and container discovery:** parse Java, Python and C/C++ crypto calls; inspect package manifests, libraries, certificates and container layers.
2. **Evidence graph and CBOM:** store asset, algorithm, mode, version, location, dependency, exposure, scan time, detector and confidence; export CycloneDX-compatible JSON.
3. **Explainable migration prioritization:** let the user enter data lifetime, business criticality, exposure and estimated migration time; calculate a Mosca-style urgency category and map each finding to a reviewed PQC/hybrid candidate with compatibility warnings.

Do not implement private-key extraction, automated code rewriting or an enterprise-wide “scan everything” claim. Include an explicit unsupported/unknown state and a secret-material safety test.

### The winning proof moment

Start with a deliberately mixed repository containing direct RSA/ECDSA calls, wrapped library calls, a vulnerable certificate, a container dependency and a file the scanner cannot inspect. Run the scan. The dashboard must show:

- exact source/binary/configuration evidence;
- the dependency and asset relationships;
- why each item is quantum-vulnerable, partially affected, safe or unknown;
- how changing data lifetime changes the priority;
- a CBOM export that another tool can parse;
- a clear “not observed” warning for the hidden/dynamic case;
- confirmation that no private-key material was read or exported.

This proof is stronger than a synthetic AI score: judges can inspect the evidence, challenge the reasoning and see the system remain honest under uncertainty.

### Final no-AI ranking

| Rank | ID | Statement | No-AI award potential | Decision |
|---:|---|---|---:|---|
| 1 | SIH26164 | ECDAT | **Very high** | Recommended winner choice |
| 2 | SIH26149 | Secure erasure and forensic recovery | High | Best backup for a forensic-hardware team |
| 3 | SIH26125 | Blockchain identity/access/assets | Medium | Needs a specific privacy/revocation breakthrough |
| 4 | SIH26141 | Quantum-inspired signature security | Medium | Research gamble; only with quantum expertise |
| 5 | SIH26160 | IPsec VPN analyzer | Medium | Strong project, but AI requirement creates proposal mismatch |
| 6 | SIH26159 | SecureMailScope | Medium | Good deterministic tool, but AI-assisted wording creates mismatch |
| 7 | SIH26041 | AR industrial safety training | Medium | Feasible, but lower cybersecurity differentiation |
| 8 | SIH26020 | Khadi hand-spinning equipment | Medium for hardware teams | Strong impact, unrelated to cyber specialization |
| 9 | SIH26058 | Adaptive sonar transmitter | Medium for DSP teams | Hardware innovation, difficult validation |
| 10 | SIH26019 | Land-governance platform | Low-medium | Too broad without AI and national data access |
| 11 | SIH26150 | DVR/NVR forensics | Low-medium | Device/vendor access is limiting |
| 12 | SIH26145 | Unidirectional threat detection | Low | AI is central to the stated solution |
| 13 | SIH26105 | Cyber-risk quantification | Low | AI, statistical estimation and financial modeling are central |
| 14 | SIH26106 | Email threat/geolocation/forensics | Low | AI-based detection is central |
| 15 | SIH26151 | Dark-web de-anonymization | Low | AI/stylometry and lawful collection are central risks |
| 16 | SIH26153 | Network attack forecasting | Low | Temporal AI/world-model framing is central |
| 17 | SIH26155 | Network compliance auditor | Low | AI-driven breadth is central to the stated approach |
| 18 | SIH26182 | VASP attribution | Low | AI/ML-assisted analytics and massive labels/infrastructure are expected |
| 19 | SIH26183 | Crypto-fraud exchange identification | Low | AI/ML pattern recognition and real-time indexing are expected |
| 20 | SIH26184 | Withdrawal hotspot prediction | Low | Predictive ML and sensitive data are central |
| 21 | SIH26189 | Criminal network analysis | Low | AI/NLP/graph inference and high-risk data are central |
| 22 | SIH26148 | JOCKY forensic language/evasion | Reject | Unsafe specification; do not pursue as written |

**Bottom line:** select **SIH26164**. Build it as a deterministic, evidence-first cryptographic discovery and migration-readiness platform. That gives you a credible “truly innovative without AI” story, a controllable demo, and a direct answer to a government-grade problem.

### The winner: SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Recommended #1 overall for award potential.** This is the best balance of national importance, technical originality, feasible demonstration, measurable performance and responsible deployment. It protects critical-infrastructure monitoring enclaves while respecting a hard operational constraint: the analytics system can observe traffic but cannot probe or send commands back into the protected network. That constraint gives the solution a distinctive engineering story and prevents the project from collapsing into a generic IDS dashboard.

The award-winning demo should show a replayable, time-ordered traffic stream, early detection of DDoS/beaconing/anomalies, confidence and supporting packet/flow evidence, false-positive control, and graceful behavior when the model cannot know something. Report detection lead time, precision/recall, alert latency, resource use and performance under concept drift. Map outputs to MITRE ATT&CK only when the evidence supports the mapping.

### Maximum raw societal/government impact: SIH26184 — Cybercrime Complaint and Cash-Withdrawal Forecasting

If “impact” means the largest potential direct effect on citizens and financial-fraud recovery, SIH26184 is the leading candidate. The statement describes approximately 8,000 complaints per day and a pathway from prediction to bank/LEA intervention, fund blocking and improved recovery. However, it is **not automatically the safest award choice**: a model can amplify geographic or socioeconomic bias, create false alarms and be invalidated by data leakage or changing criminal behavior. It requires temporal validation, uncertainty intervals, fairness checks and human authorization.

### Best strategic/long-horizon impact: SIH26164 — ECDAT

ECDAT addresses a national-scale cryptographic migration problem and can become reusable infrastructure for government and enterprise systems. Its impact is strategic rather than immediately visible to citizens. It ranks below SIH26145 because many teams can present a scanner/dashboard, and because complete enterprise coverage is impossible in a hackathon unless the scope is sharply controlled.

### Scoring method

The ranking below applies the official SIH-style dimensions of novelty, complexity, clarity, feasibility, practicability, sustainability, scale of impact, user experience and future progression, as summarized in the SIH guidelines. The score is an analytical estimate, not an official jury score.

| Weight | Criterion | What earns a high score |
|---:|---|---|
| 30% | Scale and urgency of impact | Addresses a high-consequence national problem with a clear affected population |
| 20% | Demonstrable feasibility | Can be proven with a working prototype and defensible test data |
| 15% | Novelty/differentiation | Has a specific insight or hard constraint beyond a standard dashboard |
| 15% | Measurable outcomes | Has metrics that judges can verify during the demo |
| 10% | Scalability/sustainability | Can progress from prototype to institutional deployment |
| 10% | Trust, safety and responsibility | Handles uncertainty, privacy, bias, evidence and misuse responsibly |

### Final ranking of all 22 statements

| Rank | ID | Problem statement | Award score / 100 | Impact tier | Decisive reason |
|---:|---|---|---:|---|---|
| 1 | SIH26145 | Unidirectional IP traffic threat detection | **90** | Very high | Critical infrastructure + unusual one-way constraint + testable real-time metrics |
| 2 | SIH26184 | Cybercrime complaint withdrawal-location forecasting | **88** | Exceptional | Direct citizen/fraud-recovery impact and national scale; requires strong fairness controls |
| 3 | SIH26164 | Enterprise Cryptographic Discovery & Analysis Tool | **87** | Very high | Strategic PQC readiness, strong sponsor fit, feasible bounded MVP and clear evidence story |
| 4 | SIH26159 | SecureMailScope email cryptographic posture | **85** | High | Highly demonstrable PCAP workflow and immediate enterprise security value |
| 5 | SIH26160 | IPsec VPN protocol analyzer | **84** | High | Controlled testbed, strong technical depth and measurable protocol assessment |
| 6 | SIH26189 | AI-powered criminal network analysis | **83** | Exceptional | Broad law-enforcement value, but provenance, bias and guilt-by-association risks reduce award confidence |
| 7 | SIH26105 | Cyber risk quantification and investment optimization | **82** | Very high | Board-level value and large market; monetary estimates are difficult to validate honestly |
| 8 | SIH26155 | Multi-vendor network compliance auditor | **81** | High | Direct remediation value; vendor breadth and rule correctness are the main barriers |
| 9 | SIH26041 | AR industrial safety training | **80** | High | Strong human impact and compelling demo; localization and real learning outcomes must be proven |
| 10 | SIH26153 | Predictive network attack forecasting | **79** | Very high | Ambitious proactive defense; forecasting calibration and temporal validation are difficult |
| 11 | SIH26149 | Secure erasure and forensic recovery | **78** | High | Tangible government/forensic value; SSD guarantees and recovery claims require care |
| 12 | SIH26106 | Email threat, geolocation and forensics | **77** | High | Relevant and visual, but crowded with existing products and attribution uncertainty |
| 13 | SIH26182 | Unknown wallet to VASP attribution | **76** | Exceptional | Strong cybercrime impact; data labels, chain coverage and lawful integration are limiting |
| 14 | SIH26183 | Fraud-linked crypto exchange identification | **75** | Exceptional | Strong response value but overlaps SIH26182 and faces the same attribution barriers |
| 15 | SIH26150 | Multi-vendor DVR/NVR forensics | **74** | High | Important evidence workflow; proprietary formats and sample access constrain feasibility |
| 16 | SIH26125 | Blockchain identity/access/assets | **72** | Medium-high | Potential institutional value, but mature alternatives and blockchain overuse reduce novelty |
| 17 | SIH26019 | National land-governance research platform | **71** | Exceptional | Massive policy impact, but national data integration and scope make a convincing prototype unlikely |
| 18 | SIH26141 | Quantum-inspired signature threat detection | **70** | High | Novel specialist research, but narrow adoption and protocol-validation uncertainty |
| 19 | SIH26151 | Dark-web actor de-anonymization | **68** | High | Intelligence value, but false attribution, adversarial deception and lawful collection risks |
| 20 | SIH26058 | Adaptive AUV sonar transmitter | **67** | High | Important strategic hardware capability, but difficult to prototype and validate in hackathon time |
| 21 | SIH26020 | Khadi hand-spinning equipment | **66** | High | Strong livelihood impact, but award outcome depends on physical field testing and artisan adoption |
| 22 | SIH26148 | JOCKY forensic language and security evasion | **35** | Potentially high but unsafe | BYOVD, stealth execution, polymorphism and domain-fronting requirements create unacceptable misuse and trust risks |

### Final choice

If the sole objective is to maximize the probability of an award, choose **SIH26145**. If the objective is maximum direct public impact and the team has legitimate access to high-quality complaint/financial data plus responsible-AI expertise, choose **SIH26184**. If the team’s strongest capability is cryptography and software analysis, choose **SIH26164** and implement the bounded MVP defined earlier.

## Previous SIH winner research: what appears to produce winning outcomes

### Evidence quality and method

Public SIH winner material is uneven. Official SIH/PIB pages establish event context and criteria; institute pages confirm a team/problem/win and sometimes describe the implementation; personal blogs and interviews give the richest process detail but are self-reported. I therefore distinguish **documented behavior** from claims that cannot be independently verified. The patterns below are not a secret formula or a guarantee of winning.

### Case study 1 — NFSU, SIH 2023, centralized power-sector log collection

The National Forensic Sciences University reports that its team won SIH1389, a Ministry of Power problem for a centralized log-collection facility compliant with CEA 2021. The institute specifically identifies the implementation choices: open-source tools, custom parsers, unidirectional flow, data normalization, real-time parsing/analysis and visualization. It also reports three mentoring rounds and three evaluation rounds during the 36-hour finale.

**Why this matters for the current list:** this is a directly relevant cybersecurity precedent. The team translated a broad operational problem into a pipeline judges could see: ingest → parse → normalize → analyze → visualize. The architecture was aligned with the sponsor’s environment instead of being an abstract AI demo. This is the strongest precedent for selecting **SIH26145**, whose one-way monitoring constraint naturally supports the same observable pipeline.

### Case study 2 — Tech Hustlers, SIH 2022, caller-ID spoofing

In a detailed participant account, Tech Hustlers describes a DoT caller-ID-spoofing problem. Their judges asked them to reduce many proposed detection parameters to one parameter that could reliably detect spoofing. The team followed that advice, built SCID, used a practical web/data stack, and presented the result with an animated explanation. The account says the nodal head emphasized that convincing the DoT evaluators was difficult, which makes judge alignment and clarity especially salient.

**Transferable lesson:** a narrower detector with a defensible result can beat a broad system with shallow claims. For SIH26145, select two or three threat classes, define the evidence for each, and make the detection metric visible. For SIH26164, this means not promising every cryptographic surface; choose source code, containers and TLS endpoints first.

### Case study 3 — Team Avlokan, SIH 2023, drone-based magnetic anomaly detection

An IIT Bombay interview reports that Team Avlokan won a Ministry of Defence problem with a Quadplane VTOL and magnetic-anomaly-detection suite. The interview emphasizes a functioning physical prototype, long-range national-security relevance, interdisciplinary roles, systematic leadership, step-wise subsystem integration, testing and a successful flight. The team also continued post-win testing and optimization toward reliability and market readiness.

**Transferable lesson:** judges can trust a solution that visibly works in the target shape, not only in a slide deck. SIH26145 should similarly demonstrate the actual one-way boundary and traffic replay, while SIH26160 should demonstrate a controlled VPN testbed and SIH26164 should show real scan evidence rather than mock dashboard cards.

### Case study 4 — Tech Hustlers’ and similar finalist accounts: mentor feedback is a design input

The Tech Hustlers account states that the problem-owning judges mentored and evaluated the team, then suggested a smaller scope. The NFSU account also documents repeated mentoring and evaluation rounds. This is consistent with the official SIH guidance that mentors work with teams to convert ideas into a working prototype and that final evaluation considers novelty, complexity, clarity, feasibility, practicability, sustainability, scale of impact, user experience and future progression.

**Transferable lesson:** prepare a modular architecture before the finale, but expect to remove features after sponsor feedback. A winning team should be able to say, “We removed X because the problem owner said Y; this increased reliability from A to B.”

### Case study 5 — Shubham Kulkarni’s SIH 2023 winner account: one core loop, offline resilience and a rehearsed proof

This is a personal retrospective rather than an official SIH record. It describes an offline-first smart-irrigation winner: the team focused on the soil-to-pump feedback loop, moved decision logic from cloud to an edge gateway after connectivity failed, tested 100 sensor readings with the network disconnected, documented the pivot in an architecture decision record, and rehearsed pulling the network cable during the demo. The author’s central claim is that one reliable capability, demonstrated under failure, beat several half-built features.

**Transferable lesson:** design a “proof moment” for the chosen cybersecurity statement. For SIH26145, disconnect the analytics environment from any active response path and show that detection still works from passive replay; then inject a new traffic condition and show the confidence/unknown state. For ECDAT, scan an unseen repository/container and show exact evidence, then show that unsupported or dynamic crypto is reported as unknown rather than falsely absent.

### Case study 6 — SIH 2024 public winner/participant signals

The Government of India’s 2024 finale communication highlights that solutions are expected to address real-world problems and notes that prior SIH solutions have entered effective ministry use. The Prime Minister’s 2024 interaction also featured teams presenting accessible, offline or multi-engine solutions and emphasized solutions that can scale from Indian needs to wider use. A 2024 winner account from Solar Masters reports a structured presentation, simulation plus hardware, quantitative testing, documentation and a future scale-up plan; because that account is institution-published but self-reported, treat its details as supporting evidence rather than official judging data.

**Transferable lesson:** communicate impact in the user’s language, keep the prototype usable under realistic constraints, show a number, and finish with a deployment path. “AI-powered” alone is not a differentiator; a measured reduction in alert latency, false positives, water use, recovery time or energy use is.

## What previous winners did — consolidated pattern

1. **Selected a real operational pain point with a visible owner.** Ministry/agency context was not decorative; the workflow and constraints shaped the prototype.
2. **Reduced the statement to one core loop.** Winners commonly made one critical function reliable rather than presenting many incomplete features.
3. **Built a testable vertical slice.** The demonstrated path ran end-to-end with real or carefully designed data, not only isolated modules.
4. **Made a hard constraint part of the innovation.** Offline operation, unidirectional flow, low cost, a physical flight or a difficult field condition became proof points.
5. **Used open-source components pragmatically.** Winning accounts describe parsers, open tools, standard libraries and practical stacks; novelty came from integration, workflow and validation.
6. **Accepted mentor/judge correction quickly.** Scope reduction was treated as engineering judgment, not as loss of ambition.
7. **Measured an outcome.** Even a prototype needs a baseline, test set and metric that a judge can verify.
8. **Assigned clear roles and rehearsed the presentation.** Technical work, integration, user story and explanation were all owned.
9. **Prepared for failure.** Offline fallback, spares, replayable data, deterministic setup and a recovery plan made the demonstration resilient.
10. **Presented a credible continuation path.** Winners typically described field testing, reliability, adoption, cost or startup/deployment progression after the hackathon.

## Problem statement selected using those winner patterns

### Recommended: SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

This is the statement most naturally aligned with the documented winning pattern. It has a real critical-infrastructure user, a crisp non-negotiable constraint, a software vertical slice that can be built and tested with public/synthetic data, and clear quantitative metrics. It also has a compelling live demonstration: threat detection must work in an enclave that cannot actively query the protected network or push a mitigation command.

### Award-winning solution concept: “OneWay Sentinel”

Build a read-only passive threat-intelligence appliance for a simulated data-diode enclave. The MVP has one core loop:

**PCAP/flow stream → feature extraction → temporal detection → evidence-backed alert → analyst dashboard/export.**

Limit the first release to three high-value behaviors:

- volumetric/protocol DDoS patterns using rates, amplification ratios, entropy and directionality;
- botnet C2 beaconing using periodicity and destination recurrence;
- suspicious lateral or exfiltration-like flow sequences using temporal and graph features.

Use a hybrid detector: deterministic rules for obvious network conditions, statistical/time-series modeling for behavior, and an optional lightweight model for ranking. This avoids the common failure of adding an unexplainable classifier where protocol facts are already knowable.

### What to show judges

- A visibly one-way architecture: the analytics node has no route or API path to the simulated production side.
- A replayed baseline, then injected DDoS/beaconing traffic, with alert lead time and evidence.
- A temporal hold-out test report with precision, recall, false-alert rate, mean detection latency and CPU/memory use.
- A confidence score with the top contributing features and packet/flow references.
- A concept-drift test in which the system flags uncertainty or requests recalibration rather than silently pretending certainty.
- A clean export for SOC/forensics use and a MITRE ATT&CK mapping only where justified by evidence.
- A failure demo: block active probes and mitigation APIs, then prove the detector still functions.

### Why this is more awardable than a broad AI platform

It follows the winner evidence: one core loop, realistic constraints, open tools used pragmatically, a visible proof moment, measurable performance and a credible deployment path. It also maps closely to the NFSU 2023 cyber winner’s documented use of unidirectional flow, normalization, real-time parsing and visualization. Its main weakness—false positives and changing traffic patterns—can become a strength if the team reports calibration, limitations and analyst feedback honestly.

### Second-best choice if the team is stronger in cryptography

Choose **SIH26164 ECDAT**, but reshape it around the same winning formula: source repositories plus containers plus TLS endpoints; exact evidence and confidence; CBOM export; user-entered business lifetime/criticality; and a single visible migration-priority workflow. Do not attempt complete enterprise discovery in the finale.

## Revised recommendation

**Choose SIH26145 if the team wants the highest award probability based on prior winner patterns.** It offers the best combination of national-security relevance, distinctive constraint, prototype feasibility, measurable proof and presentation clarity. **Choose SIH26184 only if the team has legitimate access to high-quality complaint/financial data and strong responsible-AI expertise**; its raw public impact may be larger, but its data, fairness and deployment risks make it harder to prove responsibly. **Choose SIH26164 for a cryptography/program-analysis team** that can execute the bounded evidence-led MVP.

## Sources and research basis

## Adversarial selection debate: choosing for winning probability without generic AI

The following debate deliberately penalizes ideas whose main novelty is “add AI,” because that will be common across submissions. It favors a distinctive operational constraint, a working proof, a non-obvious technical insight, measurable performance and a demo that judges can independently understand.

### Perspective A — SIH judge

**Argument:** A judge has limited time and must compare teams under the same problem statement. The strongest submission will make the problem-owner’s pain obvious within minutes, show the required workflow working, and answer “what is better than the existing tools?” AI branding is not enough. The project should have a crisp success metric and few assumptions.

**Preferred candidates:** SIH26160, SIH26159 and SIH26149. These have controlled inputs and observable outputs. SIH26145 is strong, but many teams may submit an AI IDS. SIH26164 is strategically important, but a broad crypto scanner can look like an aggregation of existing tools.

### Perspective B — cybersecurity domain expert

**Argument:** Security judges distrust black-box claims. Protocol facts should be derived from protocol parsing; cryptographic posture should be evidence-backed; “unknown” is better than a fabricated answer. The most credible non-generic solution is one that exposes its evidence and respects what encryption prevents it from knowing.

**Preferred candidate:** SIH26160. An IPsec analyzer can be built around deterministic IKE/ESP/Security Association parsing, a controlled test matrix, replay protection/PFS/configuration checks and a transparent confidence layer. AI can be limited to anomaly ranking, not used to invent protocol facts.

### Perspective C — deployment and product evaluator

**Argument:** A winning prototype should have a believable route to deployment. It should not need classified data, private keys, undocumented government APIs or a national-scale training corpus. It should be possible to demo locally, repeatably and safely, then package as an analyst tool.

**Preferred candidates:** SIH26160 and SIH26159. Both can use a generated lab testbed and PCAP corpus, produce reports and demonstrate value without claiming access to sensitive production data. SIH26149 has strong utility but must make technically careful claims about SSD sanitization and deleted-file recovery.

### Perspective D — skeptical hackathon veteran

**Argument:** Most teams lose by building breadth. Choose the problem where a single “pull the cable / show the attack / prove the evidence” moment can settle the argument. Avoid problems where success depends on data access, vague future benefits or a dashboard that looks the same as every other dashboard.

**Preferred candidate:** SIH26160, with SIH26149 as the strongest non-network alternative. SIH26141 is genuinely novel but has a high risk that judges cannot verify the quantum-signature claims during the event. SIH26058 is distinctive but hardware integration failure can eliminate the team.

### Devil’s advocate against SIH26160

SIH26160 explicitly asks for an AI-driven platform, and packet analyzers already exist. A shallow implementation that simply wraps Wireshark will not win. The solution must therefore demonstrate a new analyst capability: automatically infer the negotiated security posture across a test matrix, explain every finding using IKE/ESP evidence, quantify metadata exposure and identify configuration regressions over time. The differentiator is **auditable protocol reasoning**, not a chatbot or an opaque classifier.

### Debate result

| Candidate | Judge | Security expert | Deployment evaluator | Veteran | Consensus |
|---|---|---|---|---|---|
| SIH26160 IPsec analyzer | 1 | 1 | 1 | 1 | **4/4** |
| SIH26159 SecureMailScope | 2 | 2 | 2 | 3 | 0/4 first |
| SIH26149 erasure/recovery | 3 | 3 | 3 | 2 | 0/4 first |
| SIH26145 unidirectional detection | 4 | 4 | 4 | 4 | 0/4 first; crowded AI space |
| SIH26164 ECDAT | 5 | 5 | 5 | 5 | 0/4 first; broad and crowded |
| SIH26141 quantum signatures | 6 | 6 | 6 | 6 | 0/4 first; validation risk |

## Final selection for maximum winning probability

### Choose SIH26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

After explicitly penalizing generic AI solutions, SIH26160 becomes the best choice for **winning probability**, even though SIH26145 remains the highest-impact cybersecurity idea and SIH26164 remains the strongest strategic crypto idea.

The reason is structural: SIH26160 gives the team a closed world in which the ground truth is known. You can deliberately create VPN configurations, capture the resulting IKE/ESP traffic, hide the configuration from the analyzer, and test whether the analyzer correctly reconstructs the truth. That makes a judge’s evaluation easy and makes exaggerated AI claims unnecessary.

### The winning concept: “IKEProof”

Build a deterministic, evidence-first IPsec assessment engine with a small, purposeful intelligence layer:

1. Generate a lab matrix covering tunnel/transport mode, IKEv1/IKEv2 where applicable, AES-GCM, AES-CBC/HMAC, DH groups, PFS on/off, IPv4/IPv6 and replay-protection settings.
2. Capture traffic from the testbed and reconstruct IKE negotiations, Security Associations, ESP/AH observations and timing/lifetime behavior.
3. Infer the security posture from packet evidence, not from a language model. Each finding links to the exact exchange, field and packet range that supports it.
4. Use a small statistical model only for anomaly ranking and traffic-pattern classification where ground truth is available. If the model cannot identify inner traffic because ESP is encrypted, report “not observable.”
5. Produce two outputs: a technical evidence report and an executive risk view. Include a configuration-diff mode that detects regressions between two captures.

### The proof moment

Configure two otherwise identical VPNs. In the first, enable AES-GCM, strong DH and PFS. In the second, disable PFS, use a weaker group and shorten or alter the Security Association lifetime. Feed both captures to IKEProof without revealing the setup. The system reconstructs the differences, cites the evidence, flags the weaker configuration, assigns a transparent score and explains the recommended correction. Then demonstrate an encrypted-traffic limitation honestly: the engine identifies the outer protocol and security properties but refuses to invent the inner application identity.

### Why this is more innovative than an AI dashboard

- **Ground-truth challenge:** the analyzer must infer hidden VPN configuration from observed traffic and be tested against a known matrix.
- **Evidence graph:** every score and recommendation is traceable to protocol fields and packets.
- **Regression detection:** the product compares posture across captures, a practical capability missing from many one-off analyzers.
- **Uncertainty discipline:** it separates observed, inferred and unobservable facts.
- **Human-readable security reasoning:** it explains PFS, key exchange, replay protection, cipher strength and metadata exposure without asking judges to trust a black box.
- **Deployment realism:** it works in an offline lab and does not require classified traffic, cloud services or private-key collection.

### What not to build

- Do not build a chatbot that summarizes Wireshark output.
- Do not claim ML can recover encrypted inner traffic reliably.
- Do not support every VPN vendor or every protocol in the finale.
- Do not spend most of the time on a marketing dashboard.
- Do not use AI for facts that deterministic parsing can establish.
- Do not claim compliance merely because a cipher name appears; evaluate the complete negotiated configuration and context.

### Winning submission language

> “IKEProof does not ask an AI to guess whether a VPN is secure. It reconstructs what the VPN actually negotiated, links every finding to packet evidence, compares the result against a known security baseline, and clearly labels what encrypted traffic cannot reveal.”

### Final answer to the selection question

**Select SIH26160.** It is the strongest choice if your priority is to win with a genuinely differentiated, non-generic solution. It offers a higher probability of a convincing, repeatable, technically deep demo than SIH26145, less scope risk than SIH26164, and less validation uncertainty than SIH26141. Select SIH26145 only if your team is substantially stronger in passive network ML and can prove early detection on a realistic temporal test set. Select SIH26164 only if your team has unusually strong static-analysis and cryptography expertise.

- [Live SIH 2026 problem-statement page](https://skt.kumaraguru.in/sih2026-review/decide.html) — official statement text, metadata, displayed category and complexity counts.
- [NIST NCCoE: Migration to Post-Quantum Cryptography](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc) — cryptographic discovery workstream, inventory and migration context.
- [NIST NCCoE PQC FAQ](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/) — inventory definition, discovery tools and migration guidance.
- [NIST SP 1800-38B preliminary draft](https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38b-preliminary-draft.pdf) — CBOM concept and multi-surface discovery considerations.
- [CycloneDX Authoritative Guide to CBOM](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-CBOM-en.pdf) — CBOM object model and cryptographic-asset relationships.
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) — transition and algorithm/key-strength guidance.
- [CryptoScan](https://github.com/csnp/cryptoscan), [CipherFlag](https://github.com/net4n6-dev/cipherflag), and [AWS CryptaMap](https://github.com/aws-samples/sample-CryptaMap) — representative open-source existing implementations; capabilities should be independently tested before reuse.
- [SIH Buddy’s ECDAT analysis](https://sih-buddy.vercel.app/ps/SIH26164) — a non-official secondary interpretation; useful as a comparison signal, not an authoritative popularity or acceptance metric.
- [NFSU’s SIH 2023 winner report](https://nfsu.ac.in/details/194) — official institute account of SIH1389, its three evaluation rounds, parsers, unidirectional flow, normalization, real-time analysis and visualization.
- [IIT Bombay’s Team Avlokan interview](https://acr.iitbombay.org/innovating-the-future-team-avlokans-triumph-at-smart-india-hackathon-2023/) — winner interview covering the physical prototype, interdisciplinary roles, integration, testing and post-win roadmap.
- [Tech Hustlers’ SIH 2022 retrospective](https://chandrashaker.com/smart-india-hackathon-2022-success-journey/) — participant account describing mentor-driven scope reduction for caller-ID spoofing and the final pitch.
- [Shubham Kulkarni’s SIH winner retrospective](https://shubhamkulkarni.me/blog/sih-win-2023.html) — self-reported account of narrowing to one core loop, an offline pivot, failure testing and demo rehearsal; not an official SIH publication.
- [SIH 2024 official guidelines](https://sih.gov.in/letters/Guidelines-College-SPOC.pdf) — published selection dimensions: novelty, complexity, clarity, feasibility, practicability, sustainability, impact, user experience and future progression.
- [Prime Minister’s SIH 2024 address](https://www.pmindia.gov.in/en/news_updates/pms-address-at-the-smart-india-hackathon-2024/) — official examples of real-world, scalable solutions and prior SIH outputs used by ministries.

**Confidence note:** official problem text and portal counts are high confidence as observed on 29 August 2026. The popularity estimate, market-gap judgments and effort estimates are analytical judgments and should not be confused with SIH submission statistics or an official evaluation rubric.
