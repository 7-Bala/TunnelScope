# Source Register (running)

## Tier 1 — IETF standards
- [RFC 7296 — IKEv2](https://www.rfc-editor.org/rfc/rfc7296.html) — exchange structure; §2.4 SA lifetimes are NOT negotiated; IKE_SA_INIT plaintext vs IKE_AUTH/CREATE_CHILD_SA encrypted.
- [RFC 9395 — Deprecation of IKEv1 and Obsoleted Algorithms](https://datatracker.ietf.org/doc/rfc9395/) — IKEv1 to Historic; deprecated algorithms; IANA Status column.
- [RFC 8221 — ESP/AH algorithm requirements](https://www.rfc-editor.org/rfc/rfc8221)
- [RFC 8247 — IKEv2 algorithm requirements](https://www.rfc-editor.org/rfc/rfc8247.html)
- [RFC 9370 — Multiple Key Exchanges in IKEv2](https://www.rfc-editor.org/info/rfc9370/) — IKE_INTERMEDIATE, hybrid PQC path.
- RFC 4301 (architecture), RFC 4302 (AH), RFC 4303 (ESP), RFC 3948 (UDP encapsulation), RFC 8229 (ESP in TCP), RFC 7383 (IKEv2 fragmentation), RFC 8784 (PQ PSK), RFC 4106 (AES-GCM in ESP), RFC 3602 (AES-CBC in ESP), RFC 7634 (ChaCha20-Poly1305), RFC 7427 (signature auth) — to be individually verified for current status.

## Tier 2 — Government guidance
- [NIST SP 800-77 Rev. 1 — Guide to IPsec VPNs (2020)](https://csrc.nist.gov/pubs/sp/800/77/r1/final)
- NIST SP 800-131A Rev. 2 — algorithm/key-strength transitions (in report.md).
- NSA CNSA 2.0 — to be sourced.

## Tier 3 — Academic
- [SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers (arXiv:2503.20093)](https://arxiv.org/pdf/2503.20093) — most published classifiers used unencrypted traffic; 348 feature-occlusion experiments; overfitting.
- [Extensible ML for Encrypted Network Traffic Application Labeling via Uncertainty Quantification (arXiv:2205.05628)](https://arxiv.org/pdf/2205.05628) — VNAT dataset; uncertainty quantification.
- [Fine-grained TLS services classification with reject option (arXiv:2202.11984)](https://arxiv.org/pdf/2202.11984) — reject option / abstention.
- [A comprehensive review on ML-based VPN detection (ScienceDirect S1574013725000577)](https://www.sciencedirect.com/science/article/pii/S1574013725000577) — ISCXVPN2016 limitations.
- "Bias in the Shadows: Explore Shortcuts in Encrypted Network Traffic Classification" (arXiv:2601.10180) — shortcut learning; to be read in full.

## Tier 4 — Project documentation / source
- [corelight/zeek-spicy-ipsec](https://github.com/corelight/zeek-spicy-ipsec) — ESP, AH, IKEv1/v2, ESP-over-UDP/TCP.
- [ukncsc/zeek-plugin-ikev2](https://github.com/ukncsc/zeek-plugin-ikev2) — IKE_SA_INIT parsing to ikev2.log.
- [Zeek's IPsec Protocol Analyzer (2021)](https://zeek.org/2021/04/zeeks-ipsec-protocol-analyzer/) — includes the caveat that native ESP is often invisible to Zeek unless UDP/TCP-encapsulated.
- [Wireshark IKEv2 decryption table](https://www.wireshark.org/docs/wsug_html_chunked/ChIKEv2DecryptionSection.html); ESP SAs preference; [ESP dissector refactor MR !3444](https://gitlab.com/wireshark/wireshark/-/merge_requests/3444) (AEAD + ICV verification).
- [royhills/ike-scan](https://github.com/royhills/ike-scan) — discovery, fingerprinting, PSK cracking; experimental IKEv2.
- [strongSwan](https://strongswan.org/) / swanctl + vici — endpoint telemetry (vantage V3).

## Internal
- `report.md` (2026-08-29) — problem-statement selection study. Prior hypothesis, not evidence.

## Added in D2–D7 (2026-09-09)

### Tier 1 — Standards
- [RFC 9242 — Intermediate Exchange in IKEv2](https://datatracker.ietf.org/doc/rfc9242/) — the IKE_INTERMEDIATE exchange.
- [RFC 9347 — AGGFRAG mode for ESP / IP-TFS](https://www.rfc-editor.org/rfc/rfc9347.pdf) — constant-rate, fixed-size tunnel; traffic-analysis resistance.
- [RFC 4303 — ESP](https://datatracker.ietf.org/doc/html/rfc4303) — §2.7 TFC padding; next-header 59 dummy packets.
- [RFC 6562 — VBR audio with SRTP](https://datatracker.ietf.org/doc/html/rfc6562) — written in response to Wright et al.
- [draft-ietf-ipsecme-ikev2-mlkem](https://www.ietf.org/archive/id/draft-ietf-ipsecme-ikev2-mlkem-03.html)
- [IETF ipsec list: ESP dummy packets thread](https://mailarchive.ietf.org/arch/msg/ipsec/e9cYfq6U0HHT6V57hS2_DPTbX5Q/) — TFC treated as an emerging research area, not deployed technology.

### Tier 2 — Government
- **[DST — Implementation of Quantum Safe Ecosystem in India, Report of the Task Force, Feb 2026](https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20(v1).pdf)** — National Quantum Mission; crypto inventory by 2027 (CII); CBOM mandate FY2027-28; names downgrade/insecure-fallback risk and reversion to vulnerable cryptography; names tunnels/VPNs/gateways.
- [DISA VPN Security Requirements Guide V2R6](https://cyber.trackr.live/stig/Virtual_Private_Network_(VPN)_Security_Requirements_Guide/2/6) — V-207205 IKEv2; V-207193 DH ≥16; V-207223/V-207192 SHA-2 384+; V-207230 AES; V-207212 anti-replay; V-207184 ESP tunnel mode.
- [CERT-In Guidelines on Information Security Practices for Government Entities](https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=1936470) — general; no IPsec algorithm baseline found.

### Tier 3 — Academic
- [The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification (arXiv:2507.16438)](https://arxiv.org/html/2507.16438) — ET-BERT 98%→10.9%; RF beats deep models; pretraining ≈ useless.
- [Less is More: Simplifying Network Traffic Classification Leveraging RFCs (arXiv:2502.00586)](https://arxiv.org/pdf/2502.00586)
- [Bias in the Shadows: Shortcuts in Encrypted Network Traffic Classification (arXiv:2601.10180)](https://arxiv.org/pdf/2601.10180)
- [Wright et al., Spot Me If You Can (IEEE S&P 2008)](https://www.cs.unc.edu/~fabian/papers/oakland08.pdf) — phrase recovery from encrypted VoIP packet lengths.
- [Cherubin, Bayes not Naïve — Security Bounds on WF Defenses (PETS 2017, arXiv:1702.07707)](https://arxiv.org/pdf/1702.07707)
- [Li, Guo, Hopper — WeFDE: Measuring Information Leakage in WF Attacks and Defenses (CCS 2018)](https://www-users.cse.umn.edu/~hoppernj/wefde-ccs2018.pdf)
- [DeepSE-WF (arXiv:2203.04428)](https://arxiv.org/pdf/2203.04428)
- [Xue et al., OpenVPN is Open to VPN Fingerprinting (USENIX Sec 2022)](https://www.usenix.org/system/files/sec22-xue-diwen.pdf) — two-phase passive filter + active prober; Best Paper + Internet Defense Prize.
- [Maghsoudlou et al., Characterizing the VPN Ecosystem in the Wild (PAM 2023, arXiv:2302.06566)](https://arxiv.org/pdf/2302.06566) — 9.8M VPN servers; SSTP >90% TLS-downgrade vulnerable.
- [Chen et al., Classify Traffic Rather Than Flow (IEEE TNSM 21(2) 2024)](https://dl.acm.org/doi/abs/10.1109/TNSM.2023.3322861) — TSHC-SW multi-flow classification; names the multiplexed-stream problem.
- [Network Intrusion Datasets: A Survey, Limitations, and Recommendations (arXiv:2502.06688)](https://arxiv.org/pdf/2502.06688)
- [Towards a better labeling process for network security datasets (arXiv:2305.01337)](https://arxiv.org/pdf/2305.01337)
- [ConCap (arXiv:2509.16038)](https://arxiv.org/html/2509.16038), [NetSecBed (arXiv:2604.04121)](https://arxiv.org/pdf/2604.04121), [Gotham Testbed (arXiv:2207.13981)](https://arxiv.org/pdf/2207.13981)
- [Luxemburk & Čejka, Fine-grained TLS services classification with reject option (arXiv:2202.11984)](https://arxiv.org/pdf/2202.11984)
- To read: [Hybrid Quantum Security for IPsec (arXiv:2507.09288)](https://arxiv.org/pdf/2507.09288), [Q-RAN (arXiv:2510.19968)](https://arxiv.org/pdf/2510.19968) — OQ-25.

### Tier 4 — Projects and issue trackers
- [corelight/zeek-spicy-ipsec](https://github.com/corelight/zeek-spicy-ipsec) — BSD-3; ESP/AH/IKEv1/IKEv2.
- [ukncsc/zeek-plugin-ikev2](https://github.com/ukncsc/zeek-plugin-ikev2)
- [Suricata IKE keywords](https://docs.suricata.io/en/latest/rules/ike-keywords.html) · [ipsec-events.rules](https://github.com/OISF/suricata/blob/main/rules/ipsec-events.rules) · **[Bug #2861 — weak-DH rule did not fire](https://redmine.openinfosecfoundation.org/issues/2861)**
- **[Wireshark issue #21072 — IKEv2 dissector does not decode RFC 9370 / ML-KEM](https://gitlab.com/wireshark/wireshark/-/work_items/21072)**
- [Wireshark ESP preferences](https://wiki.wireshark.org/ESP_Preferences) · [IKEv2 decryption table](https://www.wireshark.org/docs/wsug_html_chunked/ChIKEv2DecryptionSection.html) · [test/captures](https://github.com/wireshark/wireshark/tree/master/test/captures)
- [royhills/ike-scan](https://github.com/royhills/ike-scan) (GPL-3.0) · [Nmap ike-version NSE](https://nmap.org/nsedoc/scripts/ike-version.html)
- [strongSwan 6.0.0 release notes](https://strongswan.org/blog/2024/12/03/strongswan-6.0.0-released.html) — RFC 9370 + ML-KEM · [swanctl.conf reference](https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html) · [IP-TFS docs](https://docs.strongswan.org/docs/latest/features/iptfs.html) · [retransmission](https://docs.strongswan.org/docs/latest/config/retransmission.html)
- [Scapy isakmp.py / contrib/ikev2.py / layers/ipsec.py](https://github.com/secdev/scapy)
- [5u5urrus/IkeProbe](https://github.com/5u5urrus/IkeProbe) · [ptsankov/secfuzz](https://github.com/ptsankov/secfuzz)
- [nprint/nprint](https://github.com/nprint/nprint) · [linwhitehat/ET-BERT](https://github.com/linwhitehat/ET-BERT) · [NSSL-SJTU/YaTC](https://github.com/NSSL-SJTU/YaTC) — reference/baseline only (DEC-006)

### Tier 5 — Vendor / practitioner
- Palo Alto KB on NO_PROPOSAL_CHOSEN — *"won't be visible in a packet capture unless the pcap is manually decrypted"* (PE-01)
- Cisco *Understand and Use Debug Commands to Troubleshoot IPsec*; Fortinet *IKEv2 IPsec tunnel flaps at every IPsec rekey*; F5 *IPsec tunnel does not rekey at expected lifetime*; Red Hat *How to troubleshoot IPsec VPN misconfigurations*
- [MIT LL VNAT dataset](https://www.ll.mit.edu/r-d/datasets/vpnnonvpn-network-application-traffic-dataset-vnat)
