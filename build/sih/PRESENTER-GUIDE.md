# TunnelScope presenter's guide

How it works, what every attribute means, and what it is built with. Rule names, threats and results are read from the code when this file is built.

## 1. The pitch in one paragraph

A VPN is only as secure as its settings, and most of an IPsec tunnel is encrypted, so an outside observer can read some things and not others. TunnelScope reads what is readable, infers what is hidden only with a stated confidence, judges everything against written standards, and says plainly what it cannot know. Every fact carries a label, every verdict cites its rule, and unknown is never scored as safe.

## 2. How it works, step by step

1. **Capture.** A pcap file, or a live stream cut into short windows (`tunnelscope live`).
2. **Read.** `tshark` (Wireshark's dissector) reads IKE, ESP and AH headers. Only `tunnelscope/ingest/tshark.py` ever runs it. Payloads are never decrypted.
3. **Evidence.** Extractors turn packets into *findings*: an attribute, a value, a label (observed, inferred, measured, unknown, not observable), a vantage, the packet it came from. An unknown finding is not allowed to carry a value; the code refuses.
4. **Judge.** YAML rule files are run against the findings. Each rule yields PASS, FAIL or UNKNOWN and cites its standard.
5. **Models.** Four models we trained fill in what the wire is silent about (section 5).
6. **Score.** Threats are rated by likelihood and impact into a threat matrix and one risk score, with an evidence-confidence figure.
7. **Deliver.** Dashboard, executive and technical reports, a CycloneDX cryptographic bill of materials, plain-English explanations, change detection.

**Vantage** says how much access a finding needed. T0: the encrypted packets only. T1: the plaintext handshake. T2: data from the endpoint itself (the tool can cross-check it). T3 keys, T4 active probing: deliberately out of scope.

## 3. Every attribute, explained

Attributes are the facts TunnelScope extracts for each tunnel. They appear in the dashboard's **Evidence** tab.

### IKE version  (`ike_version`)

- **What it is:** Which IKE protocol version the tunnel uses: IKEv1 (old) or IKEv2.
- **How we get it:** Read from the exchange type in each IKE message header.
- **Label:** OBSERVED, T1
- **Why it matters:** IKEv1 is retired. DISA V-207205 requires IKEv2. Threat TH-06.

### IKE exchanges seen  (`ike_exchanges`)

- **What it is:** Which IKE exchanges appear in the capture (IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL...).
- **How we get it:** Read from the exchange types.
- **Label:** OBSERVED, T1
- **Why it matters:** Shows how much of the handshake the capture contains. A capture that starts mid-tunnel says so, instead of pretending.

### IKE SA SPIs  (`ike_spi`)

- **What it is:** The two 8-byte identifiers that name one IKE security association.
- **How we get it:** Read from the IKE header.
- **Label:** OBSERVED, T1
- **Why it matters:** Groups packets into one tunnel record. They change at each rekey, so the tunnel is identified by its endpoint pair.

### Handshake (IKE SA) PRF  (`ike_prf`)

- **What it is:** The function used to derive the session keys.
- **How we get it:** Chosen transform in the responder's IKE_SA_INIT reply.
- **Label:** OBSERVED, T1
- **Why it matters:** For AES-GCM there is no separate integrity algorithm, so the PRF is the closest thing; the tool says so.

### Handshake (IKE SA) encryption  (`ike_encr`)

- **What it is:** The cipher and key length that protect the IKE handshake itself, for example AES-CBC-256.
- **How we get it:** Chosen transform in the IKE_SA_INIT reply. Uses the LAST reply that actually selects a suite, so a refused first attempt cannot hide it.
- **Label:** OBSERVED, T1
- **Why it matters:** RFC8247-ENCR. This is the handshake's cipher, not the data cipher: keep those two apart.

### Handshake (IKE SA) integrity  (`ike_integ`)

- **What it is:** The integrity algorithm for the IKE handshake, for example HMAC-SHA2-256-128.
- **How we get it:** Chosen transform in the IKE_SA_INIT reply. Absent for AEAD suites such as GCM.
- **Label:** OBSERVED, T1 (UNKNOWN for GCM)
- **Why it matters:** DISA V-207223 asks for SHA-2 at 384 bits or more. Threat TH-05.

### Handshake key-exchange group  (`ike_dh_group`)

- **What it is:** The key-exchange group chosen (MODP-2048, ECP-384, Curve25519, ...). This is what protects the keys.
- **How we get it:** Chosen key-exchange transform in the reply.
- **Label:** OBSERVED, T1
- **Why it matters:** V-207193 (DISA, group 16 or higher) and RFC8247-DH-MUST. Weak groups mean the keys can be recovered. Threat TH-01.

### Key-exchange groups offered  (`ike_offered_dh`)

- **What it is:** Every group the initiator was willing to use.
- **How we get it:** All key-exchange transforms in the initiator's plaintext IKE_SA_INIT.
- **Label:** OBSERVED, T1
- **Why it matters:** RFC8247-DH-OFFER. A tunnel can negotiate a strong group while its endpoint still accepts a forbidden one: that is downgrade exposure. Only the initiator's offer is visible.

### Post-quantum key exchange  (`pq_key_exchange`)

- **What it is:** Whether a post-quantum key exchange (ML-KEM hybrid) was used, offered, or absent.
- **How we get it:** Additional key-exchange transforms and extra IKE messages in plaintext (RFC 9370).
- **Label:** OBSERVED, T1
- **Why it matters:** DST-PQ-KE and DST-PQ-DOWNGRADE. Threats TH-02 (harvest now, decrypt later) and TH-03 (downgrade).

### IPsec protocol(s)  (`ipsec_protocols`)

- **What it is:** Whether the data is carried by ESP, AH, or both.
- **How we get it:** IP protocol numbers 50 (ESP) and 51 (AH), excluding headers merely quoted inside ICMP errors.
- **Label:** OBSERVED, T0
- **Why it matters:** AH alone authenticates but does not encrypt: RFC4301-CONFIDENTIALITY, threat TH-07.

### Data (ESP) cipher: candidates  (`esp_cipher_family`)

- **What it is:** The set of ESP ciphers consistent with the packet lengths.
- **How we get it:** The 'cipher sieve': each family has fixed IV, ICV and alignment rules, so lengths rule families out.
- **Label:** INFERRED, T0
- **Why it matters:** A candidate SET, never one answer. It cannot tell AES-128 from AES-256 (both give identical sizes), and the tool says that is provable, not a shortcoming.

### Data (AH) integrity  (`ah_integrity`)

- **What it is:** The integrity algorithm used by AH.
- **How we get it:** AH's integrity value sits in the clear; its length (12, 16, 24 or 32 bytes) names the algorithm family.
- **Label:** OBSERVED or INFERRED, T0
- **Why it matters:** RFC8221-AH-INTEG and -LEGACY. A 12-byte value cannot tell MD5 from SHA-1, so that rule says UNKNOWN, not FAIL.

### Tunnel / transport mode  (`mode`)

- **What it is:** Tunnel mode (the whole original packet is wrapped) or transport mode (only the payload is).
- **How we get it:** AH: read from its next-header field. ESP: transport is proven when a packet is smaller than any tunnel packet can be; otherwise a model estimate for TCP over AEAD; otherwise unknown.
- **Label:** OBSERVED, INFERRED, or UNKNOWN
- **Why it matters:** The brief asks for it. Tunnel mode is never claimed from ESP traffic alone.

### Sequence numbers (replay)  (`sequence_integrity`)

- **What it is:** Whether any sequence number is used twice on one SA.
- **How we get it:** Per-SPI ESP/AH sequence numbers; separates real repeats from a second tap recording the same packet.
- **Label:** OBSERVED, T0
- **Why it matters:** RFC4303-SEQ. A repeat means a replay or a broken sender. Whether the receiver drops replays is not visible. Threat TH-08.

### Perfect forward secrecy  (`pfs`)

- **What it is:** Whether a rekey used a fresh key exchange (perfect forward secrecy).
- **How we get it:** The rekey message is larger when it carries a key exchange (a 256-byte gap, experiment EXP-03).
- **Label:** INFERRED, needs a rekey in the capture
- **Why it matters:** Without PFS one stolen key exposes past and future keys. Threat TH-11.

### Rekey interval (key lifetime)  (`rekey_cadence`)

- **What it is:** How often the tunnel rekeys.
- **How we get it:** Time between observed CREATE_CHILD_SA exchanges.
- **Label:** MEASURED with 2 or more rekeys, else NOT_OBSERVABLE
- **Why it matters:** Evidence for key lifetime. It is a measurement, never a claimed configured lifetime.

### Peer authentication method  (`peer_auth_method`)

- **What it is:** How the peers proved who they are: pre-shared key, certificate or EAP.
- **How we get it:** Not on the wire: negotiated inside the encrypted IKE_AUTH.
- **Label:** NOT_OBSERVABLE
- **Why it matters:** We tested the tempting shortcut (certificate requests) and it was misleading, so we report not observable.

### Responder certificate capability  (`responder_cert_capability`)

- **What it is:** Whether the responder has any certificate trust anchor loaded.
- **How we get it:** A certificate request in the plaintext IKE_SA_INIT.
- **Label:** OBSERVED, T1
- **Why it matters:** Describes the responder's policy, not the method this tunnel used.

### Negotiation outcome  (`negotiation_outcome`)

- **What it is:** Whether the tunnel came up, or why it failed (proposal mismatch, traffic-selector mismatch, authentication failure).
- **How we get it:** Message sizes and notify codes, by a written decision tree (experiment EXP-06).
- **Label:** OBSERVED or INFERRED
- **Why it matters:** Turns 'the VPN is down' into a cause an engineer can fix.

### CVE-2026-78135 pattern  (`early_childsa_cve`)

- **What it is:** The CVE-2026-78135 pattern: a Child SA requested before authentication finished.
- **How we get it:** IKE message IDs and exchange order, compared per originator.
- **Label:** OBSERVED; UNKNOWN if the capture starts mid-tunnel
- **Why it matters:** Rule CVE-2026-78135, threat TH-09. Built so that not seeing the handshake is never reported as a detection.

### Metadata exposure (bits)  (`metadata_exposure`)

- **What it is:** How many bits of size and timing information leak per packet, and whether padding hides sizes.
- **How we get it:** Entropy of ESP packet lengths and inter-arrival times.
- **Label:** MEASURED, T0
- **Why it matters:** Threat TH-10. Padding can zero the size channel but leaves timing, as our experiment showed.

### Attacker exposure (Random Forest)  (`attacker_exposure`)

- **What it is:** A 0 to 100 score: how sure and consistent our attacker model is about this tunnel's traffic.
- **How we get it:** The traffic classifier is run as an eavesdropper over 2-second windows.
- **Label:** MEASURED (UNKNOWN with too little traffic)
- **Why it matters:** Turns 'traffic analysis is possible' into a number.

### Traffic type inside the tunnel  (`traffic_type`)

- **What it is:** The predicted kind of traffic inside the tunnel, with a probability and runners-up.
- **How we get it:** Random Forest over 31 numbers per 2-second window; a second model checks for mixed traffic.
- **Label:** INFERRED, or UNKNOWN when uncertain or mixed
- **Why it matters:** The brief's 'predict the type of traffic'. It abstains instead of guessing, and states its known weak spot.

## 4. The rules and the threats

### The rules (each names its standard)

| Baseline | Rule | Severity | Judges | What it checks |
|---|---|---|---|---|
| CVE-WATCH | `CVE-2026-78135` | high | CVE-2026-78135 pattern | No CREATE_CHILD_SA may be attempted before IKE_AUTH completes (pre-auth Child SA, CVE-2026-78135 pattern) |
| DISA-VPN-SRG-V2R6 | `V-207205` | high | IKE version | The IPsec VPN Gateway must use IKEv2 for IPsec SAs |
| DISA-VPN-SRG-V2R6 | `V-207193` | high | Handshake key-exchange group | IKE Phase 1 must use a Diffie-Hellman group of 16 or greater |
| DISA-VPN-SRG-V2R6 | `V-207223` | medium | Handshake (IKE SA) integrity | IKE must use FIPS-validated SHA-2 at 384 bits or higher |
| DST-NQM-2026 | `DST-PQ-KE` | informational | Post-quantum key exchange | CII cryptographic assets should negotiate a post-quantum key exchange (assess quantum risk) |
| DST-NQM-2026 | `DST-PQ-DOWNGRADE` | high | Post-quantum key exchange | A proposed PQ key exchange must not fall back to classical (prevent insecure fallback) |
| RFC-8221/4303 | `RFC4301-CONFIDENTIALITY` | medium | IPsec protocol(s) | Traffic should be protected by ESP; AH alone authenticates but does not encrypt (RFC 4301 sec 3.2) |
| RFC-8221/4303 | `RFC8221-AH-INTEG` | high | Data (AH) integrity | AH integrity must not be HMAC-MD5-96 (RFC 8221 sec 6: MUST NOT; HMAC-SHA1-96 is MUST-, HMAC-SHA2-256-128 MUST) |
| RFC-8221/4303 | `RFC8221-AH-LEGACY` | informational | Data (AH) integrity | AH integrity should be HMAC-SHA2 (RFC 8221 sec 6 marks HMAC-SHA1-96 MUST-, i.e. expected to be demoted) |
| RFC-8221/4303 | `RFC8221-ESP-3DES` | medium | Data (ESP) cipher: candidates | ESP encryption should not be 3DES (RFC 8221 sec 5: ENCR_3DES SHOULD NOT) |
| RFC-8221/4303 | `RFC4303-SEQ` | high | Sequence numbers (replay) | A sequence number must not repeat on one SA (RFC 4303 sec 3.3.3 / RFC 4302 sec 3.3.2: the counter increases and MUST NOT cycle) |
| RFC-8247 | `RFC8247-DH-MUST` | high | Handshake key-exchange group | IKE SA key exchange must not use a group RFC 8247 marks MUST NOT or SHOULD NOT (1, 2, 5, 22, 23, 24) |
| RFC-8247 | `RFC8247-DH-OFFER` | medium | Key-exchange groups offered | An initiator's offer should not include groups RFC 8247 marks MUST NOT or SHOULD NOT |
| RFC-8247 | `RFC8247-ENCR` | medium | Handshake (IKE SA) encryption | IKE encryption should be AES (GCM preferred; CBC acceptable) |

### The twelve threats (the threat matrix)

Each threat has an impact (1 to 3). It is *present* if a rule that tests for it fails, *mitigated* if the rules pass, and *not assessable* if the evidence is unknown; not assessable is never counted as safe.

| Id | Threat | Impact |
|---|---|---|
| TH-01 | Key exchange broken by cryptanalysis | high |
| TH-02 | Harvest now, decrypt later (quantum) | high |
| TH-03 | Downgrade attack | high |
| TH-04 | Weak or legacy cipher | medium |
| TH-05 | Tampering via weak integrity | medium |
| TH-06 | Legacy protocol (IKEv1) | high |
| TH-07 | No confidentiality (plaintext payload) | high |
| TH-08 | Replay of captured packets | medium |
| TH-09 | Pre-authentication exploitation (CVE-2026-78135) | high |
| TH-10 | Traffic analysis (metadata exposure) | low |
| TH-11 | No forward secrecy on rekey | medium |
| TH-12 | Configuration drift | medium |

### The scores

- **Risk score (0 to 100):** `100 x (1 - product(1 - 0.6 x likelihood x impact / 9))` over the present threats. Adding a threat never lowers it. 0 means none was seen in what could be assessed, not that the tunnel is safe. It is a designed formula, not measured against real attacks.
- **Evidence confidence:** the share of the attributes we assess that this capture supports, weighting observed 1.0 and inferred by its stated confidence.
- **Model confidence:** the traffic classifier's own probability. Not the same as accuracy.
- **Per-baseline compliance scores:** one per standard, never averaged together, so a disagreement between DISA and RFC 8247 stays visible.

## 5. The four models (all trained by us)

| Model | Method | Input | Output | Trained on |
|---|---|---|---|---|
| Traffic type | Random Forest (scikit-learn) | 31 numbers per 2-second window: packet counts, sizes, timing gaps, size histogram, direction | 1 of 8 types + confidence, or uncertain | 9,369 windows: 4,667 from 472 lab sessions (synthetic shapes, real applications, Libreswan, delayed and lossy links) and 4,702 from 82 real OpenVPN tunnels in MIT Lincoln Laboratory's public VNAT dataset (EXP-19) |
| Mixed traffic | Random Forest | The pattern of the first model's per-window probabilities | single vs mixed | The project's own mixed and single sessions |
| Tunnel or transport | Random Forest | Shares of ACK-sized packets | mode + confidence, or abstain | Tunnel and transport sessions |
| Change detection | Isolation Forest, plus rules and robust statistics | A tunnel's posture and traffic profile over time | normal, changed, learning | Each tunnel's own history |

No pretrained or third-party AI model is used, and a test fails if one is ever added. Models ship as plain arrays (no pickle) and train in about a second at first use. The eight traffic types are voip, web, bulk file transfer, interactive shell, video, e-mail, messaging and icmp; they are traffic *shapes* (real software against lab servers, plus a seeded generator), not app fingerprints.

## 6. What it is built with

**Analysis engine (Python)**
- Python 3.11 or newer (developed on 3.13); `tshark` for reading packets; `scikit-learn` and `numpy` for the models; `PyYAML` for the rule files.
- Local server: Python standard library `http.server`, bound to 127.0.0.1 only. CLI: `argparse`.
- Outputs: Markdown and HTML reports, CycloneDX 1.6 JSON (CBOM).

**Dashboard (web)**
- React 19, TypeScript 6, Vite 8, Tailwind CSS 4, Radix UI components, Recharts 3, lucide icons.
- three.js for the intro and background tunnel, Motion and GSAP for animation. Fonts: Geist, Geist Mono, and Kufica Bold for the wordmark.

**Lab (Docker)**
- strongSwan 5.9.8 and 6.1.0, Libreswan 5.4, and a real OpenBSD `iked` 7.9 VM for one experiment.
- A router container with `tcpdump` and no keys (the observer's position); `tc netem` for delay and loss.
- Real software for traffic: Chromium, nginx, OpenSSH and SFTP, Postfix with swaks, Prosody (XMPP), ffmpeg (RTP), ping.

**Quality and process**
- `pytest` (392 tests), 60 browser checks (Playwright), GitHub Actions CI, a ground-truth check against each endpoint's own `swanctl` output, a dataset hash check, and a check against other people's public captures.
- Double Diamond method; pre-registered experiments (predictions written before capture; failures kept); an offline install bundle proven in an air-gapped container.
- Standards used: DISA VPN SRG V2R6, RFC 4301, 4302, 4303, 7296, 8221, 8247, 9370, CycloneDX, the DST/NQM post-quantum report; DPDP Rules 2025 and CERT-In as context only.

## 7. Questions judges ask

- **Is it really AI?** The parts that need judgement are AI: traffic type, mixed traffic, mode, change detection. Plaintext fields are read exactly, because guessing them would be worse.
- **Can you tell AES-128 from AES-256?** No, and nobody can from outside: both give identical packet sizes. We prove it and say so.
- **Do you decrypt anything?** Never. Headers, sizes and timing only.
- **How accurate is it on real traffic?** 0.986 macro-F1 on held-out runs in our lab. A model trained on synthetic traffic only scored 0.461 on real applications, which is why it also trains on real applications. On traffic we did not make (real VPN traffic recorded by MIT Lincoln Laboratory, the public VNAT dataset) the lab-trained model scored only 0.472; after adding 4,702 real windows it scores 0.741 on real capture files it never saw. That is below the 0.80 we wrote down in advance; we shipped it as an owner decision (DEC-036) because it was a large gain with no loss on our lab tests. That traffic is OpenVPN, not IPsec, and on its own it did not transfer to IPsec (0.378), so real IPsec traffic is still the gap.
- **Why several scores instead of one?** DISA and RFC 8247 disagree about some groups. One blended number would hide that.
- **What is the risk score based on?** A designed formula over rated threats. It ranks tunnels sensibly; it is not a measured probability of an attack.
- **What would you do next?** Delay and packet loss (already pre-registered), vendor equipment and a real cloud tunnel, and learning on the customer's own network. Since EXP-17 ran: we found and closed that gap already — the traffic classifier's accuracy under delay/loss went from 0.53/0.38 to 0.98/0.91 by retraining on impaired-network captures (`experiments/exp17-network-conditions/`).
- **Isn't this still just a report? The auditor still has to read it and patch things by hand.** Not any more, in the lab. For each failed rule that a config change can fix, the dashboard proposes the exact change, and the analyst approves it. TunnelScope then previews the real diff (on copies of the config, and strongSwan loads it in a throwaway container), applies only what was previewed, captures again, and forces a rekey. It says "Confirmed fixed" only if the rule now passes, no other rule got worse and the tunnel stays up. Otherwise it undoes the change itself and checks the files are restored byte for byte. It only ever touches the lab, never a real VPN. Rules that cannot be judged from the wire (for example whether AH uses MD5 or SHA-1, which look identical) are refused with that reason rather than "fixed" blind.
- **Would you use a local AI model, like an LLM?** Every model that decides something (traffic type, mode, anomaly, mixed traffic) is ours, trained on our own captures (the traffic-type model also on public real VPN traffic). We did test a small language model that runs offline on the laptop (MiniCPM, 2B) for one job: drafting fixes. Code checks every draft, and we pre-registered a pass bar before testing it (EXP-18). The checks stopped all 32 deliberately bad drafts, but the model got 0 of 16 real fixes right, so drafting stays switched off; only the written fixes are used. It may still reword explanations, never decide a verdict. That is the honest answer: we measured it, it was not good enough, and the safety net held.
- **How do you find vulnerabilities — do you have a database? What about a zero-day?** Two layers, the same split real security tools use. (1) Known: 14 rules from 5 named baselines (DISA VPN SRG, RFC 8247, RFC 8221/4303, the DST post-quantum guidance, and CVE-2026-78135 as one worked CVE example) — a small, hand-curated set, not NVD's 190,000+ entries, and not a live feed. (2) Unknown: per-tunnel anomaly detection (`tunnelscope/anomaly/`) learns each tunnel's normal crypto, traffic shape and behaviour, then flags a DEVIATION from it — a downgrade, an unusual traffic pattern, or a tunnel behaving unlike the rest of the fleet — with no idea what caused it. That is the honest answer to "zero-day": we cannot name an unknown vulnerability, nothing can, by definition. We can notice a tunnel's behaviour changed from its own history and put that in front of a human before they'd otherwise notice. Stated limit: the anomaly layer needs a baseline first (`MIN_BASELINE = 2` observations minimum before it reports anything but "learning") — a zero-day on the very first-ever observation of a tunnel would only be caught if it happens to match a known rule.

## 8. Where to show the code

- `tunnelscope/evidence/extract.py` and `protocol.py`: packets to findings. `tunnelscope/rules/*.yaml`: the rules. `tunnelscope/assess/engine.py`: the judge.
- `tunnelscope/risk/risk.py`: threats and score. `tunnelscope/leakage/`: the traffic and mode models. `tunnelscope/anomaly/`: change detection. `tunnelscope/live/`: live mode.
- `fleet-dashboard/src/`: the dashboard. `testbed/`: the lab. `experiments/`: each experiment with its pre-registration and result.