# Discover D5 — Dataset Landscape and Generation Feasibility

**Purpose:** answer Q13–Q16 / OQ-09. Determine whether any existing dataset can support this
project, and if not, what a defensible generation methodology looks like.

---

## 1. Headline conclusion

> **No public dataset exists that supports this problem.** Not one surveyed corpus contains IPsec
> traffic labelled with its cryptographic configuration. The nearest neighbours are OpenVPN-based,
> a decade old, and documented as substantially unencrypted.
>
> `[FACT]` This is not a gap to lament — it is **PS deliverable (A) + (B) restated**, and it is the
> single most defensible original contribution available to this project. A rigorously constructed,
> openly documented, configuration-labelled IPsec corpus would be a **first**, and it is buildable.

---

## 2. Existing datasets — assessment

| Dataset | Protocol | IPsec? | Config labels? | Verdict |
|---|---|---|---|---|
| **ISCXVPN2016** (UNB CIC) | **OpenVPN, UDP mode only** | ❌ | ❌ | **REJECT** |
| **VNAT** (MIT Lincoln Laboratory) | VPN/non-VPN, 165 pcaps, 36.1 GB, 33,711 connections, ~272 h, 10 apps in 5 groups | ❌ (not IPsec-configuration-labelled) | ❌ | **Reference / baseline only** |
| **CIC-Darknet2020, CICIDS2017/2018** | Mixed IDS traffic | ❌ | ❌ | **REJECT** for our task |
| **Wireshark `test/captures/`** | IKEv1, IKEv2, ESP | ✅ | ✅ **partially — in the filenames** | **ADOPT as a validation oracle** |
| **Zeek `spicy-analyzers` test pcaps** | `ipsec-ikev1-isakmp-main-mode.pcap`, `ipsec_client.pcap` | ✅ | partial | **ADOPT as parser fixtures** |
| Wireshark wiki SampleCaptures | incl. an IKEv2 site-to-site Cisco↔Cisco capture, **AES-256-GCM + DH group 19**, full handshake then ESP | ✅ | ✅ (documented) | **ADOPT — a real-vendor sample** |
| NetResec public pcap index, Chris Sanders captures | Mixed | occasional | ❌ | Discovery only |
| Kaggle | Mostly derived CSV feature tables from the CIC family | ❌ | ❌ | **REJECT** — inherits upstream flaws |

### 2.1 Why ISCXVPN2016 must be refused, explicitly `[STRONG]`

Four independent problems, each disqualifying on its own:
1. **~98.9% of the traffic is unencrypted** — the core failure identified in the 2025 SoK.
2. **OpenVPN in UDP mode only** — no IPsec, and results do not generalise beyond that one protocol.
3. **Documented data-integrity discrepancies** in the VPN captures.
4. **Ten years old**, predating TLS 1.3 and modern application behaviour; class imbalance and
   sampling bias on top.

> Naming this refusal *explicitly* in the SIH report is worth more than any benchmark number.
> Nearly every competing team that uses ML will use this dataset without knowing any of the above.

### 2.2 The one genuinely useful find — Wireshark's labelled IKE/ESP corpus `[FACT]`

`wireshark/test/captures/` contains algorithm-labelled captures with keys available in the test
suite:

```
ikev2-decrypt-3des-sha1_160.pcap      ikev2-decrypt-aes192ctr.pcap
ikev2-decrypt-aes128ccm12.pcap        ikev2-decrypt-aes256cbc.pcapng
ikev2-decrypt-aes128ccm12-2.pcap      ikev2-decrypt-aes256ccm16.pcapng
ikev1-certs.pcap    ikev1-bug-12610.pcapng.gz    ikev1-bug-12620.pcapng.gz
esp-bug-12671.pcapng.gz
```

Why this is disproportionately valuable:
- It spans suites we might not otherwise configure — **3DES-SHA1, AES-CCM-12, AES-CTR-192,
  AES-CBC-256, AES-CCM-16** — giving independent coverage of the IV/ICV/alignment space that the
  **F-04 length-residue sieve** depends on.
- It provides **third-party ground truth**, immunising the sieve's validation against the criticism
  "you only tested it on traffic your own testbed produced."
- The `-bug-` captures are malformed/edge-case inputs — free **robustness and fuzz fixtures**.
- Plus a real Cisco↔Cisco IKEv2 AES-256-GCM/DH-19 sample from the wiki: **vendor diversity** without
  owning vendor hardware.

**Action:** adopt as the parser-conformance and sieve-validation corpus. Licensing of Wireshark test
assets to be confirmed — **OQ-20**.

---

## 3. What our dataset must avoid — inherited failure modes

`[STRONG]` The intrusion-dataset literature has catalogued exactly how this goes wrong:

- **CICIDS2017** — Engelen et al. (2021) found defects in traffic generation, flow construction,
  feature extraction and labelling. Liu et al. (2022) documented errors across the whole creation
  lifecycle for CIC-IDS-2017 and CSE-CIC-IDS-2018. Lanvin et al. (2023) additionally found **packet
  misordering, duplicate flows, undocumented capture gaps and labelling errors that materially
  change detection performance.**
- Time-and-address-based labelling (label by attack window + attacker/victim IP) is **inherently
  prone to mislabelling**.
- The 2025 dataset survey names six recurring deficiencies: labelling, realism gaps, **data leakage**,
  class imbalance, documentation deficiency, reproducibility failure — and recommends diverse
  collection environments, transparent labelling protocols with conflict resolution, comprehensive
  documentation of every processing decision, balanced sampling, and open availability.

> **Design lesson DL-04.** Our label source must be *causal, not temporal*. We do not label by
> "what we think was running at that time." We label from the **configuration that produced the
> capture** and from **strongSwan's own SA state** (`swanctl --list-sas` / vici) — the endpoint's
> authoritative account of what it actually negotiated. This eliminates the single largest error
> class in the entire cited literature.

---

## 4. Generation methodology — prior art worth copying

`[STRONG]` Container-native reproducible testbeds are an established pattern:

| Framework | What it teaches |
|---|---|
| **ConCap** | Isolated, lightweight per-scenario network environments producing **automatically labelled** packets/flows |
| **NetSecBed** | Container-native, scenario-oriented pipeline automating parametrised execution, packet capture, log collection, service probing, feature extraction and **dataset consolidation** |
| **Gotham Testbed** | Capture on *any* link; mixes network-level and host-level sources |
| Clausen et al., *Traffic Generation using Containerization for ML* | Containerised generation for ML datasets |

Consolidated requirement, stated by that literature: *capture scenarios must be consistent and
reproducible so that a trace corresponds unambiguously to the scenario that generated it, and
individual traffic events can be related to the computational operations that caused them.*

`[INFER]` **Our advantage over all of these:** they must *infer* labels for attacks. We **command**
our labels — the IPsec configuration is an input we set, and the endpoint reports back what was
negotiated. Ground truth is not estimated here; it is constructed and then independently confirmed.
That is an unusually strong epistemic position and should be stated plainly in the SIH report.

---

## 5. Combinatorics — why the PS's implied matrix must be refused

The PS lists roughly eight axes. A naïve full cross-product:

```
mode(2: tunnel, transport) × cipher(4: AES-128-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM)
× integrity(3) × DH group(4) × PFS(2) × IP version(2) × IKE version(2) × traffic type(6)
≈ 2·4·3·4·2·2·2·6 = 9,216 cells
```
…before network conditions, implementations and repetitions. Multiply by 3 network conditions,
2 implementations and 5 repetitions and it is ~276,000 captures. Absurd, and mostly redundant.

**Reasons most cells are scientifically empty `[INFER]`:**
- **AES-128 vs AES-256 is unobservable in ESP (F-05).** Every key-length pair is a *duplicate* for
  every ESP-side task. Keep them **only** for IKE-plaintext tasks and as the deliberate
  negative-result experiment (OQ-02).
- **AEAD suites have no separate integrity transform.** The integrity axis is undefined for GCM/CCM
  — those cells do not exist.
- **Transport mode is only meaningful for endpoint-to-endpoint traffic**, and is rarely combined
  with gateway topologies. Many mode×topology cells are unrealistic.
- **RFC 9395 makes IKEv1 Historic.** Keep IKEv1 as a *deliberately weak* arm (Aggressive Mode, PSK,
  legacy transforms) rather than crossing it with everything.

**Proposed replacement `[HYP]`, to be designed properly in DELIVER:**
1. A **pairwise covering array** over the configuration axes — guarantees every *pair* of factor
   levels co-occurs in some run, typically tens of cells rather than thousands.
2. Plus **targeted full-factorial "microscopes"** on the specific hypotheses that need clean
   contrasts, each varying exactly one factor:
   - F-04 sieve → cipher-suite axis only, fixed traffic
   - F-05 negative result → AES-128 vs AES-256, everything else identical
   - A10 PFS inference → PFS on/off across DH groups, forced rekeys
   - A7 mode inference → tunnel vs transport, identical inner traffic
   - CS-01 leakage → `tfc_padding = 0 | mtu`, `mode = tunnel | iptfs`
   - CS-02 failure diagnosis → one deliberate misconfiguration per known failure mode (PE-02)
3. Plus **generalization arms**: second implementation (Libreswan), varied network conditions
   (netem loss/jitter/reorder), varied host counts and concurrency.

`[INFER]` This design *is* the scientific contribution. A covering array with named hypotheses is a
defensible experiment; a cross-product is a data-collection chore.

---

## 6. Leakage control — where this project most plausibly fails

`[STRONG]` From E-02, DL-04 and the dataset survey, the failure is near-certain unless designed out.

**Splitting rules (mandatory, to be enforced in code, not convention):**
- **Never split by packet.** E-02 shows per-packet splitting leaks flow identity through sequence
  numbers and timestamps.
- **Never split by flow within one capture session.** Same SA, same SPI, same host clock, same
  netem seed — the model learns the session, not the phenomenon.
- **Split by capture session at minimum;** by **configuration cell** for configuration-inference
  tasks; by **implementation** and by **network condition** for the generalization claims.

**Mandatory evaluation arms:**
- Leave-one-configuration-out
- Leave-one-implementation-out (strongSwan → Libreswan)
- Leave-one-network-condition-out
- Cross-vantage degradation (V1 → V0)
- **Feature occlusion** (per E-01) — remove the feature we believe is doing the work and confirm
  performance drops for the reason we claim
- **A deliberate shortcut hunt:** train on a feature set that *should* carry no signal (e.g. outer
  IP addresses, capture-file index) and confirm it fails. If it succeeds, the corpus is
  contaminated.

`[INFER]` The single highest-value negative control: **train a classifier to predict AES-128 vs
AES-256 from ESP features.** Theory (F-05) says it is impossible. If the model succeeds, we have a
leakage bug — the corpus tells the model which capture file it came from. This is a **built-in
contamination detector**, which is a genuinely elegant design and worth highlighting to a jury.

---

## 7. Traffic realism

The PS asks for VoIP, WhatsApp-like, e-mail, web, ICMP, video. `[INFER]` The trap is generating each
in isolation (§D4 §3). Requirements:
- **Concurrent, multiplexed traffic must be the default arm**, not an afterthought — this is the
  production reality of tunnel mode.
- Single-application arms are retained only as a *controlled contrast*, and their results must be
  reported as an upper bound that does not transfer.
- Class balance must be designed, not accidental.
- Background/idle traffic (DPD, keepalives, rekeys) must be present — it is the dominant content of
  a real tunnel and it is what SA-lifecycle analysis (CS-03) actually consumes.

`[UNK]` Realism ceiling: synthetic traffic will never fully match production. The honest framing is
that our dataset is a **controlled instrument** for measuring analyzer behaviour under known ground
truth, not a claim about the population of real-world VPNs. Say so.

---

## 8. Open questions from D5

- **OQ-09 → closed.** No IPsec-configuration-labelled public dataset exists. Generation is required
  and is itself a contribution.
- **OQ-20** (new) Licensing of Wireshark/Zeek test captures for redistribution inside our dataset.
- **OQ-21** (new) What is the realistic ceiling on capture volume given available hardware, and does
  the covering array fit inside it?
- **OQ-22** (new) Is there any published measurement of ESP's share of real backbone traffic?
  Searched CAIDA/MAWI literature and found none — recorded as a genuine `[UNK]` rather than
  guessed at.
