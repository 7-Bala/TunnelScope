# 11 — Existing Solutions Deep Dive

**Date:** 2026-09-11 · **Trigger:** user request (targeted reopening of the research freeze, logged
as T-020 in `TODO.md`) · **Raw data:** `research/data/solutions-maintenance-2026-09-11.json`

**Method.** Everything here was checked at the source rather than taken from marketing pages or
READMEs:
- **Maintenance figures** come live from the GitHub API on 2026-09-11 (commits in the last 12 months,
  last commit, latest release, licence).
- **Capability claims** for open-source tools were verified by reading the parser source code itself
  (Wireshark `packet-ike.c`, Suricata `rust/src/ike/*` and its `ipsec-parser` crate, Zeek
  `analyzer.spicy`, Arkime `capture/parsers/isakmp.c`, nDPI `protocols/ipsec.c`, Greenbone's
  installed NVT feed).
- **Released-software behaviour** was tested against our own ML-KEM capture with the tshark release
  installed on this machine.
- **Competing projects** were found via GitHub search; their code was read, and treated as data only.

Evidence tags as before: `[FACT]` verified at the source · `[STRONG]` multiple independent sources ·
`[INFER]` reasoned from facts · `[HYP]` untested · `[UNK]` unknown.

---

## 1. What exactly is the problem?

Stripped of the PS's wording, and using what Discover and our experiments established, the problem
is **five problems stacked on top of each other**:

| # | Sub-problem | What the analyst actually needs | Hard because |
|---|---|---|---|
| P1 | **Protocol visibility** | See the IKE/ESP fields that are on the wire | Largely solved — see §3 |
| P2 | **Configuration recovery** | Know what was negotiated: ESP cipher, mode, PFS, lifetime, auth, PQ key exchange | Most of it sits inside **encrypted** IKE_AUTH (F-01). Some is recoverable from structure (EXP-03, EXP-04), some partially (EXP-01), some never (F-05) |
| P3 | **Assessment** | A verdict — secure? compliant with *which* standard? downgraded? — with the evidence behind it | Needs policy knowledge, multi-baseline mapping, and honesty about what couldn't be observed |
| P4 | **Behaviour over time** | What the tunnel actually does: rekey cadence, failures, flapping, leakage | Needs measurement across time, not one handshake |
| P5 | **Traffic / metadata inference** | What a passive observer can learn about what's inside | Easy to fake (as §3.F shows); hard to do honestly |

**The PS's own framing** asks for all five, but spends most of its words on P2 and P5, and frames
both as AI problems.

---

## 2. The questions asked of every solution

The user's questions, plus the ones I added because the answer changes what we build (marked ★):

1. **What does it do, and how does it work?** — the mechanism.
2. **How was it built?** — language, architecture, dependencies.
3. **Is it actively maintained?** — dated metrics, not impressions.
4. **Which part of the problem (P1–P5) does it address, and does it bridge the gap?**
5. **Where does it fall short?**
6. **Does it follow the PS, or drift from it?**
7. ★ **Is it current?** — IKEv2-first? RFC 9370 / ML-KEM aware? The PS is dated 2026 and India's
   PQ roadmap makes this decisive.
8. ★ **Does it produce an *assessment*, or only *fields* / *alerts*?**
9. ★ **Which vantage tier does it need** (T0 passive … T4 active)?
10. ★ **Does it show its evidence and admit what it couldn't see?**
11. ★ **Licence — can we reuse it, and on what terms?**
12. ★ **Can it run offline / air-gapped?** — relevant for an NTRO deployment.
13. ★ **Reuse verdict for us** — REUSE / WRAP / EXTEND / REFERENCE / AVOID.

---

## 3. Solution-by-solution

### 3.A Packet dissectors and passive analyzers

#### Wireshark / tshark — `[FACT]` **Solves P1, now including post-quantum IKE. Does not assess.**

- **How it works.** A per-protocol dissector (`epan/dissectors/packet-ike.c`, 8,823 lines, C) walks
  each ISAKMP/IKE payload and renders every field into a tree. Given keys, it can also decrypt IKE
  (IKEv1/IKEv2 decryption tables) and ESP (ESP SA table, AEAD with ICV check via libgcrypt).
- **How it was built.** C, GPL-2.0, huge contributor base. The dissector was **renamed
  `packet-isakmp.c` → `packet-ike.c` in May 2026** (commit `ff53d6096b`).
- **Maintenance.** Very active: **3,968 commits in the last 12 months**; last commit 2026-09-11.
- **⚠️ Correction to our own research.** Discover (07-DISCOVER, PQ-3) treated **GitLab issue #21072**
  — *"IKEv2 dissector does not display updated field names from RFC 9370"* — as an open gap and a
  pillar of our PQ novelty claim. **That issue was closed on 2026-03-14**, five days after it was
  filed. Current `master` defines `IKE_INTERMEDIATE (43)`, transform types `ADDKE1`–`ADDKE7`, and
  names `ML-KEM-512/768/1024` (IDs 35/36/37).
- **Released version, tested on our capture.** tshark **4.6.4** (installed here) already shows
  `Exchange type: IKE_INTERMEDIATE (43)` and `Transform Type: ADDKE1 (6)`, but prints the algorithm
  as a bare `Transform ID: 36` rather than "ML-KEM-768". The full naming is on `master` and will
  reach users in the next release.
- **Falls short on:** P2 beyond what's plaintext; P3, P4, P5 entirely. It is a viewer. The friction
  catalogued in D2 — manual per-SA keys, hidden preferences, "Decode As" — is still the analyst's
  problem.
- **PS alignment:** covers the "packet-level visibility" the PS explicitly describes as *not enough*.
- **Reuse:** **REUSE** as ingestion (`tshark -T json/ek`) and as an independent oracle. Shell out
  rather than link, because of GPL-2.0.

#### Zeek + `corelight/zeek-spicy-ipsec` — `[FACT]` **Partial P1, and out of date.**

- **How it works.** Zeek has **no built-in IPsec analyzer**: `scripts/base/protocols` covers 33
  protocols and none is IPsec/IKE. The add-on package is a Spicy grammar (`analyzer.spicy`, 655
  lines) that parses IKE/ESP/AH into `ipsec.log`.
- **Maintenance.** **4 commits in 12 months**; last commit 2025-09-22; 8 stars. The only other Zeek
  IKE plugin, `ukncsc/zeek-plugin-ikev2`, is **archived** (last commit 2020).
- **Currency.** The grammar cites **RFC 4306 (2005)**. Its exchange-type enum ends at the RFC 7296
  set — **no `IKE_INTERMEDIATE`, no ADDKE transforms**. It will misread a PQ/hybrid negotiation.
- **Falls short on:** RFC 9242/9370, assessment, time behaviour.
- **Reuse:** **REFERENCE only.** Pulling in the Zeek runtime for a stale grammar isn't justified.

#### Arkime (full packet capture + search) — `[FACT]` **Indexes IKE fields. Deliberately discards ESP.**

- **How it works.** C capture engine with per-protocol parsers feeding OpenSearch/Elasticsearch.
  `capture/parsers/isakmp.c` (666 lines) handles IKEv1 and IKEv2 transforms and indexes `version`,
  `exchange-type`, `encryption`, `hash`, `dh-group`, `auth-method`, `vendor-id` and both SPIs, so
  they're searchable across a whole fleet of sessions. `esp.c` tags ESP sessions and then sets
  **`stopSaving = 1`** — it chooses not to store encrypted payload at all.
- **Maintenance.** Active: 677 commits in 12 months. Apache-2.0.
- **Falls short on:** PQ transforms (no ADDKE handling found), assessment, and anything that needs
  ESP packet geometry (P4, P5, and our EXP-01/03).
- **Reuse:** **REFERENCE** — its fleet-scale "index IKE fields and search" pattern is the right shape
  for a SOC deployment.

#### nDPI (ntop) — `[FACT]` **A new entrant to P1. Extracts, does not judge.**

- **How it works.** C deep-packet-inspection library. `src/lib/protocols/ipsec.c` (448 lines)
  detects IPsec and — **new in April 2026** — dissects IKEv2 SA_INIT proposals, storing per-proposal
  ENCR (with key bits), PRF, INTEG and DH group into flow metadata, and keeping both the IKE request
  and the response.
- **Maintenance.** Active: 425 commits in 12 months; release 6.0 on 2026-08-28.
- **Licence — changed 2026-08-22.** nDPI moved to a **dual-licence model**, but only its **QUIC, TLS
  and DNS** dissectors went dual; the **IPsec dissector remains LGPL-3.0**. The caller must declare
  commercial vs non-commercial use at initialisation.
- **Falls short on:** no risk flags for IPsec (no `ndpi_set_risk` in `ipsec.c`), no ADDKE/PQ, no
  ESP analysis, no time behaviour.
- **Reuse:** **REFERENCE / possible WRAP.** Worth noting as the most recently active open IKEv2
  extractor.

#### Suricata (IDS) — `[FACT]` **Partial P1/P3 through alert rules. Blind to PQ.**

- **How it works.** Rust app-layer parser plus rule keywords (`ike.chosen_sa_attribute` and others),
  and 14 shipped IPsec event rules (weak DH, weak encryption, no auth…) — detailed in D2.
- **Currency.** IKEv2 parsing is delegated to the **`rusticata/ipsec-parser` crate (v0.7)**, whose
  transform enum stops at ENCR/PRF/INTEG/DH/ESN. **No `IKE_INTERMEDIATE`, no ADDKE**: a PQ transform
  lands in `Unknown`. The crate's last commit was 2025-09-16.
- **Maintenance.** Suricata itself is very active (1,645 commits in 12 months; 8.0.6 released
  2026-07-07); its IKE backend is not.
- **Falls short on:** PQ, assessment (alerts, not verdicts — DL-01), and the evidence-handling
  defects documented in Suricata bug #2861.
- **Reuse:** **REFERENCE.** It's also the natural baseline for "what a SOC runs today".

#### Scapy — `[FACT]` Building blocks, not a solution.
GPL-2.0; 300 commits in 12 months; v2.7.0 released 2025-12-26. IKEv1/IKEv2/ESP layers. **REUSE**
for crafting test packets only.

### 3.B Active scanners

| Tool | How it works | Maintained? | IKEv2 | PQ | Verdict |
|---|---|---|---|---|---|
| **ike-scan** | Sends crafted IKEv1 Phase-1 proposals and fingerprints responses by Vendor ID and retransmission backoff | **No.** Last release **1.9 in 2013**; last commit 2024-09-15; 0 commits in 12 months | Experimental | No | REFERENCE (GPL-3.0) |
| **Nmap `ike-version`** | Sends 4 packets, extracts Vendor IDs only | Nmap itself active (455 commits in 12 months); the script is not | No | No | REFERENCE (NPSL — don't bundle) |
| **Greenbone / OpenVAS** — checked on the installed feed | 95,102 NVTs; **92** mention IKE/ISAKMP, but **89 are version→CVE matches**. Only 3 real protocol probes: UDP service detection, IKEv1 Aggressive-Mode disclosure (CVE-2002-1623), and a pre-2008 check. The shared library `ike_isakmp_func.inc` has **0 references to IKEv2** | Active (805 commits in 12 months) | **No** | No | REFERENCE |
| **Tenable Nessus** | Plugins such as *IKE Aggressive Mode with PSK* (`ike1_aggressive_mode_with_psk.nasl`) | Commercial | IKEv1-centric | Not found | REFERENCE |

`[FACT]` **Every active IKE scanner we examined is built around IKEv1.** The protocol has been
Historic since RFC 9395 (2023), and strongSwan 6.1.0 (released 2026-09-07) **disabled IKEv1 by
default**. No active tool enumerates IKEv2 proposals, tests RFC 9370 support, or checks for downgrade.

### 3.C Endpoint tooling (vantage T2 and T3)

- **strongSwan** (`swanctl`/vici) — authoritative SA state. Very active: 545 commits in 12 months;
  **6.1.0 released 2026-09-07**. Two things in that release matter to us:
  - **CVE-2026-78133** — a use-after-free in IKEv2 **rekey-collision** handling, potentially remote
    code execution, affecting **6.0.0 and newer**. Our lab's PQ image runs **6.0.2**, so it is
    affected. The lab is isolated, but the image should move to 6.1.0 → **T-021**.
  - **CVE-2026-78135** — a peer could get a **usable Child SA from CREATE_CHILD_SA before
    authentication completed** (5.9.7 and newer). `[HYP]` This pattern is visible to a passive
    observer: exchange type, message ID and SPIs are all plaintext, so *"CREATE_CHILD_SA on an IKE SA
    whose IKE_AUTH never succeeded"* should be detectable at T0/T1. That would be a concrete,
    CVE-backed detection capability no surveyed tool has → **T-022** (experiment).
  - **Kernel lockdown.** 6.1.0 adds support for kernels in lockdown-confidentiality mode, where
    *"we don't get the keys back when we query an SA."* On hardened hosts, **T3 (keys from
    `ip xfrm state`) is not available**. DEC-005 needs that caveat → **DEC-016**.
- **Libreswan** — very active (2,807 commits in 12 months; v5.4 on 2026-08-14). The second
  implementation for EXP-07.
- **`0101-CTRL/ipsec-pcap-decrypt`** (created 2026-08-19, Python, no licence) — turns
  `pcap + ip xfrm state` into a decrypted inner-IP capture by driving tshark's ESP-SA table. It
  automates exactly the Wireshark friction from D2 and is the T3 path in miniature. Unlicensed, so
  **REFERENCE only**.

### 3.D Commercial cryptographic-inventory and PQ products

| Product | How it discovers | IPsec/IKE covered? | Notes |
|---|---|---|---|
| **SandboxAQ AQtive Guard** — Network Analyzer | Passive: PCAP upload or the `yanadump` live sensor emitting compact JSONL | **No.** Its documentation lists **TLS and SSH only**, with no mention of IPsec, IKE or ESP. `[FACT]` (docs, 2026-09-11) | Market leader for passive crypto inventory. The gap is IPsec-shaped |
| **Keyfactor AgileSec** (ex-InfoSec Global) | **Agent**-based host scans: files, registry, memory, libraries | Only indirectly, through host configs | Not a traffic tool |
| **Palo Alto PAN-OS 12.1 "Orion"** | Firewall-native. *"Fully support[s] RFC 8784, RFC 9242, RFC 9370"* for **its own** tunnels; the Quantum Readiness / Cryptographic Inventory view reports *"cipher usage by apps, users, devices"* | Its own IKEv2/PQ tunnels, yes. **Third-party IPsec passing through: `[UNK]`**, the docs don't say | Vendor-locked, needs PAN hardware |
| **Cisco ETA, and NDR vendors** (Vectra, ExtraHop, Darktrace) | Behavioural ML over flows | No IPsec posture assessment found | Encrypted-traffic analytics is TLS-centric |

`[STRONG]` **Commercial crypto-inventory has concentrated on TLS and SSH.** The one class of product
built to answer "what cryptography is in use on my network?" doesn't cover the protocol our PS is
about, and the firewall vendor that does cover it covers only its own boxes.

### 3.E Research artefacts

- **`hypergalois/pqc-tls-observability`** (MIT, v1.0.0 on 2026-05-04, 1 commit in 12 months) — the
  multi-surface PQ observability framework from D8. **TLS-only by its authors' own statement.**
  Frozen release-style artefact: **REFERENCE**, and its schemas are reusable under MIT.
- **Mallick, Kundu & Kompella, *Study of Post Quantum status of Widely Used Protocols*
  (arXiv:2603.28728, March 2026)** — a survey of nine protocols. IPsec has *"standardised mechanisms
  but lack[s] widespread production adoption"*, and *"message size and fragmentation often
  dominate"* — **independent corroboration of our EXP-04 fragmentation finding.** It proposes no
  measurement tool.
- **`ekoh9704/PQC-IPsec-on-5G-…-Benchmark`** (MIT, July 2026) — benchmarks ML-KEM-768 and ML-DSA-65
  strongSwan IKEv2 on an Open5GS 5G core, including an **MTU sweep**. A performance study, not
  observability. Useful as a reference for PQ configs and ML-DSA certificates.
- **Encrypted-traffic-classification ML** (ET-BERT: MIT, 4 commits in 12 months; nPrint: Apache-2.0,
  last release 2021) — covered in D4. The credibility problems there are unchanged.

### 3.F Competing hackathon / SIH projects

#### `Samarth2357-hacker/ipsec-analyzer` — an explicit **SIH PS-26160** submission (created 2026-09-07)

- **How it's built.** Python backend (FastAPI + Scapy + scikit-learn RandomForest) and a React/Vite
  dashboard. 46 KB.
- **How it works, read from the code — this is the concrete failure pattern Discover predicted:**
  1. **The classifier never sees real traffic.** `train_model.py` builds its training set with
     `np.random.normal(...)`, using class means the authors typed in (e.g. Video = 1250 bytes,
     VoIP = 110 bytes), then trains a RandomForest to separate those Gaussians. Any reported accuracy
     measures its own assumptions (circular — E-02/E-04 in D4).
  2. **It fabricates a secure verdict when it can't see IKE.** If no transform is parsed, it
     *defaults* to `enc = "AES-256-GCM"`, `dh = "MODP-2048"`, `pfs = True`. An ESP-only capture is
     therefore reported as AES-256-GCM with PFS — which is **the false-assurance failure** (DEC-008),
     and also claims a key length that F-05 proves can't be recovered.
  3. **PFS is defined wrongly**, as `dh_group ≥ 14` on the IKE SA. PFS is a KE payload in the
     Child SA rekey (our EXP-03).
  4. **Transform parsing is a byte-pattern scan** (`payload[i]==1 and payload[i+1]==0`) over the raw
     payload rather than a structural parse, which invites false matches.
  5. **Mode is hardcoded** to `"Tunnel (Assumed)"`. **The score** is uncited deductions from 100.
     **No PQ awareness.** Its demo capture is Scapy-generated, with ESP payloads of `b"X"*1200`.
- **PS alignment:** it covers every PS heading on paper. Technically, P2, P3 and P5 are not actually
  solved.
- **Fair caveat:** the repo is four days old and may be early work in progress. The pattern still
  matters: **it is what a jury will see from typical submissions.**

#### `naman9271/ipsec-pcap-lab` — a serious dataset lab (created 2026-08-27, 13 commits)

- **How it's built.** Two privileged strongSwan containers; captures taken on the **host-side veth
  of one endpoint**; five profiles (P01–P05: IKEv2/IKEv1, tunnel/transport, IPv4/IPv6, native vs
  forced UDP/4500); seven traffic classes; an OOD set (DNS, SSH, gaming…) and an anomaly set;
  `metadata.csv` with SHA-256 per file and generator seeds; a strict validator; **run-level splits**
  (R01–R03 train, R04 validation, R05 locked test). It states its limits openly: *"does not claim
  real NAT traversal, certificate authentication, or rekey/replay testing."*
- **Where it falls short**, `[INFER]` from its configs:
  1. **Confounded factors.** Each profile fixes a cipher *and* IKE version *and* mode *and* IP version
     *and* encapsulation together (P01 = aes128-sha256 + modp2048; P02 = aes256gcm16 + ecp256;
     P03 = IKEv1…), so no single factor's effect can be isolated — the opposite of our one-factor
     "microscopes" (DEC-004).
  2. **One application per capture** — the tunnel-multiplexing trap (G-12).
  3. **Endpoint-adjacent vantage**, not a third-party path.
  4. **No PQ, PFS or cipher-key-length arms**, so it can't run our EXP-02/03/04.
  5. Uses the legacy `ipsec.conf`/stroke syntax.
- **Takeaway:** this team solved dataset *hygiene* well (run-level splits, hashes, OOD, a locked test
  set). Those practices are worth matching, credited. Our differentiation is **experimental design**
  (isolated factors, ground truth from `swanctl`, a keyless third-party vantage) and **PQ**.

---

## 4. Maintenance at a glance (GitHub API, fetched 2026-09-11)

| Project | Commits, last 12 mo | Last commit | Latest release | Licence | Status |
|---|---:|---|---|---|---|
| wireshark/wireshark | 3,968 | 2026-09-11 | (GitLab releases) | GPL-2.0 | 🟢 very active |
| libreswan/libreswan | 2,807 | 2026-09-11 | v5.4 (2026-08-14) | GPL | 🟢 very active |
| zeek/zeek | 2,264 | 2026-09-09 | v9.0.0-rc2 (2026-08-21) | BSD | 🟢 — but no IPsec analyzer |
| OISF/suricata | 1,645 | 2026-09-05 | 8.0.6 (2026-07-07) | GPL-2.0 | 🟢 — IKE backend stale |
| greenbone/openvas-scanner | 805 | 2026-08-31 | v23.50.24 | GPL-2.0 | 🟢 — IKEv1 probes only |
| arkime/arkime | 677 | 2026-09-09 | 2026-05 | Apache-2.0 | 🟢 |
| strongswan/strongswan | 545 | 2026-09-10 | **6.1.0 (2026-09-07)** | GPL-2.0 | 🟢 |
| nmap/nmap | 455 | 2026-09-11 | — | NPSL | 🟢 — script stale |
| ntop/nDPI | 425 | 2026-09-10 | 6.0 (2026-08-28) | LGPL-3.0 (IPsec part) | 🟢 |
| secdev/scapy | 300 | 2026-09-10 | v2.7.0 (2025-12-26) | GPL-2.0 | 🟢 |
| rusticata/ipsec-parser (Suricata's IKEv2 backend) | — | 2025-09-16 | v0.7 | MIT/Apache | 🟡 slow |
| corelight/zeek-spicy-ipsec | 4 | 2025-09-22 | — | BSD-3 | 🟡 slow, RFC 4306-era |
| hypergalois/pqc-tls-observability | 1 | 2026-05-04 | v1.0.0 | MIT | 🟡 research artefact |
| royhills/ike-scan | **0** | 2024-09-15 | **1.9 (2013)** | GPL-3.0 | 🔴 unmaintained |
| ukncsc/zeek-plugin-ikev2 | 0 | 2020-01-27 | — | — | 🔴 **archived** |
| ptsankov/secfuzz | 0 | 2015-05-29 | — | GPL-3.0 | 🔴 abandoned |

---

## 5. Coverage against the problem statement

Legend: ✅ does it · 🟡 partly / only for the plaintext part · ❌ doesn't · — not applicable

| Solution | A Testbed | B Capture | C Identify (proto / ver / mode / cipher / KE / SA / traffic) | D Assess (strength / compliance / lifetime / replay / PFS / metadata) | E Reports / score / confidence | PQ |
|---|---|---|---|---|---|---|
| Wireshark/tshark | — | ✅ | 🟡 plaintext fields; everything with keys | ❌ | ❌ | ✅ master, 🟡 4.6.4 |
| Zeek + spicy-ipsec | — | ✅ | 🟡 IKE fields | ❌ | 🟡 logs | ❌ |
| Arkime | — | ✅ | 🟡 IKE fields, searchable | ❌ | 🟡 search UI | ❌ |
| nDPI | — | ✅ | 🟡 SA_INIT proposals | ❌ | ❌ | ❌ |
| Suricata | — | ✅ | 🟡 | 🟡 weak-crypto alerts only | 🟡 alerts | ❌ |
| ike-scan / Nmap / Greenbone / Nessus | — | — | 🟡 IKEv1 proposals via probing | 🟡 Aggressive Mode, CVE by version | 🟡 scan report | ❌ |
| strongSwan / Libreswan (T2) | ✅ | — | ✅ own SAs, authoritatively | ❌ | ❌ | ✅ |
| SandboxAQ AQtive Guard | — | ✅ | ❌ **no IPsec** (TLS/SSH) | ❌ for IPsec | ✅ for TLS/SSH | ❌ for IPsec |
| Palo Alto PAN-OS 12.1 | — | ✅ | ✅ own tunnels; `[UNK]` third-party | 🟡 | ✅ dashboard | ✅ own tunnels |
| Samarth ipsec-analyzer (SIH) | ❌ | 🟡 | 🟡 claimed; defaults fabricate values | 🟡 uncited deductions | 🟡 | ❌ |
| naman ipsec-pcap-lab (SIH) | ✅ | ✅ | — (dataset only) | — | — | ❌ |
| **Our work so far** | ✅ | ✅ keyless vantage | 🟡 per-tier, with honest NOT-OBSERVABLE (EXP-01/02/03/04) | 🟡 designed (09-DEFINE), not built | ❌ not built | ✅ (EXP-04) |

**Reading the matrix.** Columns A–C are well covered by existing tools, at least for plaintext
fields. **Columns D and E are almost empty.** Only products that have endpoint access (the firewall
vendors, for their own boxes) or products that ignore IPsec (the TLS crypto-inventory tools) produce
assessments at all.

---

## 6. So — does any existing solution close the gap?

### The honest answer

**No single existing solution satisfies the problem statement, and none does the assessment
columns (D, E) for third-party IPsec traffic.** But the gap is **narrower than it was two days
ago**, and I have to correct two of our own claims to say so.

### What changed during this deep dive

| Claim | Before | Now |
|---|---|---|
| "Wireshark cannot decode RFC 9370 / ML-KEM" (07-DISCOVER, PQ-3) | A pillar of the CS-05 novelty claim | ❌ **Withdrawn.** Issue #21072 closed 2026-03-14; `master` names ML-KEM; the released 4.6.4 shows ADDKE1 with a numeric ID. **PQ *dissection* is solved.** |
| "No open-source tool handles IKE_INTERMEDIATE / ADDKE" (OQ-26) | `[UNK]` for Zeek/Suricata | ✅ **Resolved:** Zeek spicy-ipsec **no**, Suricata/ipsec-parser **no**, Arkime **no ADDKE found**, nDPI **no**, Wireshark **yes** |
| "IPsec is uncovered by crypto-inventory tools" | `[INFER]` | ✅ `[FACT]` for the market leader (AQtive Guard: TLS and SSH only) |
| "Active IKE tooling is IKEv1-era" (G-07) | Based on ike-scan and Nmap | ✅ **Strengthened:** Greenbone's own IKE library has zero IKEv2 references; ike-scan's last release was 2013 |
| "Typical submissions will fake the AI and the verdict" | Prediction | ✅ **Observed** in an actual PS-26160 repository |

### The revised gap map — what is genuinely unserved as of 2026-09-11

1. **PQ *assessment*, not PQ dissection** `[STRONG]`. Wireshark will show an operator `ADDKE1`.
   Nothing tells them: *was PQ **offered** but not **selected** (a downgrade)? Does this tunnel meet
   the DST/NQM roadmap? Is this a hybrid, or a PQ-only suite?* — and nothing does it across a
   thousand tunnels, with evidence attached. Note also that the tools SOCs actually run
   (Suricata, Zeek, nDPI) **can't parse the fields at all**. CS-05 survives, narrowed from
   "detect PQ" to "**assess PQ posture and downgrade**".
2. **Assessment with named baselines and admitted unknowns** (G-05/06/09) `[STRONG]`. Nothing in §3
   produces a per-SA verdict naming its authority (RFC 8221/8247/9395, NIST SP 800-77r1, DISA SRG,
   DST) and marking what it could not observe.
3. **Data-plane measurement over time** (G-01, G-13) `[STRONG]` — effective lifetime, rekey cadence,
   PFS-at-rekey (**EXP-03 proved this works with a clean 256-byte signature**), failure signatures.
   No tool looks at ESP/CREATE_CHILD_SA geometry, and Arkime explicitly discards ESP.
4. **IKEv2-era active probing** (G-07) `[FACT]` — every scanner found is IKEv1-built.
5. **IPsec in cryptographic inventory / CBOM** `[FACT]` — the inventory market covers TLS and SSH.
   India's DST roadmap mandates CBOMs from FY 2027–28.
6. **New, CVE-backed: authentication-bypass pattern detection** `[HYP]` — CREATE_CHILD_SA on an IKE
   SA that never authenticated (the CVE-2026-78135 pattern) should be visible passively. Needs an
   experiment (T-022).

### Does the PS itself still hold up?

Mostly yes — the gap is real — with the same caveats as 09-DEFINE. The existing-solutions evidence
**sharpens** where the PS points the wrong way:
- The PS's AI emphasis (C: "predicted type of traffic") is **exactly what the observed competing
  submission fakes.** Our measurement reframing (CS-01) is the defensible version.
- The PS's "security assessment" and "reports" (D, E) are **where nothing exists** — and they're
  under-weighted in the PS's wording. That's where the value is.

---

## 7. Consequences for the project

- **DEC-017** — *Withdraw the "Wireshark can't decode PQ IKE" claim everywhere and restate CS-05 as
  "PQ posture assessment + downgrade detection", positioned on top of — and cross-checked against —
  Wireshark's ADDKE parsing.* The four EXP-04 signals remain valid; they now also work for tools that
  don't parse ADDKE (Suricata, Zeek, nDPI), which is where SOCs actually live.
- **DEC-016** — *DEC-005's T3 tier (keying material) carries a caveat: on lockdown-confidentiality
  kernels, keys can't be read back from XFRM (strongSwan 6.1.0 notes).* T3 is an audit-lab tier,
  not a production assumption.
- **New tasks:** T-021 (upgrade the PQ image to 6.1.0 — CVE-2026-78133), T-022 (CVE-2026-78135
  pattern-detection experiment), T-023 (adopt the dataset-hygiene practices seen in the competing
  lab: locked test set, per-file SHA-256, OOD set, strict validator), T-024 (compare against
  Wireshark master's ADDKE output as an oracle for EXP-04).
- **Positioning for the jury, stated fairly:** *parsing and dissection are solved, and we reuse
  them. What's missing is the assessment — per-tunnel verdicts that name their standard, admit what
  they can't see, measure behaviour over time, and assess PQ migration and downgrade across a fleet.
  We checked every open-source parser's source, the leading commercial crypto-inventory product, and
  the public SIH-26160 repositories; none does this.*

---

## 8. Sources

**Code and live data (verified at source, 2026-09-11)**
- Wireshark `packet-ike.c` (master) — https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ike.c ; rename commit `ff53d6096b`
- Wireshark issue #21072 (closed 2026-03-14) — https://gitlab.com/wireshark/wireshark/-/work_items/21072
- Zeek base protocols — https://github.com/zeek/zeek/tree/master/scripts/base/protocols ; spicy-ipsec grammar — https://github.com/corelight/zeek-spicy-ipsec/blob/master/analyzer/analyzer.spicy
- Suricata IKE parser — https://github.com/OISF/suricata/tree/master/rust/src/ike ; rusticata ipsec-parser — https://github.com/rusticata/ipsec-parser
- Arkime IKE/ESP parsers — https://github.com/arkime/arkime/tree/main/capture/parsers
- nDPI IPsec dissector — https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/ipsec.c ; licence change PR #3220 — https://github.com/ntop/nDPI/pull/3220 ; README.license.md
- Greenbone NVT feed — inspected locally (`greenbone-community-edition-ospd-openvas-1:/var/lib/openvas/plugins`)
- strongSwan 6.1.0 release notes — https://github.com/strongswan/strongswan/releases/tag/6.1.0
- Maintenance metrics — GitHub REST API; stored in `research/data/solutions-maintenance-2026-09-11.json`

**Commercial / docs**
- SandboxAQ AQtive Guard Network Analyzer — https://aqtiveguard.sandboxaq.com/docs/sensors/network-analyzer/
- Palo Alto quantum-feature support — https://docs.paloaltonetworks.com/network-security/quantum-security/administration/quantum-security-concepts/support-for-quantum-features
- Keyfactor cryptographic discovery — https://www.keyfactor.com/products/cryptographic-discovery-inventory/
- Tenable/Nessus IKE Aggressive Mode plugin (via Vulners) — https://vulners.com/nessus/IKE1_AGGRESSIVE_MODE_WITH_PSK.NASL
- Encryption Consulting, cryptographic inventory vendors — https://www.encryptionconsulting.com/cryptographic-inventory-vendors/

**Research**
- Mallick, Kundu, Kompella — arXiv:2603.28728 — https://arxiv.org/abs/2603.28728
- PQ-TLS observability — https://github.com/hypergalois/pqc-tls-observability
- PQC-IPsec 5G benchmark — https://github.com/ekoh9704/PQC-IPsec-on-5G-Network-Deployment-Feasibility-Benchmark

**Competing projects (read as data)**
- https://github.com/Samarth2357-hacker/ipsec-analyzer
- https://github.com/naman9271/ipsec-pcap-lab
- https://github.com/0101-CTRL/ipsec-pcap-decrypt
