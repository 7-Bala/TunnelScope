# Discover D2 — Prior-Art Teardown and Ecosystem Map

**Purpose:** answer Q6–Q8 and OQ-06/07/11. Determine precisely what already exists, what it does
*not* do, and what the smallest defensible novelty claim is.

**Method:** for each project — capability, non-capability, input/output, license, maturity, and a
**reuse verdict** (REUSE / WRAP / EXTEND / REFERENCE-ONLY / AVOID).

---

## 1. Headline conclusion of D2

> **Parsing IPsec is solved. Interpreting it is not. Diagnosing it is barely attempted.
> Measuring what it leaks is attempted by nobody.**

Three findings drive this:

- **P-01 `[FACT]`** Zeek's Spicy IPsec analyzer already extracts IKE SPIs, version, exchange type,
  flags, message ID, vendor IDs, notify messages, **transforms, DH groups, proposals, certificates
  and attributes** — for IKEv1 *and* IKEv2, including ESP-over-UDP/TCP. Our contribution cannot be
  a parser.
- **P-02 `[FACT]`** Suricata already ships **14 IPsec/IKE app-layer event rules** (SIDs
  2224000–2224013) covering weak encryption, weak PRF, weak auth, **weak DH**, missing DH, missing
  auth, no-encryption, invalid/unknown proposals and multiple server proposals. A meaningful slice
  of PS section D exists in a mainstream IDS today.
- **P-03 `[FACT]`** Yet the *active* IKE tooling ecosystem is stuck in the IKEv1 era: `ike-scan`'s
  IKEv2 support is experimental and "only tested against strongSwan"; Nmap's `ike-version` has a
  "very limited response parser" that extracts **only Vendor IDs**, with backoff analysis still an
  unimplemented TODO. Nothing surveyed handles RFC 9370 `IKE_INTERMEDIATE` / hybrid PQ exchanges.

---

## 2. Tool-by-tool teardown

### 2.1 Zeek + `corelight/zeek-spicy-ipsec` — **EXTEND / REUSE**

| | |
|---|---|
| **Does** | Spicy-based analyzer for ESP, AH, IKEv1, IKEv2, incl. ESP-in-UDP and ESP-in-TCP. Logs: init/resp SPI, version, exchange type, flags (E,C,A,I,V,R), message ID, vendor IDs, notify messages, transforms, DH groups, proposals, certificates, attributes, payload length, hashes. |
| **Does not** | No security assessment. No standards mapping. No confidence model. No SA lifecycle/rekey analysis. No ESP-side statistical analysis. No cipher-suite inference from ESP structure. No failure diagnosis. |
| **License / maturity** | BSD-3-Clause. ~70 commits, 8 stars, 8 forks — functional but early-stage, low bus factor. `[FACT]` |
| **Critical caveat** | Zeek's own announcement notes it **will not see native ESP (IP proto 50)** in many deployments unless UDP/TCP-encapsulated. This is a deployment-model constraint, not a bug. `[FACT]` |
| **Verdict** | **REUSE as a reference implementation and cross-check oracle; EXTEND conceptually.** Adopting the whole Zeek runtime for a hackathon prototype is a heavyweight dependency decision to be weighed in DEVELOP. Its field list is an excellent completeness checklist for our own extractor. |

`ukncsc/zeek-plugin-ikev2` — narrower (IKE_SA_INIT only → `ikev2.log`), useful as a second
reference. **REFERENCE-ONLY.**

### 2.2 Suricata — **REFERENCE-ONLY, but strategically important**

`[FACT]` IKE keyword surface: `ike.init_spi`, `ike.resp_spi`, `ike.chosen_sa_attribute`,
`ike.exchtype`, `ike.vendor`, `ike.key_exchange_payload(_length)`, `ike.nonce_payload(_length)`.

**The asymmetry is the finding:**

| Attribute matchable via `ike.chosen_sa_attribute` | IKEv1 | IKEv2 |
|---|:--:|:--:|
| `alg_enc`, `alg_auth`, `alg_prf`, `alg_dh` | ✅ | ✅ |
| `alg_hash` | ✅ | ❌ |
| `sa_group_type`, `sa_field_size` | ✅ | ❌ |
| **`sa_life_type`, `sa_life_duration`** | ✅ | ❌ |
| **`sa_key_length`** | ✅ | ❌ |

`[INFER]` The IKEv2 gaps are not arbitrary — they mirror the protocol reality established in D1:
IKEv2 **does not negotiate lifetimes at all** (F-02), and Suricata's key-length gap means
**it cannot distinguish AES-128 from AES-256 even for the IKE SA in IKEv2**, though the plaintext
transform attribute is right there. That is an implementable gap, not a physical one. `[EXP]` —
verify against a live capture.

**Documented defects that generalise into design lessons:**
- `[FACT]` Bug #2861: the shipped weak-DH rule (sid 2224005) *silently failed*. Three causes —
  (a) a deliberate `flow:to_client` filter meaning **client-side weak proposals were never
  alerted**, (b) wrong event names in the rules file, (c) a transaction-handling logic bug that
  caused **events raised in the first IKEv2 message to be ignored entirely**.
- `[FACT]` "If there is more than one chosen SA … the attributes of the **first** SA are used."
- `[FACT]` Events fire "at most once per connection."

> **Design lesson DL-01.** A rule/alert model is the wrong abstraction for posture assessment.
> Suricata's failures are all *evidence-handling* failures: direction filtering hid half the
> evidence, first-message events were dropped, multi-proposal negotiations were truncated to the
> first entry, and one-shot alerts destroy the per-SA history. A posture tool must build a
> **complete, per-SA, bidirectional evidence record** and reason over it afterwards — not emit
> stateless alerts during parsing.
>
> This is a concrete, citable argument for why our system is not "Suricata rules with a dashboard."

### 2.3 Wireshark / tshark — **REUSE (as oracle + key-driven decryption path)**

`[FACT]` Capabilities: full ISAKMP/IKEv2 dissection; **IKEv1 decryption table**, **IKEv2 decryption
table**, and **ESP SAs** preference supporting AEAD with ICV verification (AES-GCM included, via
Libgcrypt). It also carries a corpus of labelled test captures (`test/captures/ikev2-decrypt-*.pcap`
with algorithm names in the filenames) — see D5.

**Documented friction (practitioner-grade evidence of the real pain) `[STRONG]`:**
- The ESP traffic key must be supplied per-SA, manually: endpoints, SPI, algorithm, key, auth
  parameters. *"A user password or IKE pre-shared key is not automatically the ESP traffic key."*
- Non-standard UDP-encapsulation ports silently break decoding; the user must `Decode As → UDPENCAP`.
- "Attempt to detect/decode encrypted ESP payloads" is off by default; without it nothing decrypts.
- AES-GCM requires selecting the exact ICV variant (`AES-GCM with 16 octet ICV [RFC4106]`).
- ESP decryption requires a Gcrypt-linked build.

> **Design lesson DL-02.** Every one of these is *expert-knowledge tax*, not a missing capability.
> This is precisely the PS's stated motivation — "traditional protocol analysis tools provide
> packet-level visibility but often require expert interpretation." We now have concrete,
> citable instances of that tax rather than a vague assertion.

**Verdict:** **REUSE.** `tshark -T json/ek` is a legitimate ingestion path and an independent
oracle for validating our own extractor. GPL-2.0 — relevant if we bundle rather than shell out.

### 2.4 `ike-scan` — **WRAP (authorization-gated), and a gap indicator**

| | |
|---|---|
| **Does** | Discovery; **fingerprinting via UDP retransmission-backoff patterns and Vendor IDs**; Phase-1 transform enumeration; user enumeration; **offline PSK cracking** (`psk-crack`) against IKEv1 Aggressive Mode. |
| **Does not** | `[FACT]` IKEv2 support is experimental. Backoff fingerprinting **fails entirely under packet loss** ("needs to see all of the responses") and **cannot fingerprint hosts that reply with a notify** rather than a handshake. Deliberately never completes a handshake, so it cannot observe Phase-2/Child-SA behaviour at all. |
| **License / maturity** | **GPL-3.0**, ~923 commits, 19 open issues, CI active. |
| **Verdict** | **WRAP behind an authorization gate.** GPL-3.0 means shelling out is fine; linking or vendoring imposes GPL-3 on the derived work — record in the licensing register. Its backoff-fingerprint corpus is valuable domain knowledge to re-derive. |

### 2.5 Nmap `ike-version` NSE — **REFERENCE-ONLY**

`[FACT]` Sends four packets, tests Main and Aggressive mode, multiple transforms per request. But
the script's own documentation states it has a **"very limited response parser — currently only the
VIDs are extracted"**, and lists complete response parsing and backoff analysis as *future* work
that has not been done. Version detection **fails entirely if the device sends no known Vendor ID**.

> `[INFER]` **Gap evidence.** Two of the three canonical active IKE tools openly document that their
> response parsing is incomplete and IKEv1-centric. In 2026, with IKEv2 mandatory under the DISA VPN
> SRG and RFC 9395 making IKEv1 Historic, **there is no mature open-source active IKEv2 posture
> prober.** That is a real, checkable gap.

### 2.6 strongSwan / Libreswan — **REUSE (testbed + vantage V3)**

`[FACT]` strongSwan provides `swanctl` over the **vici** interface: load configs, initiate, and
query live SA state — i.e. authoritative endpoint telemetry. Retransmission behaviour is explicitly
configurable (`relative timeout = retransmit_timeout × retransmit_base^(n−1)`), which matters twice:
it is our testbed's control knob **and** the mechanism behind backoff fingerprinting.

**Verdict:** **REUSE** as both the testbed VPN implementation and the V3 telemetry source and
**ground-truth oracle** for labelling. Libreswan as the second implementation for
leave-one-implementation-out generalization testing.

### 2.7 Scapy — **REUSE (selectively)**

`[FACT]` `scapy/layers/isakmp.py` (IKEv1), `scapy/contrib/ikev2.py` (IKEv2), and
`scapy/layers/ipsec.py` (ESP/AH with encryption/decryption support). GPLv2.
**Verdict: REUSE** for testbed traffic crafting, targeted probe construction and unit-test fixtures.
Not suitable as a high-throughput ingestion path.

### 2.8 Smaller / research projects — **REFERENCE-ONLY**

- `5u5urrus/IkeProbe` — IKE service detector built on Scapy's native IKE layers; scans non-standard
  ports and IPv6 targets. Useful as a construction reference for probe packets.
- `ptsankov/secfuzz` — academic IKE fuzzer (Scapy + Openswan). Teaches *implementation-difference
  discovery*, which is relevant to our fingerprinting work. Not a posture tool.
- `isaudits/scripts/ike-scan.py` — thin ike-scan wrapper (aggressive mode, PSK crack). Shows the
  standard pentest workflow; low technical content.

---

## 3. Practitioner evidence — where the real pain is (Q17 partial)

This is the most decision-relevant material found so far, and it comes from vendor support
knowledge bases and community forums rather than papers. Weighted as `[STRONG]` where multiple
independent vendors say the same thing.

### PE-01 — Negotiation failures are invisible in packet captures `[STRONG]`

> *"This encryption mismatch won't be visible in a packet capture unless the pcap is manually
> decrypted, so it's best to use CLI commands or check both sides' configurations manually."*
> — Palo Alto community guidance on `NO_PROPOSAL_CHOSEN`

Corroborated by Cisco/Fortinet guidance: *"Phase 2 can only complete after Phase 1 because all
packets are encrypted, which complicates debugging at this stage."*

**This is independent practitioner corroboration of finding F-01**, arrived at from the operational
side rather than the specification side. Two source classes agreeing raises F-01 to the strongest
evidence tier available.

**And it reveals an unmet need the PS does not name:** the dominant real-world IPsec analysis task
is **diagnosing why a tunnel did not come up**, and the industry's answer is *"stop using the
capture, go read both configs by hand."*

### PE-02 — The recurring operational failure taxonomy `[STRONG]`

Consistent across Cisco, Fortinet, Palo Alto and F5 knowledge bases:
- Phase-2 / Child-SA **proposal mismatch** → ESP SAs never install
- **Traffic-selector mismatch** → `TS_UNACCEPTABLE`, Phase 1 clean but Phase 2 fails instantly
- **PFS mismatch** → tunnel flaps at *every* IPsec rekey
- **Lifetime mismatch** between peers → repeated rekeys, unstable SPIs
- **Simultaneous-rekey race** when both peers use identical Phase-2 lifetimes → "can't find SA"
  errors; the documented remedy is to **stagger lifetimes by 60–300 s**
- Downstream blast radius: integrity-check failures, tunnel drops, **BGP peering drops**

> `[INFER]` **This taxonomy is observable at V0/V1 even though the *reason* is encrypted.** Every
> item above produces a distinct *structural* signature: SPI churn rate, rekey periodicity, ESP
> gaps, `IKE_AUTH`-then-`INFORMATIONAL`-delete patterns, retransmission bursts, message counts and
> sizes. **Classifying the failure mode from encrypted exchange structure is a well-posed, novel,
> ground-truth-available task** — and it is exactly what practitioners need.
> Logged as **concept seed CS-02** (§5).

### PE-03 — Expert-knowledge tax is concrete, not rhetorical `[STRONG]`

The Wireshark friction list in §2.3 is the mechanism behind the PS's "requires expert
interpretation." It is per-SA manual key entry, hidden preferences, decode-as workarounds and
exact-ICV-variant selection.

---

## 4. What existing tooling collectively does NOT do

Consolidated gap list. Each is a candidate contribution; each must survive D6 gap validation.

| ID | Gap | Evidence |
|---|---|---|
| **G-01** | **No SA-lifecycle analysis.** Nothing measures rekey interval / bytes / packets between SPI changes, i.e. the *effective* lifetime policy (the only way to get lifetime for IKEv2 — F-02) | Suricata: IKEv2 has no `sa_life_duration`. Zeek: logs events, not lifecycle. Wireshark: manual. |
| **G-02** | **No ESP-side cipher-suite inference.** No tool derives the suite family from IV/ICV/alignment structure (F-04) | Absent from all surveyed tools |
| **G-03** | **No negotiation-failure diagnosis from capture.** Industry answer is "read both configs manually" | PE-01 |
| **G-04** | **No metadata-exposure quantification.** No tool tells an operator how much their tunnel leaks | Absent everywhere; §5 CS-01 |
| **G-05** | **No evidence-linked, confidence-tagged posture record.** Rules emit alerts; nothing builds a per-SA evidence graph with observed/inferred/unknown separation | DL-01 |
| **G-06** | **No vantage-point model.** No tool declares what its verdict is based on, or degrades gracefully across V0–V5 | Absent everywhere |
| **G-07** | **No modern active IKEv2 posture prober.** ike-scan experimental, Nmap VID-only | P-03 |
| **G-08** | **No RFC 9370 / PQ-readiness assessment.** `IKE_INTERMEDIATE` and additional-KE transforms unhandled | OQ-11, pending final verification |
| **G-09** | **No standards traceability.** Nothing maps a finding to RFC 8221/8247/9395 clauses, NIST SP 800-77r1, or the **DISA VPN SRG** control IDs | Absent |

---

## 5. Concept seeds emerging from D2

**Not decisions.** Recorded so DEVELOP has real, evidence-derived material rather than
brainstorming. Each names the evidence that generated it.

### CS-01 — Metadata-exposure quantification (*"how much does your tunnel leak?"*)

Turn the PS's inner-traffic-classification requirement inside out. Rather than claiming to identify
the application inside ESP as ground truth, **use a classifier as a measuring instrument for
adversary capability**: how well can a passive adversary infer inner activity from this specific
deployment's observable stream?

Why this is strong:
- It is grounded in canonical, high-tier prior work: Wright et al., *Spot Me If You Can*
  (IEEE S&P 2008) showed ~50% average and >90% for some phrases on **encrypted VoIP** purely from
  packet lengths under VBR + length-preserving encryption — a result significant enough that
  **RFC 6562** was written about it. `[FACT]`
- It maps directly to an actionable, standards-backed remediation: ESP traffic-flow-confidentiality
  padding and dummy packets (RFC 4303 §2.7).
- **It makes the ML component necessary *and* immune to the credibility crisis in §D4.** A low
  classifier accuracy is not an embarrassing result — it is a *good security posture finding*.
  The measurement is valid in both directions.
- It fills G-04, which nothing else addresses.

### CS-02 — Failure-mode diagnosis from encrypted exchange structure

Classify *why* a tunnel failed (proposal mismatch / TS mismatch / auth failure / PFS mismatch /
lifetime race) from the structural signature of an encrypted negotiation. Directly answers PE-01
and G-03; ground truth is trivially generated in a testbed by deliberately misconfiguring one side.

### CS-03 — SA lifecycle observatory

Measure what a deployment *actually does* over time — effective rekey cadence, SPI churn, staggering,
DPD behaviour, rekey-race detection — as opposed to what any config claims. Fills G-01 and directly
detects the PE-02 failure taxonomy.

### CS-04 — Vantage-aware evidence graph with graceful degradation

The cross-cutting mechanism for G-05/G-06: one posture record per SA, every field carrying its
evidence, its vantage point and its confidence, degrading explicitly as evidence is removed.

---

## 6. Licensing register (running)

| Component | License | Implication |
|---|---|---|
| zeek-spicy-ipsec | BSD-3-Clause | Permissive; safe to reuse/derive |
| Zeek | BSD-3-Clause | Permissive |
| Wireshark / tshark | GPL-2.0 | Shelling out to `tshark` = fine. Linking/bundling ⇒ GPL obligations |
| Suricata | GPL-2.0 | Same |
| ike-scan | **GPL-3.0** | Shell-out acceptable; linking/vendoring imposes GPL-3 on derived work |
| Scapy | GPL-2.0 | Same caution |
| strongSwan | GPL-2.0 (+ some dual) | Used as a *system under test*, not linked ⇒ no obligation |
| Nmap NSE | Nmap Public Source License | Restrictive on redistribution — **reference only, do not bundle** |

`[UNK]` SIH's own IP/licensing expectations for submitted deliverables — recorded as OQ-14.

---

## 7. Open items carried forward

- **OQ-06 → partially closed.** Zeek/Suricata/Wireshark capability now mapped. Remaining: run all
  three against our own captures and diff against the D1 Observability Matrix. `[EXP]`
- **OQ-11 → still open, high value.** No evidence yet that any tool parses RFC 9370
  `IKE_INTERMEDIATE`. Needs source-level verification in Wireshark and Zeek.
- **OQ-15 (new).** Verify the Suricata IKEv2 `sa_key_length` gap empirically — is the plaintext
  transform key-length attribute genuinely unmatched for IKEv2?
- **OQ-16 (new).** Confirm the problem-statement ID. `report.md` records **SIH26160**; one public
  index appears to list this statement as **SIH26161**. Low technical impact, non-zero submission
  impact.
