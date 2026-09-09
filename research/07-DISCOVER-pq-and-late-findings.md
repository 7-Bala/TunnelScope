# Discover D7 — Late Findings: The Post-Quantum Observability Gap, and a Correction

Two things happened at the end of this research session that materially change the picture. One is
a **self-correction** (I overstated a gap). The other is the **strongest single finding of the
entire Discover phase**.

---

## Part 1 — Correction: G-12 was overstated

**What I claimed in D4/D6:** that the entire VPN-classification literature assumes one flow per
tunnel and that multiplexing is unaddressed.

**What is actually true `[FACT]`:** a small multi-flow / multi-label encrypted-traffic-classification
literature exists and explicitly names this problem.

- **Chen, Cheng, Wei, Niu & Fu — *Classify Traffic Rather Than Flow: Versatile Multi-Flow Encrypted
  Traffic Classification With Flow Clustering*, IEEE TNSM 21(2), 2024, pp. 1446–1466.**
  States the problem directly: *"A single flow may contain more than one class label, referred to as
  a multiplexed stream — for instance, traffic that passes through a tunnel may contain several
  applications that share the same 5-tuple."* Method: **TSHC-SW** (Time Sequential Hierarchical
  Clustering with Sliding Windows) to group flows into "flow bunches," then five multi-flow
  classification schemas trading accuracy vs speed vs coverage. Reports 95% adjusted Rand Index and
  98% purity for clustering, >99% F1 for multi-flow classification, 79% prediction-time saving.
- **GRAIN** — granular multi-label ETC via classifier chains.
- **MFSI** — multi-flow service identification (Computer Networks, 2025).
- MLP-Mixer multi-view multi-label anomaly traffic classification.

**Revised G-12 `[INFER]`:** multi-flow ETC is *not* an untouched field. The remaining gap is
narrower and more precise:

> Existing multi-flow work clusters flows that are **individually visible** (same 5-tuple but
> separable by timing/behaviour, and in practice recoverable because the tunnel is not the unit of
> observation). **Inside IPsec tunnel mode there is exactly one SPI and one observable stream —
> the flows are not merely co-located, they are *superposed*.** TSHC-SW-style clustering operates on
> flow objects; at V0/V1 inside ESP we do not have flow objects to cluster.

So the honest position is: **the technique family exists but its input assumption does not hold at
our vantage point.** That is still a gap, but it is a *smaller and more defensible* claim than the
one I made, and the >99% F1 headline must be read against the D4 credibility findings, not adopted.

`[INFER]` Practical consequence unchanged: **do not attempt to solve superposed-flow separation.**
Measure and bound the degradation. But we must now cite this literature rather than claim it does
not exist — and a jury member who knows it will respect the distinction.

---

## Part 2 — The post-quantum observability gap (the strongest finding so far)

Four facts, each independently verified, that line up almost implausibly well.

### PQ-1 `[FACT]` — The protocol exists and is standardised

- **RFC 9242** (IKE_INTERMEDIATE exchange) and **RFC 9370** (Multiple Key Exchanges in IKEv2,
  May 2023) define **Additional Key Exchange (ADDKE)** transforms — up to **seven** additional key
  exchanges, classical or post-quantum, negotiated in `IKE_SA_INIT` and carried in
  `IKE_INTERMEDIATE` messages between `IKE_SA_INIT` and `IKE_AUTH`.
- **RFC 8784** adds post-quantum pre-shared keys as the short-term alternative.
- `draft-ietf-ipsecme-ikev2-mlkem` is standardising ML-KEM specifically.

### PQ-2 `[FACT]` — Implementations shipped

**strongSwan 6.0.0** (December 2024) supports RFC 9370 multiple key exchanges and **ML-KEM**
(FIPS 203), via Botan 3.6.0+ or the `oqs` plugin using liboqs directly. Configuration is a simple
proposal string, e.g. `x25519-ke1_mlkem768` — X25519 first, ML-KEM-768 as additional KE.

⇒ **Our testbed can generate hybrid post-quantum IPsec traffic today, with ground truth.**

### PQ-3 `[FACT]` — The leading analysis tool cannot read it

**Wireshark GitLab issue #21072** — *"IKEv2 dissector does not display updated field names from
RFC 9370."* The reporter's summary: Wireshark **"does not decode Post-Quantum Cryptography (PQC)
algorithms such as ML-KEM-1024 in IKEv2 packets"**; `IKE_SA_INIT` packets carrying ML-KEM-1024 fail
to display correctly in **Wireshark 4.6.3**. Expected behaviour: *"show IKE_SA_INIT with key
exchange as MLKEM 1024."* A reproduction capture (`ipsec_mlkem.pcap`) is attached.

And from D2: no evidence that Zeek's Spicy IPsec analyzer or Suricata's IKE parser handle
`IKE_INTERMEDIATE` or ADDKE transforms either. (OQ-11 → **confirmed for Wireshark**; Zeek/Suricata
still `[UNK]`, to be verified at source.)

### PQ-4 `[FACT]` — India has a national mandate that requires exactly this capability

**Department of Science & Technology, *Implementation of Quantum Safe Ecosystem in India — Report of
the Task Force*, February 2026**, under the National Quantum Mission, chaired by the CEO of C-DOT.
Directly relevant content:

| Task Force text | Relevance |
|---|---|
| Milestone 1 (**CII by 2027**, enterprises by 2028): *"**Inventory cryptographic assets and assess quantum risk**"*; *"Introduce PQC readiness requirements in procurement, including phased adoption of Cryptographic Bills of Materials (CBOMs)"*; *"mandate CBOM submissions from vendors starting FY 2027–28"* | A dated national requirement to inventory and assess deployed cryptography |
| *"**Interoperability During Transition:** Coexistence of classical and quantum-safe cryptography increases complexity and **introduces risks of downgrade or insecure fallback**."* | **Names the exact threat our analyzer would detect** |
| *"**Assurance and Validation Gaps:** Independent validation is critical to ensure correct implementation and **prevent reversion to vulnerable cryptography**."* | Names the exact assurance function |
| *"**Continuous Assurance:** Independent validation, monitoring, and capacity-building"* | Monitoring, not one-off audit |
| *"**Contingency Planning:** Prepare interim quantum-safe solutions (e.g., proxies, **tunnels, VPNs, gateways**, QRNG, TRNG)"* | VPNs named as a primary interim quantum-safe mechanism |
| Medium-term: *"Migrate high-priority and long-lifetime systems as well as **validate migration through independent testing**"*; *"establish **national testbeds**"* | Testbed + independent validation, i.e. our PS deliverables A and B |
| CBOM defined as *"a detailed inventory of cryptographic components and configurations used by a system, including **algorithms, modes of operation, key sizes, protocols**, libraries, random number generators, and cryptographic parameters, covering both classical and quantum-safe cryptography"* | Nearly a restatement of PS section C |
| *"All cryptographic transition planning shall proceed under an 'assume breach' principle, recognising the risk of 'Harvest Now, Decrypt Later' (HNDL)"* | HNDL is *the* argument for why IPsec PFS and PQ key exchange matter now |

### PQ-5 — The synthesis `[INFER]`, high confidence

> **India has a dated national mandate (CII by 2027) to inventory deployed cryptography, assess
> quantum risk, and prevent silent downgrade to vulnerable cryptography during hybrid transition.
> strongSwan can already negotiate hybrid ML-KEM IPsec. Wireshark cannot decode it. No surveyed tool
> can tell an operator, from the network, whether an IPsec deployment actually negotiated a
> post-quantum key exchange or silently fell back to classical.**

### Why this capability is unusually strong for *this* project

| Criterion | Assessment |
|---|---|
| **Observability** | `IKE_SA_INIT` is plaintext, and ADDKE transforms plus `IKE_INTERMEDIATE` exchanges are visible there. This is **O — directly observable, deterministic** at V1. It sits in the *strongest* zone of our Observability Matrix, unlike the inner-traffic requirements. |
| **Downgrade detection** | Proposed vs selected transforms are both observable. A negotiation that *offered* ML-KEM but *selected* classical-only is detectable **with plaintext evidence** — the "insecure fallback" the Task Force names. |
| **Novelty** | Confirmed tool gap with a live, citable issue number. Not a claim; a link. |
| **AI necessity** | **Zero.** Deterministic parsing. Honest, and a good example for the AI Necessity Matrix of where AI adds nothing. |
| **Testbed feasibility** | strongSwan 6.0.0 + `x25519-ke1_mlkem768`. One config line. |
| **Policy alignment** | DST/NQM Task Force, February 2026 — six months old, Government of India, and the PS's sponsor (NTRO) is a national technical organisation. |
| **Risk** | Low. The protocol is standardised, the implementation ships, the evidence is plaintext. |

`[UNK]` Prior work to check before claiming novelty: *Hybrid Quantum Security for IPsec*
(arXiv:2507.09288) and *Q-RAN: Quantum-Resilient O-RAN Architecture* (arXiv:2510.19968) appear to
implement or evaluate hybrid PQ IPsec. They are likely *implementation/performance* studies rather
than *observability/assessment* tools — but this must be verified, not assumed. **OQ-25.**

---

## Part 3 — New concept seed

### CS-05 — PQ-readiness and downgrade observability for IPsec

Deterministically detect, from plaintext IKE:
1. Whether ADDKE transforms (RFC 9370) are **proposed** by each peer, and which KEMs;
2. Whether `IKE_INTERMEDIATE` exchanges (RFC 9242) actually **occurred**;
3. Which key exchange was **selected** — and therefore whether a **downgrade or fallback** to
   classical-only occurred despite PQ being offered;
4. Whether RFC 8784 post-quantum PSKs are in use;
5. Report the result as a **CBOM-shaped cryptographic inventory entry** for the tunnel, in the
   vocabulary the DST Task Force uses (algorithms, modes, key sizes, protocols, parameters).

`[INFER]` This one capability simultaneously satisfies PS §C (key exchange method identification),
PS §D (cryptographic strength, cipher-suite strength, configuration compliance), PS §E (reports and
risk scoring), and a live national policy requirement — while requiring **no AI at all** and sitting
in the **highest-confidence** zone of the Observability Matrix.

It is also the answer to *"why doesn't an existing tool already solve it?"* — because the leading
tool has an open issue saying it doesn't.

---

## Part 4 — Register deltas

**New findings:** PQ-1…PQ-5; correction to G-12.
**New concept seed:** CS-05.
**New open questions:** OQ-25 (prior art in arXiv:2507.09288 / 2510.19968), OQ-26 (do Zeek and
Suricata handle IKE_INTERMEDIATE / ADDKE?), OQ-27 (does the Wireshark issue have a fix in flight —
if it lands before SIH, part of the novelty evaporates; check the merge requests).
**Gap G-08 upgraded:** from `[UNK] no positive evidence` to `[FACT] confirmed for Wireshark, with a
citable issue number`.

---

## Part 5 — Addendum (post-D8): a length-only PQ detector that works *despite* the dissector gap

Following OQ-29. If Wireshark cannot decode ML-KEM transform IDs (#21072), can we detect
post-quantum key exchange **without needing to**?

`[FACT]` Key-exchange payload sizes are fixed and unambiguous:

| Key exchange | Initiator KE payload | Responder KE payload | Symmetric? |
|---|---:|---:|:--:|
| X25519 (group 31) | 32 | 32 | ✅ |
| ECP-256 (group 19) | 64 | 64 | ✅ |
| ECP-384 (group 20) | 96 | 96 | ✅ |
| MODP-2048 (group 14) | 256 | 256 | ✅ |
| MODP-4096 (group 16) | 512 | 512 | ✅ |
| **ML-KEM-512** (FIPS 203) | **800** (encapsulation key) | **768** (ciphertext) | ❌ |
| **ML-KEM-768** | **1184** | **1088** | ❌ |
| **ML-KEM-1024** | **1568** | **1568** | ✅ (but distinctive size) |

> **Finding PQ-6 `[STRONG]` → `[EXP]`.**
> **A KEM is structurally distinguishable from a Diffie–Hellman exchange by direction asymmetry
> alone.** Every classical (EC)DH group produces **identical-length** KE payloads in both
> directions, because both peers send a group element. A KEM does not: the initiator sends an
> **encapsulation key** and the responder sends a **ciphertext**, and for ML-KEM-512/768 these
> differ (800→768, 1184→1088).
>
> Therefore: *"is this negotiation using a post-quantum KEM?"* is answerable from **payload lengths
> in plaintext IKE_SA_INIT / IKE_INTERMEDIATE**, with **no knowledge of the transform ID and no
> dissector support at all.**

Why this matters disproportionately:
- It is **deterministic**, explainable, and requires zero AI.
- It works on the exact captures the leading analyzer fails on — the strongest possible
  demonstration of the gap in G-08.
- It is **immediately testable today**: Suricata already exposes `ike.key_exchange_payload_length`
  as a rule keyword (D2 §2.2), so a working detector can be written before any of our own code
  exists. That makes this the **cheapest possible early validation experiment** in the whole
  project. `[EXP]`
- It is the **same structural reasoning as F-04** (ESP cipher-suite sieve) and **A10** (PFS
  inference from CREATE_CHILD_SA length): *lengths are metadata that encryption does not hide, and
  protocol structure makes them diagnostic.*

`[INFER]` That recurrence is not a coincidence — it is starting to look like the **unifying
technical thesis of the whole project**:

> **Cryptographic protocols leak their own configuration through the geometry of their messages.**
> Where fields are encrypted or dissectors are absent, *structure* — lengths, counts, directions,
> alignments, intervals — remains observable and is frequently sufficient to determine, constrain,
> or bound the configuration.

Every deterministic capability found in Discover is an instance of it: F-04 (IV/ICV/alignment
residues → cipher family), F-05 (the honest limit — key length has no geometry), A10 (KE payload
presence → PFS), F-02/CS-03 (SPI change intervals → effective lifetime), PQ-6 (KE length asymmetry
→ KEM vs DH), and CS-01 (packet-length distributions → metadata leakage, measured in bits).

This is a candidate for the project's one-sentence identity, and it should be stress-tested — not
adopted — in DEVELOP.
