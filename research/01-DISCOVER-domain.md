# Discover D1 — Domain Fact Base and the Observability Matrix

**Status:** In progress (D1 of the sequence in `00-RESEARCH-PLAN.md`). This document must pass
**GATE-1** before prior-art teardown conclusions are finalised and before any requirement is
accepted.

**Confidence tags used throughout:**
`[FACT]` established by a normative spec or direct measurement ·
`[STRONG]` strong evidence, multiple authoritative sources ·
`[INFER]` reasonable inference from facts ·
`[HYP]` hypothesis, plausible, untested ·
`[EXP]` needs our own experiment ·
`[UNK]` unknown

---

## 1. Why this document exists first

The problem statement asks the system to identify, from captured traffic:
IPsec protocol, IKE version, tunnel/transport mode, **encryption algorithm**, authentication
algorithm, key exchange method, SA characteristics, and the traffic type inside ESP.

Those eight items are written as if they were one homogeneous task. They are not. They live in
**different parts of the protocol, with different encryption status**. Until that is mapped, every
downstream decision — architecture, ML choice, dataset, dashboard, scoring — is guesswork.

---

## 2. Vantage points (the missing variable in the problem statement)

The PS says "inspect captured traffic or live network streams" without saying *from where*. That
omission hides the single biggest determinant of what is knowable. We therefore define an explicit
vantage-point taxonomy, which will be carried through the whole project:

| ID | Vantage point | Realistic? | What it adds |
|---|---|---|---|
| **V0** | Passive capture on the path between endpoints, **ESP only** (SA already established before capture started) | Very common in forensic PCAP review | Outer headers, SPI, sequence numbers, sizes, timing |
| **V1** | V0 **+ the IKE negotiation is in the capture** | Common if capture starts before tunnel setup, or spans a rekey | All plaintext IKE payloads |
| **V2** | V1 + capture on the **inside (plaintext) interface** of one endpoint | Available when you own an endpoint | Ground truth for inner traffic; resolves mode |
| **V3** | V1 + **endpoint telemetry** (`swanctl --list-sas`, `ip xfrm state`, vici, vendor API) | Available when you own the estate — this is the *audit* use case | Full negotiated config, authoritatively |
| **V4** | V1 + **keying material** (IKE SK_ei/SK_er, ESP keys) | Available on infrastructure you own; how Wireshark decrypts | Full decryption of IKE_AUTH and ESP |
| **V5** | Authorized **active probe** of your own gateway (ike-scan style) | Audit context only | Supported proposals, implementation fingerprint |

`[FACT]` These are not equivalent. A capability that is impossible at V0 may be trivial at V3.

> **Design implication (early, provisional):** the product's honesty and its usefulness both depend
> on it declaring which vantage point produced each finding. A single "security score" computed
> without stating vantage point is not defensible. Recorded as **DEC-001 candidate** in the
> decision log.

---

## 3. Protocol fact base

### 3.1 IPsec architecture
- `[FACT]` IPsec = AH (RFC 4302), ESP (RFC 4303), architecture (RFC 4301), keyed by IKEv1
  (RFC 2407/2408/2409) or IKEv2 (RFC 7296).
- `[FACT]` **IKEv1 is deprecated and RFCs 2407/2408/2409 were moved to Historic by RFC 9395
  (April 2023).** RFC 9395 also deprecates RC5, IDEA, CAST, Blowfish, 3IDEA, ENCR_DES_IV64,
  ENCR_DES_IV32, and adds a "Status" column to the IANA IKEv2 Transform Type registries.
  ⇒ *Observing IKEv1 at all is itself a finding.*
- `[FACT]` Current algorithm requirements: RFC 8221 (ESP/AH) and RFC 8247 (IKEv2), both updated by
  RFC 9395. RFC 8247 states RSA keys < 2048 bits SHOULD NOT be used.
- `[FACT]` RFC 9370 (May 2023) adds multiple/hybrid key exchanges to IKEv2 via `IKE_INTERMEDIATE`
  (the PQC migration path); RFC 8784 adds post-quantum pre-shared keys.
  ⇒ A 2026 analyzer that cannot recognise `IKE_INTERMEDIATE` or additional key-exchange transforms
  will misreport modern deployments. **None of the tools surveyed so far clearly handle this** —
  candidate novelty, to be verified in D2.
- `[FACT]` Normative posture guidance: NIST SP 800-77 Rev. 1 (June 2020), *Guide to IPsec VPNs*.

### 3.2 What IKEv2 sends in the clear vs. encrypted — the decisive fact

`[FACT]` (RFC 7296)

| Exchange | Encryption | Carries |
|---|---|---|
| `IKE_SA_INIT` | **PLAINTEXT** | `SAi1/SAr1` (full **IKE SA** proposals: ENCR incl. key length, PRF, INTEG, D-H), `KEi/KEr`, nonces, `CERTREQ`, and notifies: `NAT_DETECTION_SOURCE_IP` / `..._DESTINATION_IP`, `COOKIE`, `SIGNATURE_HASH_ALGORITHMS`, `IKEV2_FRAGMENTATION_SUPPORTED`, Vendor IDs |
| `IKE_AUTH` | **ENCRYPTED** | `IDi`/`IDr`, `AUTH`, certificates, **`SAi2/SAr2` — the Child (ESP) SA proposal**, `TSi`/`TSr` traffic selectors, `USE_TRANSPORT_MODE`, `ESP_TFC_PADDING_NOT_SUPPORTED` |
| `CREATE_CHILD_SA` | **ENCRYPTED** | Rekey proposals, optional `KEi/KEr` (**this is what "PFS" means in IKEv2**) |
| `INFORMATIONAL` | **ENCRYPTED** | Deletes, liveness checks |

> **⚠️ Headline finding F-01 `[FACT]`.**
> **The ESP cipher suite, the tunnel/transport mode selection, the traffic selectors, the peer
> identities, the authentication payload, and the PFS group are all negotiated inside the
> *encrypted* portion of IKE.** At vantage point V0/V1 they are **not directly readable**.
>
> This directly contradicts the implicit assumption in PS section C, which lists "encryption
> algorithm", "authentication algorithm" and "tunnel/transport mode" as things to be "identified"
> from traffic. They can be *constrained* or *inferred*, not *read*, unless we move to V3/V4.

`[FACT]` **IKEv2 does not negotiate SA lifetimes at all.** RFC 7296 §2.4: *"there is no reason to
negotiate and agree upon an SA lifetime."* Lifetime is purely local policy on each peer.
⇒ **Headline finding F-02:** "Key lifetime" (PS section D) cannot be *read* from IKEv2 under any
vantage point short of V3. It can only be **measured empirically** as the observed interval /
byte-count / packet-count between SPI changes. That is a legitimate and arguably more useful
capability — it reports what the deployment *actually does*, not what it claims.

### 3.3 IKEv1 leaks far more (and this matters)

- `[FACT]` IKEv1 **Main Mode** messages 1–2 carry the full ISAKMP SA transform set in plaintext —
  encryption algorithm, hash, authentication method (PSK / RSA_SIG / …), DH group, **and the
  negotiated SA lifetime attributes**. Only Phase 2 (Quick Mode), which negotiates the ESP
  algorithms and mode, is encrypted.
- `[FACT]` IKEv1 **Aggressive Mode** additionally exposes the initiator identity and an
  authentication hash in plaintext, enabling offline dictionary attack against a PSK. This is a
  long-standing, well-documented weakness (the basis of `ike-scan --pskcrack`).
- `[INFER]` ⇒ Aggressive-Mode-with-PSK detection is a **fully deterministic, high-severity,
  100%-observable** finding requiring no AI whatsoever.

> **Structural insight F-03 `[INFER]`, high leverage.**
> **Observability is inversely correlated with security.** A weak legacy IKEv1/Aggressive/DES
> deployment reveals almost everything about itself. A correctly configured IKEv2 + AES-GCM +
> ECDH deployment reveals almost nothing.
> ⇒ The analyzer's blind spots are concentrated precisely where risk is lowest, and its sharpest
> vision is precisely where risk is highest. This is a genuinely strong argument for the whole
> product, and it is honest. It should become a core narrative pillar.

### 3.4 ESP on the wire

`[FACT]` RFC 4303 wire format:
```
[ outer IP ][ SPI(4) | Seq(4) ][ IV ][ ciphertext: payload | pad | padlen(1) | nexthdr(1) ][ ICV ]
                ^^^^^^^^^^^^^ always plaintext
```
Always visible at V0: outer addresses, **SPI**, **sequence number**, total length, arrival time,
DSCP/ECN, TTL, and whether it is native ESP (proto 50) or UDP-encapsulated (RFC 3948, UDP/4500)
or ESP-in-TCP (RFC 8229).

`[FACT]` Per-suite structural constants:

| Suite | IV bytes | ICV bytes | Ciphertext alignment |
|---|---|---|---|
| AES-CBC + HMAC-SHA1-96 | 16 | 12 | 16 |
| AES-CBC + HMAC-SHA256-128 | 16 | 16 | 16 |
| AES-CTR + HMAC-* | 8 | 12/16 | 4 |
| AES-GCM-16 (RFC 4106) | 8 | 16 | 4 |
| ChaCha20-Poly1305 (RFC 7634) | 8 | 16 | 4 |
| AES-CBC + AES-XCBC-MAC-96 | 16 | 12 | 16 |

> **Finding F-04 `[STRONG]`, becomes `[FACT]` after our own experiment.**
> Because these constants are fixed, the set of cipher suites **consistent with an observed stream
> of ESP frame lengths** can be computed by a *deterministic constraint sieve*: for each candidate
> suite, test whether every observed length satisfies
> `(esp_payload_len − 8 − IV − ICV) mod alignment == 0`.
> Over a few hundred packets with varied inner sizes, this collapses the candidate set sharply.
> **This is a deterministic algorithm, not a classifier, and it is fully explainable.**
> It is a strong candidate to *replace* an ML component that competing teams will build.
>
> Limits of the sieve, stated honestly:
> - AES-GCM-16 and ChaCha20-Poly1305 share the (8, 16, 4) signature ⇒ **indistinguishable by
>   length alone**. `[FACT]`
> - Distinguishing CBC+SHA1-96 from CBC+SHA256-128 requires knowing an inner packet size (a fixed
>   ICMP payload, a known codec frame) to resolve the constant offset. `[INFER]`

> **⚠️ Headline finding F-05 — an information-theoretic impossibility `[FACT]`.**
> **AES-128 and AES-256 are indistinguishable in ESP traffic.** They share block size, IV length,
> ICV length and ciphertext alignment; the key length leaves *no trace whatsoever* on the wire.
> Round-count timing differences (10 vs 14 rounds) are nanoseconds under AES-NI and are swamped by
> network jitter by many orders of magnitude — not a credible channel.
> ⇒ The PS's requirement to distinguish "AES-128" from "AES-256" is **satisfiable only at V1 for
> the IKE SA** (key length is an explicit transform attribute in plaintext `IKE_SA_INIT`) **or at
> V3/V4 for the ESP SA**. At V0 it is **not recoverable, and no amount of AI changes that.**
> Any team claiming otherwise is either using IKE data and mislabelling it, or overfitting to a
> testbed artifact.

### 3.5 Per-attribute Observability Matrix

Legend: **O** = directly observable/deterministic · **M** = indirectly *measurable* ·
**I** = inferable with quantified uncertainty · **N** = not recoverable

| # | Attribute (from PS §C/§D) | V0 (ESP only) | V1 (+IKE) | V3 (+endpoint) | Method | Conf. |
|---|---|---|---|---|---|---|
| A1 | IPsec present; ESP vs AH | **O** | **O** | O | proto 50/51, UDP/4500 heuristic, RFC 8229 | `[FACT]` |
| A2 | IKE version (v1/v2) | N | **O** | O | ISAKMP header version + exchange types | `[FACT]` |
| A3 | IKEv1 mode (Main/Aggressive) | N | **O** | O | exchange type field | `[FACT]` |
| A4 | **IKE SA** cipher/PRF/INTEG/DH **incl. key length** | N | **O** | O | plaintext `SAi1/SAr1` transforms | `[FACT]` |
| A5 | **ESP (Child SA) cipher suite family** (CBC-block vs AEAD/counter) | **I** | **I** (+ strong prior from A4) | **O** | length-residue sieve (F-04) | `[STRONG]` |
| A6 | **ESP AES key length (128 vs 256)** | **N** | **N** | **O** | — | `[FACT]` F-05 |
| A7 | Tunnel vs Transport mode | **I** | **I** | **O** | endpoint-vs-host topology; 20/40-byte inner-header length shift; MTU/frag behaviour | `[INFER]`, needs `[EXP]` |
| A8 | Authentication method (PSK / cert / EAP) | N | **I** | **O** | presence of `CERTREQ`, `SIGNATURE_HASH_ALGORITHMS`; IKE_AUTH round-trip count for EAP | `[HYP]` → `[EXP]` |
| A9 | Key exchange group (DH/ECDH) for **IKE SA** | N | **O** | O | transform + `KE` payload length | `[FACT]` |
| A10 | **PFS on/off** for Child SA | N | **I** | **O** | presence of a `KE` payload inside encrypted `CREATE_CHILD_SA`, inferred from a group-sized length increment | `[HYP]` → `[EXP]` — *novel, testable* |
| A11 | SA lifetime / rekey policy | **M** | **M** (v1 Main Mode: **O**) | **O** | measure SPI-change interval, bytes, packets | `[FACT]` F-02 |
| A12 | Replay protection **in use** (seq numbers incrementing, no reuse) | **O** | **O** | O | ESP sequence field analysis | `[FACT]` |
| A13 | Replay protection **enforced by receiver** | **N** (passive) | **N** | **O** | requires active test or endpoint config | `[FACT]` — important honesty point |
| A14 | Extended Sequence Numbers (ESN) | **N** in practice | **I** | **O** | only visible after 2³² packets or via ICV computation | `[INFER]` |
| A15 | NAT traversal in use | **O** | **O** | O | UDP/4500, non-ESP marker, `NAT_DETECTION_*` notifies | `[FACT]` |
| A16 | IPv4 / IPv6 outer | **O** | **O** | O | outer header | `[FACT]` |
| A17 | IPv4 / IPv6 **inner** | **I** | **I** | **O** | tunnel-mode length shift 20 vs 40 | `[INFER]` |
| A18 | Implementation / vendor / version fingerprint | **I** (rekey cadence, DPD timing, padding style) | **O**-ish (Vendor ID payloads, notify ordering, retransmit timers) | O | fingerprinting | `[STRONG]` |
| A19 | Traffic-flow-confidentiality (TFC) padding in use | **I** | **I** | **O** | length-distribution flatness | `[HYP]` |
| A20 | Inner application/traffic type | **I**, degraded | **I**, degraded | **O** (V2) | packet size/timing/direction sequence models | `[HYP]` — see §4 |
| A21 | Metadata exposure profile | **O** | **O** | O | enumeration of what a passive observer learns | `[FACT]` |
| A22 | Hybrid/PQ key exchange (RFC 9370) | N | **O** | O | `IKE_INTERMEDIATE` exchange + additional KE transform types | `[FACT]` |

**GATE-1 preliminary verdict:** of the 22 attributes the PS implies, **at V0 only 5 are directly
observable.** At V1 that rises to ~10. Reaching the PS's full stated ambition requires V3 or V4.

---

## 4. Inner-traffic classification — the requirement most likely to be overclaimed

`[FACT]` ESP padding is minimal by default (alignment only); RFC 4303's traffic-flow-confidentiality
padding is optional and rarely enabled ⇒ **inner packet lengths are largely preserved**, so a
length/timing side channel genuinely exists.

`[STRONG]` But the published evidence base is far weaker than headline accuracies suggest:
- The 2025 SoK on encrypted traffic classifiers (arXiv:2503.20093) reports that **the majority of
  proposed classifiers mistakenly used *unencrypted* traffic** because of legacy datasets, and that
  348 feature-occlusion experiments showed design choices leading to overfitting.
- ISCXVPN2016 — the field's most-used VPN benchmark — is reported as **~98.9% unencrypted**, covers
  **only OpenVPN in UDP mode**, and is a decade old. It contains **no IPsec at all**.
- Shortcut-learning work ("Bias in the Shadows") shows models latching onto dataset artifacts rather
  than protocol semantics, with collapse under domain shift.

`[INFER]` **Gap G-1, and a trap.** Nearly all published VPN traffic classification assumes
**one application flow per tunnel**. Real IPsec **tunnel mode multiplexes many inner flows onto a
single ESP SA (one SPI)**. The observable stream is therefore a *mixture*, and per-application
classification becomes a blind source-separation problem, not a classification problem.
- If we ignore this, we will produce a testbed-only result that is scientifically worthless.
- If we address it explicitly — even by *bounding* it — it is a legitimate research contribution.
- Open question **OQ-04**: does any credible work address the tunnel-mode mixture case?

`[HYP]` A defensible reformulation to be evaluated in DEFINE: instead of *"which app is inside?"*,
ask *"what is the **traffic-character profile** of this SA (interactive / real-time-constant-rate /
bulk / bursty-web / idle-keepalive), and what does that profile imply for metadata exposure and
for the observer's ability to profile this tunnel?"* This is (a) actually learnable, (b) actually
useful to a security assessment, (c) not a surveillance capability, and (d) honest.

---

## 5. Requirements from the PS that must be challenged

| PS text | Problem | Status |
|---|---|---|
| "identify … encryption algorithm" (§C) | Child SA algorithm is inside encrypted IKE_AUTH | Re-scope: family-level sieve at V0/V1 (F-04); exact at V3/V4 |
| "AES-128 / AES-256" as distinguishable classes (§A/§C) | Information-theoretically impossible at V0 (F-05) | **Formally decline at V0**; deliver at V1 (IKE SA) / V3 |
| "authentication algorithm" (§C) | Ambiguous: ESP integrity algorithm, or IKE peer-authentication method? | Disambiguate; both need separate treatment |
| "key lifetime" (§D) | IKEv2 does not negotiate lifetimes at all (F-02) | Re-scope to *empirically measured* rekey behaviour |
| "replay protection" (§D) | Passive capture cannot show receiver-side enforcement (A13) | Re-scope to "sequence-number hygiene observed"; enforcement needs V3 or an authorized active test |
| "Predicted type of traffic inside ESP-IPsec" (§C) | Tunnel-mode multiplexing + inflated literature (G-1) | Re-scope to traffic-character profiling with calibrated uncertainty |
| "AH packets (optional)" (§B) | AH is effectively obsolete in deployment; RFC 8221 discourages it | Keep parser, drop from ML scope |
| Full cross-product of config axes (§A) | ~8 axes ⇒ combinatorial explosion, most cells scientifically redundant | Replace with a covering-array / fractional-factorial design (Q14) |
| "AI-driven" (title) | Several capabilities are strictly better solved deterministically | Resolve in the AI Necessity Matrix (Phase 11); do not pre-commit |

---

## 6. What this implies (provisional, not a decision)

`[INFER]` The centre of gravity of a defensible system is shifting away from
*"an AI that reads encrypted traffic"* and toward:

1. A **deterministic evidence engine** over plaintext IKE + ESP header/length/timing structure.
2. An explicit **vantage-point and confidence model** — the thing every competing team will lack.
3. A **standards-mapped assessment engine** (RFC 8221/8247/9395, SP 800-77r1, SP 800-131A, CNSA).
4. A **small, honest, well-calibrated statistical layer** for the genuinely uncertain attributes
   (A5, A7, A10, A19, A20), each with a measured deterministic baseline to beat.

This is a *hypothesis to be tested against ≥4 rival concepts in DEVELOP*, not a selection.
Recorded as **H-A** in the assumption register.

---

## 7. Open items blocking GATE-1

- **OQ-01** Verify F-04 (length-residue sieve) empirically across strongSwan/Libreswan for all
  suites in §3.4. `[EXP]`
- **OQ-02** Verify F-05 by attempting, and failing, to separate AES-128 from AES-256 — a
  deliberate **negative result** we should publish in the report. `[EXP]`
- **OQ-03** Test A10 (PFS via encrypted `CREATE_CHILD_SA` length increment). `[EXP]`
- **OQ-04** Literature check: tunnel-mode multi-flow mixture classification. `[UNK]`
- **OQ-05** Confirm A8 (auth-method inference from `CERTREQ` / `SIGNATURE_HASH_ALGORITHMS`) across
  implementations. `[EXP]`
- **OQ-06** Confirm which of A1–A22 Zeek/Wireshark already extract (feeds D2).
