# Discover D8 — Convergent Prior Art: The Framework I Proposed Already Exists (for TLS)

**This is the most consequential document of the Discover phase, and it begins with two
corrections to my own earlier claims.**

---

## 1. What was found

**Meseguer-style multi-surface observability for post-quantum readiness — published in 2026, for TLS.**

- *Observability for Post-Quantum TLS Readiness: A Multi-Surface Evidence Framework*
  — arXiv:2605.02978 / IACR ePrint 2026/866. Artifact:
  `github.com/hypergalois/pqc-tls-observability`.
- *Detecting Post-Quantum and Hybrid TLS Deployments via Raw TLS Record Inspection*
  — IACR ePrint 2026/834.

### What the framework does `[FACT]`

**Four evidence surfaces:**

| Surface | Content |
|---|---|
| **ΣP — Passive session** | Handshake fields from packet captures: version, selected groups, cipher suites, certificate visibility (TLS 1.2) |
| **ΣA — Active probe** | Deliberate connections with *declared client profiles*; yields **capability lower bounds** and details hidden from passive view |
| **ΣC — Certificate chain** | Leaf/intermediate algorithms, validity intervals, chain depth |
| **ΣR — Registry / rules** | Normalisation of raw identifiers; algorithm status (draft / final / obsolete); inference rules held **outside parser code** |

**Seven measurement planes with explicit closure conditions:** session core, key establishment,
capability, authentication, lifecycle, observability (linkage/confidence/provenance), and an
**optional policy plane kept downstream of measurement**.

**Their stated closure rule:**
> *"Passive evidence closes session-level planes, active probing closes capability lower bounds,
> and certificate-chain evidence closes authentication and lifecycle when source and linkage are
> explicit."*

**Unresolved states are first-class measurement outcomes:** `Unknown`, `Not applicable`,
`Ambiguous`, `Contradictory` — with contradictions between surfaces *preserved in the output rather
than reconciled away*.

**Benchmark:** PQ-TLS Observability Benchmark v1 — **29 controlled scenarios (14 canonical,
15 stress)**, where the stress scenarios explicitly *reward correct uncertainty preservation*
(e.g. a truncated capture showing only a partial ServerHello must emit `unknown`, not guess).

---

## 2. Correction 1 — G-06 was wrong

**What I claimed (D2 §4, D6):** *"No vantage-point model exists anywhere in the ecosystem."*

**What is true `[FACT]`:** one exists, is published, is benchmarked, and has released code — for
**TLS**. My claim was correct about the *IPsec tooling ecosystem* and false as a statement about the
field. G-06 is hereby **narrowed**: no such model exists **for IPsec/IKEv2**, which the authors
state explicitly is out of their scope (*"The work is exclusively focused on TLS, not IPsec/IKEv2
or other protocols"*).

## 3. Correction 2 — CS-05's novelty claim was too broad

**What I claimed (D7):** PQ-readiness observability is unserved.

**What is true:** PQ-readiness observability is **served for TLS and unserved for IPsec/IKEv2**.
The precise, defensible claim is now narrower and better:

> Post-quantum readiness observability has been formalised, benchmarked and released **for TLS**.
> **The IPsec/IKEv2 analogue does not exist** — and it is not a mechanical port, because:
> 1. IKEv2's PQ negotiation spans **two exchanges** (`IKE_SA_INIT` proposals + `IKE_INTERMEDIATE`
>    payloads, RFC 9242/9370) with **up to seven ADDKE transforms**, versus TLS's single
>    `key_share` in one hello pair;
> 2. the leading dissector **cannot decode it** (Wireshark #21072), so there is no equivalent of the
>    "inherited analyzer" adapter their artifact relies on — the parser must be built;
> 3. IPsec has an **ESP data plane with no TLS counterpart**, carrying SA lifecycle, rekey/PFS
>    behaviour, replay hygiene and a metadata side channel — none of which their seven planes model;
> 4. IPsec's authentication and identity payloads are **encrypted** (F-01), whereas TLS 1.2
>    certificates are passively visible — so the passive surface closes *less* in IPsec, making the
>    surface-separation discipline *more* necessary, not less.

---

## 4. Why this find makes the project stronger, not weaker

It costs us a novelty claim on the *framework* and buys something worth far more.

### 4.1 Independent validation of five decisions I had already made

I derived the following from RFCs, vendor KBs and the observability analysis, before finding this
paper. It reaches materially the same conclusions from an independent direction, for the analogous
problem:

| Our decision | Their equivalent |
|---|---|
| **DEC-002** Observability Gate — classify every capability O/M/I/N | Measurement planes with explicit **closure conditions** |
| **DEC-003** Vantage taxonomy V0–V5; every finding declares its vantage | **Evidence surfaces ΣP/ΣA/ΣC/ΣR** with retained **provenance labels** |
| **DEC-005** Passive-first + active escalation; active closes what passive cannot | *"Active probing closes **capability lower bounds**"* — and their active surface exists **precisely because passive cannot close capability** |
| **DEC-007** Name the authority behind every compliance verdict; never emit unqualified "compliant" | **Policy plane kept downstream of measurement**; registry holds algorithm status separately from parser code |
| **DEC-008** `UNKNOWN` / `NOT OBSERVABLE` are first-class verdicts | `Unknown` / `Not applicable` / `Ambiguous` / **`Contradictory`** as first-class outcomes, contradictions preserved |

> `[INFER]` **Convergent derivation is strong evidence that the architecture is right.** For an SIH
> jury this is far more persuasive than an unsupported claim of originality: *"we derived this
> architecture from the protocol; independent 2026 research derived the same architecture for TLS;
> we are building the IPsec instance, which they explicitly excluded."*

### 4.2 Two things they do that I had not thought of — adopt both

1. **`Contradictory` as an explicit outcome.** I had `Unknown` and `Not observable` (DEC-008), but
   not a state for *two surfaces disagreeing*. In IPsec this is a **first-class product feature**,
   not an edge case: the whole point of DEC-005's cross-tier consistency check is that T0/T1
   inference can disagree with T2/T3 truth. That disagreement is our validation signal *and* a real
   security finding (an endpoint whose reported config contradicts its observed behaviour).
   **Elevate to a design requirement.**
2. **Inference rules and registries held *outside* parser code, versioned.** Their registry maps raw
   identifiers to canonical meanings and tracks draft/final/**obsolete** status. For us this is
   exactly how RFC 9395's new IANA "Status" column, RFC 8221/8247 requirement levels, and the DISA
   rule IDs should be encoded — as **versioned data, not code**. This makes multi-baseline
   assessment (DEC-007) tractable and makes the whole engine auditable.

### 4.3 A benchmark design to mirror

Their **29 scenarios (14 canonical + 15 stress)**, where stress scenarios *reward correct
uncertainty preservation*, is a directly transferable and highly defensible validation design.
An **"IPsec Observability Benchmark"** built the same way — canonical configurations plus stress
cases (truncated capture, capture starting mid-SA, packet loss, NAT rewriting, missing IKE,
contradictory endpoint telemetry) — would be a genuine research deliverable, and it maps cleanly
onto the PS's "Dataset used for training/testing."

### 4.4 Prior art check on the other lead — resolved

*Hybrid Quantum Security for IPsec* (arXiv:2507.09288) is an **implementation and performance
study** — Docker environments, strongSwan, QKD integration, overhead measurement. It builds no
network-forensics or detection tooling. `[FACT]` **It does not contest CS-05.** OQ-25 closed.

---

## 5. Revised gap statement

| ID | Revised gap | Status |
|---|---|---|
| **G-06** | ~~No vantage model anywhere~~ → **No evidence-surface / closure-condition model for IPsec/IKEv2.** One exists for TLS and is explicitly TLS-only | Narrowed, still valid |
| **G-08** | No RFC 9370 / `IKE_INTERMEDIATE` / ADDKE decoding or assessment. Confirmed for Wireshark (#21072); Zeek/Suricata pending (OQ-26) | **Confirmed** |
| **G-13** *(new)* | The TLS framework's seven planes **have no data-plane analogue**. IPsec's ESP plane — SA lifecycle, rekey/PFS behaviour, replay hygiene, metadata leakage — is unmodelled by any observability framework in either protocol | **New, and ours** |

`[INFER]` **G-13 is now the clearest statement of what this project uniquely contributes:** extending
multi-surface cryptographic observability from a *handshake-only* model to one that includes a
**long-lived, measurable data plane**. TLS has no equivalent of an SA that runs for hours, rekeys on
a policy you can only infer by watching, and leaks a measurable side channel the whole time.
That is genuinely new, it is IPsec-specific, and it is exactly where CS-01 (leakage quantification)
and CS-03 (SA lifecycle observatory) live.

---

## 6. Register deltas

**Corrections:** G-06 narrowed; CS-05 novelty claim narrowed and made precise.
**Closed:** OQ-25 (arXiv:2507.09288 is implementation-only, does not contest CS-05).
**New gap:** G-13 — no data-plane analogue in any cryptographic-observability framework.
**New design requirements:** `Contradictory` as a first-class outcome; versioned registries/rules
held outside parser code.
**New open questions:** OQ-28 (can we adopt their JSON schema shapes and registry pattern directly —
what licence is `hypergalois/pqc-tls-observability` under?), OQ-29 (does ePrint 2026/834's raw-record
inspection technique have an IKE analogue — key-share/KE-payload *length* as a PQ indicator even
without a dissector? This would be a passive PQ detector that works **despite** Wireshark's gap, and
it is the same length-signature reasoning as F-04 and A10 — a pleasing structural echo worth testing).
