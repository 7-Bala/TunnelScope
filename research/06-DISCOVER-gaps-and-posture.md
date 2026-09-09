# Discover D6 — Research Gaps, the Analysis-Posture Decision, and Readiness for DEFINE

---

## Part 1 — The analysis-posture decision (OQ-13, resolved)

The instruction was to decide this on evidence rather than escalate it. Here is the evidence and the
decision.

### 1.1 Evidence for and against each posture

| Evidence | Source tier | Implication |
|---|---|---|
| ESP suite, mode, PFS, identities, traffic selectors are inside **encrypted** IKE_AUTH / CREATE_CHILD_SA (F-01) | 1 — RFC 7296 `[FACT]` | Passive-only cannot *read* most of PS §C |
| IKEv2 **does not negotiate SA lifetimes** (F-02) | 1 — RFC 7296 `[FACT]` | "Key lifetime" is endpoint-local or must be measured over time |
| AES-128 vs AES-256 leaves **no trace** in ESP (F-05) | 1 — derived from RFCs `[FACT]` | Unrecoverable passively at any effort |
| Receiver-side **anti-replay enforcement** is passively unobservable (A13) — yet **DISA V-207212** mandates it | 1 + 2 `[FACT]` | A named government control is unassessable without endpoint or active test |
| Industry's own remedy for negotiation failure is *"use CLI commands or check both sides' configurations manually"* | 5 — vendor KB, multi-vendor `[STRONG]` | Practitioners already work at V3 because V0/V1 is insufficient |
| Every role's workflow — including **pentest** — terminates in configuration review (D3 §2) | 5 `[STRONG]` | Endpoint truth is the industry's actual ground truth |
| USENIX Sec '22 Best Paper fingerprints VPNs with a **two-phase passive filter → active prober** framework | 3 `[FACT]` | Top-tier VPN research *stages* passive and active rather than choosing |
| `ike-scan` IKEv2 support experimental; Nmap `ike-version` extracts **only Vendor IDs** | 4 `[FACT]` | There is no mature modern active IKEv2 prober — a real, checkable gap |
| **The PS itself requires us to build the testbed** (§A) and to generate the dataset (deliverables) | 0 — the PS `[FACT]` | Endpoint control is *inside the PS's own scope by construction* |
| strongSwan exposes authoritative SA state via `swanctl`/vici | 4 `[FACT]` | V3 telemetry is cheap and already available |
| Inner-traffic identification against tunnels one does not own is a surveillance capability (D3 §5) | — `[INFER]` | Argues for scoping capability to owned assets, i.e. toward V3/V5, not away |

### 1.2 Arguments considered and rejected

- *"Passive-only is cleaner to defend."* — True, and irrelevant. It would require formally declining
  a large fraction of PS §C and §D, including a control (V-207212) that a government baseline
  mandates. The instruction is to solve the PS as effectively as technically possible.
- *"Active probing is more impressive."* — Not a reason. Active capability is included only where a
  named capability is otherwise unobtainable.
- *"Keys/endpoint access are unrealistic."* — Contradicted by evidence. Roles A and B have that
  access by definition, the PS mandates building the testbed, and practitioners already rely on it.

### 1.3 Decision — **DEC-005**

> **Posture: passive-first, evidence-tiered, with endpoint-telemetry augmentation as the primary
> escalation and authorization-gated active probing as a bounded secondary escalation.**

Concretely, a **capability ladder** in which each tier is optional, each finding declares the tier
that produced it, and the system degrades explicitly rather than silently:

| Tier | Input | Added capability | Gate |
|---|---|---|---|
| **T0 — Passive, ESP only (V0)** | pcap / live tap | ESP structure, SPI lifecycle, rekey cadence, cipher-family sieve (F-04), metadata-exposure measurement (CS-01), mode inference | none |
| **T1 — Passive + IKE (V1)** | capture spanning negotiation | IKE version/mode, IKE SA suite **incl. key length**, DH group, NAT-T, PQ/hybrid (RFC 9370), vendor fingerprint, failure-mode diagnosis (CS-02) | none |
| **T2 — Endpoint telemetry (V3)** | `swanctl`/vici, `ip xfrm state`, config export | **Authoritative** ESP suite, key length, mode, PFS, replay window, lifetimes, traffic selectors — closes A6, A13, and most of §C/§D | user asserts ownership; read-only |
| **T3 — Keying material (V4)** | IKE/ESP keys for owned tunnels | Full IKE_AUTH decryption; inner-traffic ground truth for calibrating T0 leakage measurement | explicit, per-SA |
| **T4 — Authorized active probe (V5)** | declared target list | Supported-proposal enumeration, IKEv2-era fingerprinting, **anti-replay enforcement test**, Aggressive-Mode/PSK exposure check | signed scope assertion, rate limits, refusal outside scope, full audit log |

**Why this ordering.** T2 (endpoint telemetry) is deliberately placed *before* active probing.
It is lower-risk, higher-fidelity, matches what practitioners already do, and closes more of the
PS than active probing does. **Most teams will reach for active scanning because it looks like
security work; the evidence says read-only endpoint telemetry is the bigger win.**

**Non-negotiable constraints attached to DEC-005:**
1. Every finding renders its **evidence tier and vantage point**. A T2 verdict must never be
   presentable as a T0 one.
2. The system must be **fully functional at T0/T1** — the SOC/forensic case must not be a degraded
   afterthought.
3. **T4 refuses to run** without an explicit, logged scope assertion; nothing outside that scope is
   probed, ever.
4. A **cross-tier consistency check** is a first-class feature: where T2/T3 truth is available,
   verify T0/T1 inference against it and report the delta. *This turns the ladder into a
   self-validating instrument* — and it is exactly the experiment a jury will want to see.

`[INFER]` Constraint 4 is, on reflection, the most valuable consequence of this decision. It gives
the project a built-in, continuously running validation harness: every capture taken at T2/T3 is
simultaneously an inference task and its own answer key.

---

## Part 2 — Validated research gaps

Consolidated from D1–D5. Each gap is stated with the evidence establishing it and an honest
difficulty rating.

| ID | Gap | Evidence | Difficulty | Novelty |
|---|---|---|---|---|
| **G-01** | No SA-lifecycle measurement (effective rekey interval/bytes/packets, SPI churn, rekey-race detection) — the only route to "key lifetime" under IKEv2 | F-02 `[FACT]`; Suricata has no IKEv2 `sa_life_duration`; PE-02 | Low | Medium |
| **G-02** | No ESP-side cipher-suite inference from IV/ICV/alignment structure | F-04 `[STRONG]`; absent from all surveyed tools | Low–Medium | Medium-High |
| **G-03** | No negotiation-failure diagnosis from capture; industry answer is "read both configs by hand" | PE-01 `[STRONG]`, multi-vendor | Medium | **High** |
| **G-04** | **No metadata-exposure quantification.** Nobody tells an operator how much their tunnel leaks | Wright et al. `[FACT]`; WeFDE/Cherubin methodology exists but has never been applied to IPsec posture | Medium–High | **Very high** |
| **G-05** | No evidence-linked, confidence-tagged, per-SA posture record | DL-01 (Suricata's alert model destroys evidence) | Low | Medium |
| **G-06** | No vantage-point / evidence-tier model anywhere in the ecosystem | Absent from every tool surveyed | Low | **High** (conceptual) |
| **G-07** | No mature active IKEv2-era posture prober | ike-scan experimental; Nmap VID-only `[FACT]` | Medium | Medium |
| **G-08** | No RFC 9370 `IKE_INTERMEDIATE` / hybrid-PQ assessment | OQ-11 — no positive evidence found for any tool | Low–Medium | **High** (currency) |
| **G-09** | No standards traceability from finding → RFC clause / NIST / **DISA rule ID** | Absent; S-02 proves multi-baseline is required | Low | Medium-High |
| **G-10** | No modern, reproducible, publicly-datasetted work on classification **inside IPsec ESP specifically** | Only Okada and Kumano, both private datasets, both pre-crisis | High | Medium |
| **G-11** | **No public IPsec dataset labelled with cryptographic configuration** | D5 §1 `[FACT]` | Medium | **Very high** |
| **G-12** | **Tunnel-mode multiplexing is unaddressed** by the entire VPN-classification literature | D4 §3 `[INFER]`, OQ-04 still open | **Very high** | **Very high — and dangerous** |

### 2.1 Gap triage

- **Highest value-to-difficulty:** G-11 (dataset), G-06 (vantage model), G-01, G-09, G-05.
  These are near-certain wins and are what make the project *credible*.
- **Highest novelty at acceptable risk:** **G-04** (leakage quantification) and **G-03**
  (failure diagnosis). These are what make the project *interesting*. G-04 in particular transplants
  a mature, peer-reviewed methodology (Bayes-error / mutual-information security estimation from
  website fingerprinting) into a domain where nobody has applied it.
- **Trap:** **G-12.** Genuinely novel, genuinely important, and genuinely hard. Attempting to *solve*
  multiplexed-tunnel source separation is a research programme, not a hackathon deliverable.
  **The defensible move is to be the project that names, measures and bounds it** — quantify how
  fast classification degrades as concurrent inner flows increase, and publish that curve. That is
  a real contribution with a fixed cost.
- **Deprioritise:** G-10 as an accuracy race. Under the CS-01 reframing it is subsumed into G-04 and
  becomes a measurement rather than a claim.

---

## Part 3 — Is there actually a meaningful gap? (the honest answer)

The instruction was not to assume the PS proves a gap exists. Assessed directly:

**What is already solved and should not be rebuilt:** IKEv1/IKEv2/ESP/AH parsing (Zeek Spicy),
IKE payload dissection and key-driven decryption (Wireshark), basic weak-crypto alerting on IKE
proposals (Suricata's 14 rules), IKEv1-era active discovery and fingerprinting (ike-scan),
authoritative endpoint SA state (strongSwan vici).

**What is genuinely not solved:** everything in the G-table above. In particular, **no tool in the
ecosystem produces an assessment** — they produce *fields* (Zeek), *alerts* (Suricata), *dissection*
(Wireshark) or *reconnaissance* (ike-scan). None of them:
- reasons over a complete per-SA evidence record,
- states what it could not observe,
- names which baseline a verdict is judged against,
- measures behaviour over time,
- or quantifies exposure.

**Verdict `[INFER]`, high confidence:** the gap is real, but it is **not where the PS says it is.**
The PS locates the gap in *identification from encrypted traffic* (mostly infeasible, G-12). The
evidence locates it in **interpretation, evidence discipline, temporal measurement, and exposure
quantification** (feasible, unserved, and more useful).

That relocation is the central finding of the entire Discover phase.

---

## Part 4 — Contradictions surfaced and adjudicated

Per the source-quality protocol, contradictions are recorded, not hidden.

| # | Contradiction | Adjudication |
|---|---|---|
| C-1 | Vendor UIs present IKEv2 "lifetime" as negotiated; RFC 7296 §2.4 says lifetimes are **not negotiated** | RFC wins. Vendors expose *local rekey policy*. Our tool must say "observed rekey behaviour," never "negotiated lifetime." |
| C-2 | RFC 8247 baseline = DH group 14; **DISA V-207193 = group 16 or greater**; NIST SP 800-77r1 differs again | Not a contradiction — **different baselines for different risk tiers**. Forces the multi-baseline requirement (S-02). Never emit an unqualified "compliant." |
| C-3 | Published ETC accuracy 95–99% vs corrected 10–40% | Corrected figures win (E-02 methodology is sound and the failure mechanism is identified). Original numbers must never be cited as expected performance. |
| C-4 | Common guidance: "identify tunnel vs transport by looking for two IP headers" | **Only true after decryption.** The inner header is ciphertext at T0/T1. Widely repeated advice that does not apply to the passive case — a useful illustration of the expert-knowledge tax. |
| C-5 | RFC 8221/8247 keep AES-GCM at SHOULD for IKEv2; operational and government guidance push AEAD harder | Report the authority with the verdict. Do not merge authorities into a single opinion. |
| C-6 | Suricata *can* match `sa_key_length` for IKEv1 but not IKEv2, though the plaintext attribute exists in both | An implementation gap, not a protocol limit. Verify empirically (OQ-15); if confirmed, it is a concrete contribution to close. |

---

## Part 5 — Readiness assessment for DEFINE

### Gate status

| Gate | Criterion | Status |
|---|---|---|
| **GATE-1** Observability | Every PS attribute classified O/M/I/N with method and confidence | ✅ **PASS** (D1 §3.5). Five experimental confirmations remain (OQ-01/02/03/05) — these *refine* the matrix, they do not block DEFINE. |
| **GATE-2** Prior art | Capability and non-capability of the ecosystem established; reuse verdicts and licences recorded | ✅ **PASS** (D2). OQ-11 (RFC 9370 coverage) open but bounded. |
| **GATE-3** Gap validation | Gaps evidenced, triaged, difficulty-rated; distinguished from the PS's assumed gap | ✅ **PASS** (D6 Parts 2–3) |
| Posture decision | OQ-13 resolved on evidence | ✅ **DEC-005** |
| Stakeholders | Roles, workflows, JTBD, FP/FN consequences established | ⚠️ **CONDITIONAL PASS** — no direct practitioner contact; findings labelled `[INFER]` throughout (D3 preamble) |
| ML evidence | State of the art assessed *and discounted*; technique assignment drafted | ✅ **PASS** (D4) |
| Datasets | Landscape mapped; generation methodology and leakage controls specified | ✅ **PASS** (D5) |

### Recommendation

> **Discover is complete enough to enter DEFINE.**
>
> Justification: the decisions that DEFINE must make — what problem we are actually solving, which
> requirements to accept/re-scope/decline, and where AI is genuinely necessary — are all now
> **evidence-bound rather than opinion-bound**. Further Discover research would refine confidence
> on questions that no longer change those decisions.
>
> The remaining open questions fall into two classes, neither of which blocks DEFINE:
> - **Experimental** (OQ-01/02/03/05/15/17) — these *require the testbed*, which is a DELIVER/Phase-1
>   artifact. They cannot be closed by more reading. Attempting to close them before DEFINE would
>   invert the process.
> - **Peripheral** (OQ-16 statement ID, OQ-20 capture licensing, OQ-24 Indian baselines) — low
>   coupling to architecture.
>
> One deliberate exception: **OQ-04** (does any work address tunnel-mode multiplexing?) is worth one
> more focused literature pass *during* DEFINE, because it determines whether G-12 is framed as
> "an open problem we bound" or "an open problem we may have missed prior art on."

### What DEFINE must produce (per the plan, now with evidence attached)

1. Refined problem statement built on the **relocation** in Part 3.
2. Requirement dispositions: **accept / re-scope / decline**, each citing the Observability Matrix.
3. The **AI Necessity Matrix**, seeded by D4 §7 and disciplined by E-01…E-05.
4. Success metrics that are **not accuracy alone** — BER, mutual information, calibration error,
   abstention rate, and cross-tier consistency.
5. Explicit rejected scope, with the reasons on the record.

---

## Part 6 — Register deltas from this session

**New findings:** P-01…P-03, PE-01…PE-03, S-01…S-03, E-01…E-09, DL-01…DL-05, G-01…G-12, C-1…C-6
**New decisions:** DEC-005 (analysis posture)
**New concept seeds:** CS-01 (leakage quantification), CS-02 (failure diagnosis), CS-03 (SA
lifecycle observatory), CS-04 (vantage-aware evidence graph)
**New open questions:** OQ-14…OQ-24
