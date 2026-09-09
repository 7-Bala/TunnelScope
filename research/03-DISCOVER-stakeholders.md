# Discover D3 — Stakeholders, Workflows and Consequences

**Purpose:** answer Q17–Q20. **Evidence caveat `[STRONG→INFER]`:** we have no direct access to
practitioners. Findings here are built from vendor support knowledge bases, government control
documents, pentest methodology write-ups and community forums — good evidence of *what goes wrong*
and *what procedures exist*, weaker evidence of *what people feel*. Everything is tagged.

---

## 1. The problem statement's hidden assumption about who this is for

`[INFER]` The PS reads as though there is one user: "an analyst" who receives a capture and wants a
security assessment. The evidence says there are **at least four distinct roles with incompatible
needs**, and they differ on the one variable that decides the architecture: **what access they have.**

| Role | Access they have | Their actual question | Vantage available |
|---|---|---|---|
| **A. VPN / network engineer** (operations) | Full — both endpoints, configs, CLI | *"Why is this tunnel down / flapping?"* | V2–V5 |
| **B. Security auditor / compliance assessor** | Own estate, read-only, often config exports | *"Does this deployment meet the baseline, and can I evidence it?"* | V1, V3, sometimes V5 |
| **C. Penetration tester / red team** | External only, authorized target list | *"What is exposed and weak from outside?"* | V0, **V5** |
| **D. SOC analyst / incident responder** | Capture from a tap/SPAN; usually **no endpoint access** | *"What is this ESP flow, is it authorized, and what is it carrying?"* | **V0, sometimes V1** |

> **Finding S-01 `[INFER]`, high leverage.** Role D — the one whose vantage point is weakest — is
> the role the PS implicitly describes ("inspect captured traffic … without requiring manual packet
> inspection"). But roles A, B and C, who have far more access, are the ones with **budget,
> mandate and an existing procedure**. Designing exclusively for D produces a tool that can answer
> the least. Designing exclusively for A/B/C ignores the PS.
>
> **This asymmetry, not any single technical limit, is the strongest argument for a
> vantage-tiered architecture** that serves all four and declares which tier produced each finding.

---

## 2. What each role does today

### Role A — network / VPN engineer `[STRONG]`

Documented workflow across Cisco, Fortinet, Palo Alto, F5 and Red Hat:
```
symptom (tunnel down / flapping / BGP drop)
  → enable vendor debug (debug crypto ikev2 …)
  → trigger interesting traffic to force a new negotiation
  → grep logs by peer IP
  → compare BOTH sides' configs by hand
  → change one parameter, retry
```
**Bottlenecks:** debug output is vendor-specific and verbose; requires privileged access to *both*
peers, often across two organizations; the decisive information (Phase-2 proposal, traffic
selectors) is encrypted, so a capture cannot substitute.

> `[STRONG]` **The industry's own advice is to abandon the packet capture.**
> *"This encryption mismatch won't be visible in a packet capture unless the pcap is manually
> decrypted, so it's best to use CLI commands or check both sides' configurations manually."*
> — Palo Alto guidance on `NO_PROPOSAL_CHOSEN`

### Role B — auditor / compliance assessor `[FACT]`

There is a real, citable control set. **DISA VPN Security Requirements Guide V2R6** contains
directly assessable IPsec requirements:

| Rule | Requirement (as titled) |
|---|---|
| V-207205 | *The IPsec VPN Gateway must use IKEv2 for IPsec VPN security associations.* |
| V-207193 | *…must be configured to use a Diffie-Hellman (DH) Group of **16 or greater** for IKE Phase 1.* |
| V-207223 | *…must use FIPS-validated **SHA-2 at 384 bits or higher** for IKE.* |
| V-207230 | *…must use AES encryption for the IKE proposal…* |
| V-207192 | *…must use IPsec with SHA-2 at 384 bits or greater for hashing…* |
| V-207212 | *The IPsec VPN Gateway must use **anti-replay mechanisms** for security associations.* |
| V-207184 | *…ESP in tunnel mode for establishing secured paths.* |

> **Finding S-02 `[FACT]` — a genuine source conflict, to be surfaced not hidden.**
> **RFC 8247** sets group 14 (2048-bit MODP) as the mandatory-to-implement IKEv2 baseline.
> **DISA V-207193** demands **group 16 or greater**. **NIST SP 800-77r1** sits between them.
> These are not contradictory — they are *different baselines for different risk tiers*.
> ⇒ A single "compliant / non-compliant" verdict is meaningless. Every finding must name **which
> authority** it is judged against. This is a hard architectural requirement, derived from evidence,
> and it distinguishes a credible tool from a checkbox.

Note also **V-207212 (anti-replay)**: assessing it requires knowing the *receiver* enforces a replay
window — which D1 (A13) establishes is **passively unobservable**. Endpoint telemetry (strongSwan
`replay_window`, default 32, `0` disables) or an authorized active test is the only way.
**A named government control cannot be assessed passively.** That is an evidence-based argument for
including non-passive capability, not a preference.

### Role C — penetration tester `[STRONG]`

Documented methodology: reconnaissance → vulnerability assessment → exploitation → reporting
(typically 6–9 days). For IPsec specifically: port-scan UDP/500 for ISAKMP, fingerprint with
`ike-scan`, enumerate Phase-1 transforms, attempt Aggressive-Mode PSK capture and offline cracking,
check for default accounts.

> `[INFER]` Two observations. First, this is **entirely active** and entirely IKEv1-shaped — the
> tooling (D2 §2.4–2.5) has not kept up with IKEv2. Second, the methodology guides themselves say
> *"a review of the VPN architecture and system configuration is suggested following the
> penetration test."* Even the outside-in role ends by asking for the configuration. **Every role's
> workflow terminates in endpoint configuration review.** That is a strong signal about where truth
> lives.

### Role D — SOC analyst `[EVIDENCE, vendor-sourced — weight accordingly]`

- >90% of internet traffic is encrypted; **55% of security teams report encrypted-traffic blind
  spots** (Network Threat Detection survey, vendor-published — tier 6, use as motivation only).
- Practically: an ESP flow appears in NDR/Zeek/SIEM as an opaque connection record. The analyst can
  see endpoints, volume and timing, and little else. Zeek will not even see native ESP unless it is
  UDP/TCP-encapsulated (D2 §2.1).
- The realistic SOC questions are **not** "which cipher" but: *is this tunnel authorized? has its
  behaviour changed? is it exfiltration shaped like a VPN?*

> **Finding S-03 `[INFER]`.** The PS's framing (identify the cipher suite from traffic) is an
> **auditor's question posed with a SOC analyst's access**. That mismatch is the root of most of the
> observability problems in D1. Naming it is a large part of the refined problem statement.

---

## 3. Jobs to be done (evidence-ranked)

| JTBD | Role | Evidence | Currently served? |
|---|---|---|---|
| J1 — Tell me **why** this tunnel won't establish / keeps flapping | A | PE-01, PE-02 `[STRONG]` | ❌ Manual, dual-sided, expert-only |
| J2 — Give me **evidence** that this deployment meets baseline X | B | DISA SRG, NIST `[FACT]` | ⚠️ Partial; manual; no evidence trail |
| J3 — Tell me what this deployment **actually does over time**, not what its config claims | A, B | PE-02 lifetime/rekey failures, F-02 `[STRONG]` | ❌ Nothing does this |
| J4 — Tell me **how much this tunnel leaks** to a passive observer | B, D | Wright et al., RFC 6562, RFC 9347 `[FACT]` | ❌ Nothing does this |
| J5 — Tell me what is **exposed and weak** from outside | C | pentest methodology `[STRONG]` | ⚠️ IKEv1-era tools only |
| J6 — Tell me what is **inside** this ESP flow | D | PS §C | ❌ and largely infeasible (D4 §3) |
| J7 — Tell me if this tunnel's behaviour **changed** | A, D | PE-02 blast radius `[INFER]` | ❌ |

> **The PS spends most of its text on J6 — the least feasible and least served-by-evidence job —
> and does not mention J1, J3, J4 or J7 at all.** J1 and J3 are the ones practitioners
> demonstrably struggle with; J4 is the one nobody addresses; J2 is the one with a government
> mandate attached.

---

## 4. Consequences of being wrong (Q19)

Asymmetric, and the asymmetry must drive thresholds — a single accuracy number cannot.

| Finding type | False positive | False negative | Asymmetry |
|---|---|---|---|
| "PFS disabled" | Unnecessary change window on a production tunnel; credibility loss | A real forward-secrecy weakness persists | **FN worse** → bias toward reporting, with confidence stated |
| "Weak cipher suite" | Emergency remediation of a healthy tunnel; possible outage | Weak crypto stays deployed | **FN worse** |
| "Traffic inside = X" | Analyst acts on a fiction; possible wrongful attribution of a person's activity | Missed detection | **FP much worse** — and it is a *privacy* harm, not just an error (§5) |
| "Replay protection absent" | Config churn | A real anti-replay gap (V-207212) | **FN worse**, but passively **unknowable** → must return *Unknown*, never *Pass* |
| "Compliant with baseline X" | **False assurance** — the worst outcome in the whole system | Unnecessary work | **FP catastrophic** |

> **Design lesson DL-05.** The system must be able to output **`UNKNOWN`** and **`NOT OBSERVABLE`**
> as first-class verdicts, and must never let absence of evidence render as compliance. Silence
> where a control cannot be assessed is a false assurance, and false assurance is the single most
> damaging failure mode an assessment tool has.

---

## 5. Legal, ethical and scope envelope (Q20)

`[INFER]`, but firm:

- **J6 (inner-traffic identification) is a surveillance capability.** Applied to one's own tunnels
  it is a posture measurement; applied to third-party tunnels it is traffic analysis of other
  people's communications. The distinction is *who owns the tunnel*, not the technique.
  ⇒ The **CS-01 reframing** (measure leakage against your own deployment) keeps the capability on
  the defensible side of that line while still satisfying the PS.
- **Active probing (V5) requires asserted ownership/authorization**, scoped to a declared target
  list, rate-limited, logged, and refusing out-of-scope targets. This is a build requirement, not a
  disclaimer.
- **PSK cracking** (ike-scan `psk-crack`) is legitimate against one's own gateway to prove an
  Aggressive-Mode weakness, and is an attack tool otherwise. If included at all, it must be
  gated behind explicit ownership assertion and should probably be *detected and reported* rather
  than *performed*.
- Captures may contain organizational metadata; retention and access control matter even though
  payloads are encrypted.

---

## 6. Dashboard implications (early, provisional)

`[INFER]` from S-01/S-03 and DL-05 — every panel must earn its place against a JTBD:

- The first screen answers **J2/J3**, not "here are some charts."
- **Vantage point and evidence tier must be visible on every finding** — not buried in a tooltip.
- `UNKNOWN` / `NOT OBSERVABLE` need first-class visual treatment, distinct from `PASS`.
- Baseline selection (RFC 8221/8247 · NIST SP 800-77r1 · DISA VPN SRG) must be an explicit control,
  because S-02 proves there is no single right answer.
- Drill-down must reach **the packet and field** that justify each verdict; that is the antidote to
  both the black-box problem (D4 §5) and Suricata's evidence-destroying alert model (DL-01).

---

## 7. Open questions from D3

- **OQ-08 → partially closed.** Four roles identified with distinct access and questions. Direct
  practitioner validation still absent.
- **OQ-23** (new) Which of the four roles does NTRO actually represent? The organization implies
  government signals/security — closest to B and D. Affects prioritisation but not architecture.
- **OQ-24** (new) Are there Indian-government-specific cryptographic baselines (CERT-In / MeitY /
  STQC) we should encode alongside NIST and DISA? Searched; found CERT-In *Guidelines on Information
  Security Practices for Government Entities* but no IPsec-specific algorithm baseline. Worth one
  more pass — high presentational value for an NTRO statement.
