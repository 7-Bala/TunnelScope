# Phase 0 — Research Plan
**Project:** SIH26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
**Organization:** NTRO · **Category:** Software / Blockchain & Cybersecurity
**Plan version:** 0.1 · **Date:** 2026-09-09
**Status:** ACTIVE — Discover phase in progress. No solution architecture authorized yet.

---

## 0.1 Prior work in this repository (context, not conclusion)

`report.md` (29 Aug 2026) is a *problem-statement selection* study across 22 SIH statements. It
concluded with the selection of SIH26160 and sketched a concept called "IKEProof."

**How this plan treats that document:** as a prior hypothesis with useful signal, **not** as a
settled design. Specifically:

| Prior claim | Status now |
|---|---|
| SIH26160 is the right statement to pick | Accepted as a given (selection already made) |
| "Deterministic, evidence-first; small statistical layer" | **Hypothesis H-A**, to be tested in Discover, not assumed |
| "IKEProof" architecture | **Discarded for now.** Concept generation is Phase 3 (DEVELOP), and must produce ≥5 genuinely distinct concepts. Re-entering with a pre-selected concept would corrupt the process. |
| "Encrypted inner traffic is a limitation" | Directionally right, but stated too vaguely. Discover must produce a *precise, per-attribute* observability analysis. |

The prior report's real contribution is strategic (ground truth is available in a lab ⇒ the claim
is falsifiable ⇒ the demo is defensible). That insight is retained and is reflected in the
methodology choice below.

---

## 0.2 What kind of problem is this, actually?

Before choosing a methodology, classify the problem. Getting this wrong is the most common way a
design process produces confident nonsense.

This problem statement has **three structurally different sub-problems** bolted together, and they
require different research disciplines:

1. **A measurement-feasibility problem** (dominant).
   "What can be determined about an IPsec deployment from observed traffic?" This is not a design
   question and not a user question. It is an **information-availability** question with objective,
   partly *information-theoretic* answers. Some requested outputs may be provably unrecoverable.
   Discipline: protocol specification analysis + controlled measurement + side-channel reasoning.

2. **A normative/compliance problem.**
   "Given a determined configuration, is it secure?" This is a *policy mapping* problem against
   external authorities (RFC 8221/8247/9395, NIST SP 800-77r1, SP 800-131A, CNSA). It is
   deterministic and citation-based. Almost none of it is an AI problem.
   Discipline: standards analysis + threat modeling.

3. **A human/analyst problem** (smallest but not zero).
   "What does an analyst need to see, trust, and act on?" This is where HCD applies — chiefly to
   evidence presentation, uncertainty communication, and report design.
   Discipline: human-centred design + user research (with realistic access constraints — see R-07).

**Consequence:** a pure Double Diamond, which is designed around *human desirability discovery*,
would under-serve sub-problem 1 — the one that decides whether the project is even possible.
The methodology recommendation in §0.5 addresses this.

---

## 0.3 Critical research questions

Ordered by *decision leverage* — i.e. how much the answer changes what we build. Questions marked
**[GATE]** must be answered before any architecture is proposed.

### Tier 1 — Observability (existential; answers may kill requirements) **[GATE]**

- **Q1 [GATE]** For each attribute the PS asks us to identify, at which point in the IPsec/IKE
  exchange does that information appear on the wire, and is it plaintext or encrypted?
  → Produces the **Observability Matrix**, the single most important Discover artifact.
- **Q2 [GATE]** Which requested attributes are **information-theoretically unrecoverable** from
  passive capture (no keys, no endpoint access)? Candidate: AES-128 vs AES-256 for the ESP SA.
- **Q3 [GATE]** Which attributes are *not observable but are measurable indirectly* (e.g. SA
  lifetime via rekey interval; PFS via encrypted-payload length signature)?
- **Q4** What changes if the analyzer is given additional, legitimately obtainable inputs —
  endpoint config (`swanctl --list-sas`), IKE keying material, an inside-interface capture,
  or an active (authorized) probe? How much of the "impossible" list becomes possible, and at
  what deployment cost?
- **Q5** How do NAT-T (UDP/4500), IPv6, ESP-in-TCP, fragmentation, packet loss and truncated
  captures degrade each of the above?

### Tier 2 — Prior art (decides build vs. reuse vs. duplicate) **[GATE]**

- **Q6 [GATE]** What do Wireshark/tshark, Zeek (`corelight/zeek-spicy-ipsec`,
  `ukncsc/zeek-plugin-ikev2`), Suricata, ike-scan, strongSwan/Libreswan telemetry, and commercial
  NDR/VPN-posture products *already* do? Precisely which of the PS's 5 capability groups (A–E)
  are already solved by mature open source?
- **Q7 [GATE]** If Zeek already parses IKE and ESP, is our contribution the parser (no) or the
  layer above it (probably)? What is the *smallest true novelty* claim we can defend?
- **Q8** Licensing: can each candidate component be used and redistributed in an SIH deliverable?

### Tier 3 — AI necessity (decides whether "AI-driven" is honest) **[GATE]**

- **Q9 [GATE]** For each PS capability, is the best technique deterministic parsing, a rule engine,
  a statistical test, classical ML, deep learning, or an LLM? Where does ML add *measurable* value
  over a deterministic baseline?
- **Q10** What is the credible published evidence for encrypted-traffic classification, after
  discounting for the dataset and evaluation failures documented in the 2025 SoK
  (arXiv:2503.20093) and shortcut-learning literature?
- **Q11** Tunnel mode aggregates many inner flows onto **one** ESP SA. Nearly all published VPN
  traffic-classification results assume one flow per tunnel. Does any credible work address the
  *mixture* case? If not, is that our research gap — or our trap?
- **Q12** What calibration/uncertainty method lets the system say "I don't know" credibly?
  (Conformal prediction, reject option, temperature scaling, evidential DL — compare.)

### Tier 4 — Data (decides whether we can validate anything)

- **Q13** Do any public datasets contain **IPsec/ESP/IKE** traffic with configuration labels?
  (Working hypothesis: no — ISCXVPN2016 is OpenVPN/UDP; VNAT is not IPsec-configuration-labelled.)
- **Q14** If we must generate our own: what is the minimum test matrix that covers the PS's
  configuration axes without a meaningless combinatorial explosion? (Design-of-Experiments:
  covering arrays / fractional factorial, not full cross-product.)
- **Q15** How do we guarantee label correctness, and how do we prevent leakage (same host, same
  session, same capture window appearing in both train and test)?
- **Q16** What generalization splits actually test the claim? (Leave-one-configuration-out,
  leave-one-implementation-out, leave-one-network-condition-out.)

### Tier 5 — Stakeholders, deployment, ethics

- **Q17** What is the real analyst workflow today for assessing an IPsec deployment? Who does it —
  SOC, network engineering, audit, or red team? (Suspicion: the PS's implied workflow is a
  *pentest/audit* workflow, not a SOC workflow, and they have different needs.)
- **Q18** Where would this actually be deployed — offline forensic PCAP review, a tap/SPAN on a
  gateway, or as an audit tool run against one's own estate? Each implies a different product.
- **Q19** What are the false-positive and false-negative *consequences* per finding type?
  (A wrong "PFS disabled" verdict causes an unnecessary change window; a wrong "PFS enabled"
  verdict leaves a real weakness hidden. These are not symmetric.)
- **Q20** Legal/ethical envelope: passive analysis of *own* infrastructure vs. third-party traffic;
  inner-traffic inference is a surveillance capability and must be scoped and justified.

### Tier 6 — Competition reality

- **Q21** What can a small team actually build and *validate* in the available time, and what is
  the minimum that produces a falsifiable, jury-legible proof?
- **Q22** What will competing teams almost certainly build (a Wireshark-summarizing dashboard with
  a CNN), and what is the cheapest way to be visibly better than that?

---

## 0.4 The most important unknowns (ranked)

| # | Unknown | Why it dominates | Resolution method |
|---|---|---|---|
| U1 | Whether the ESP cipher suite / mode / PFS are recoverable from realistic passive capture | If not, most of PS section C collapses into "inference with uncertainty" and the whole product framing changes | Spec analysis (RFC 7296/4303/2409) + testbed experiment |
| U2 | Whether inner-traffic classification survives *tunnel-mode multiplexing* | Published SOTA does not cover it; PS assumes it works | Literature + our own controlled experiment |
| U3 | Whether ML beats a well-built deterministic/statistical baseline on any capability | Determines whether "AI-driven" is honest or decorative | Ablation experiment with a strong non-ML baseline |
| U4 | How much Zeek's existing IPsec analyzers already deliver | Determines novelty and build size | Install and run against our own captures |
| U5 | Whether a security score can be made defensible rather than invented | Judges will attack an unjustified "87/100" | Standards mapping + published scoring methodology review (CVSS-style rationale) |
| U6 | Real analyst workflow and access model | Determines the product shape (forensic tool vs. monitor vs. auditor) | Practitioner interviews if reachable; else documented proxies + labelled assumption |

---

## 0.5 Methodology: comparison and recommendation

### Candidates assessed

| Methodology | Strength for this problem | Weakness for this problem | Verdict |
|---|---|---|---|
| **Double Diamond** | Excellent governance frame; forces divergence before convergence; jury-legible | Assumes the hard part is *understanding people*. Here the hard part is *what physics and cryptography permit*. Has no mechanism for feasibility gating | **Adopt as outer frame only** |
| **Design Thinking / HCD** | Right for dashboard, report design, uncertainty communication | Cannot answer "is this information present in the packet" | **Adopt, scoped to Phase DELIVER surfaces** |
| **Scientific method / hypothesis-driven** | Directly fits: testbed = apparatus, config = independent variable, analyzer output = measurement | Doesn't organise stakeholder/product questions | **Adopt as the engine of DEVELOP + VALIDATE** |
| **Measurement-study methodology** (networking/IMC tradition) | Purpose-built for "what can be observed on a network, and how do we prove it" — ground truth, ablation, reproducibility, negative results | Not a product-design process | **Adopt — this is the missing piece a generic Double Diamond lacks** |
| **Threat modeling (STRIDE / attack trees)** | Needed to make the security engine principled rather than a checklist; also models the *adversary who wants to fool our analyzer* | Not a discovery process | **Adopt for the security engine + red team** |
| **Design of Experiments (fractional factorial / covering arrays)** | Directly solves the PS's combinatorial-explosion trap (the PS lists ~8 config axes) | Narrow | **Adopt for testbed matrix design** |
| **Systems thinking** | Useful for stakeholder/causal mapping in Discover | Can become abstract diagramming with no decisions | Adopt lightly, for root-cause work only |
| **Lean startup / MVP** | Useful pacing discipline | "Ship and learn from users" is unavailable — we have no users in the loop | Reject as primary; keep the iteration cadence |
| **Research-through-design** | Legitimises the testbed as a knowledge-producing artifact | Weak on validation rigor | Subsumed by measurement-study methodology |

### Recommended combination

```
        OUTER FRAME:  Double Diamond  (Discover → Define → Develop → Deliver)
                              │
   ┌──────────────────────────┼──────────────────────────┐
   │                          │                          │
 DISCOVER                  DEVELOP                    DELIVER
 driven by                 driven by                  driven by
 MEASUREMENT-STUDY         HYPOTHESIS-DRIVEN          HCD (analyst surfaces)
 METHODOLOGY               EXPERIMENTATION            + THREAT MODELING
 + SPEC ANALYSIS           + DoE (covering arrays)      (security engine)
 + THREAT MODELING         + RED TEAM
                              │
              CROSS-CUTTING: Evidence & confidence discipline
              (every claim tagged: Fact / Strong / Inference / Hypothesis / Unknown / Needs-experiment)
```

**One added, non-negotiable gate that stock Double Diamond does not have:**

> **The Observability Gate.** No capability may enter the requirement set until it has been
> classified on the Observability Matrix as *Observable*, *Indirectly measurable*,
> *Inferable-with-uncertainty*, or *Not recoverable*. Requirements landing in the last category
> are either re-scoped (by adding a legitimate extra input) or explicitly declined in writing.

This single gate is the difference between a defensible submission and one that gets destroyed in
five minutes of jury questioning.

**Why not just Double Diamond:** the first diamond in Double Diamond diverges on *problem space*.
Our binding constraint is not problem understanding — it is that some of the PS's stated outputs
may be physically unavailable. That is a feasibility constraint, and it must gate the funnel, not
be discovered late in Develop.

---

## 0.6 Source strategy

Tier hierarchy (higher tier wins on conflict; conflicts are logged, never hidden):

1. **IETF RFCs / IANA registries** — protocol truth. RFC 7296 (IKEv2), 4301/4302/4303 (arch/AH/ESP),
   2407–2409 (IKEv1, now Historic), 8221, 8247, 9395, 9370, 8784, 3948 (UDP encap), 7383 (frag).
2. **NIST / CISA / NSA-CNSA / government guidance** — normative security posture. SP 800-77r1,
   SP 800-131A, CNSA 2.0.
3. **Peer-reviewed academic research** — for ML claims. Prefer SoK/replication papers over
   accuracy-record papers.
4. **Official project documentation & source** — Wireshark, Zeek, strongSwan, Suricata, ike-scan.
5. **Reputable vendor technical docs** — Cisco/Palo Alto/F5 operational behaviour.
6. **Community/blogs** — discovery leads only; never sole evidence for a technical claim.

**Rules:**
- Never cite an ML accuracy number without checking the dataset it was measured on against the
  known-flawed list (ISCXVPN2016 etc.).
- Never assume an RFC is current; check `datatracker` status and "Updated by / Obsoleted by".
- Every claim in a Discover/Define document carries a confidence tag.
- Where sources disagree, record both in `registers/RESEARCH-LOG.md` with the adjudication.

---

## 0.7 Investigation sequence

| Step | Output | Gate |
|---|---|---|
| D1 | Protocol fact base + **Observability Matrix** (Q1–Q5) | **GATE-1** |
| D2 | Prior-art teardown; Zeek/Wireshark/Suricata run against our own captures (Q6–Q8) | **GATE-2** |
| D3 | Stakeholder & workflow research (Q17–Q20) | |
| D4 | ML/encrypted-traffic-classification evidence review, discounted for known flaws (Q9–Q12) | |
| D5 | Dataset landscape + generation feasibility (Q13–Q16) | |
| D6 | Research-gap statement — what is genuinely unsolved | **GATE-3** |
| F1 | Root-cause analysis, refined problem statement, requirements, AI-necessity matrix | **GATE-4** |
| V1 | ≥5 distinct concepts, weighted matrix, red team, selection | **GATE-5** |
| L1 | Architecture, testbed, dataset, pipelines, validation plan, roadmap | |

**Gate rule:** a gate is passed only when its open questions are either answered *with evidence* or
formally moved to the Open Questions register with an owner and a resolution method. Gates are not
passed by running out of patience.

---

## 0.8 Expected outputs of the Discover phase

1. `01-DISCOVER-domain.md` — protocol fact base + **Observability Matrix** (started)
2. `02-DISCOVER-prior-art.md` — tool-by-tool teardown, reuse/extend/duplicate verdicts
3. `03-DISCOVER-stakeholders.md` — actors, workflows, jobs-to-be-done, FP/FN consequences
4. `04-DISCOVER-ml-evidence.md` — what encrypted-traffic ML can and cannot credibly do
5. `05-DISCOVER-datasets.md` — dataset landscape and generation feasibility
6. `06-DISCOVER-gaps.md` — the defensible research gap
7. Living registers: research log, assumptions, open questions, decisions, risks

## 0.9 Declared areas of uncertainty at plan time

- Whether we can reach real practitioners for Q17–Q19. If not, stakeholder findings will be
  explicitly downgraded to *Reasonable inference from documented workflows* and labelled as such.
- Whether the SIH evaluation rubric rewards honest negative results ("not recoverable") or
  penalises them. Mitigation: never *only* report a limitation — always pair it with the
  legitimate alternative input that resolves it.
- The exact time budget and team skill distribution are currently unknown (see OQ register).
