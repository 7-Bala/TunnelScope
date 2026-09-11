# 12 — DEVELOP: Alternative Concepts, Decision Matrix, Red Team, Selection

**Status:** GATE-5. **Nothing in the build roadmap (T-030+) starts until this document's selection
is on the record.** · **Date:** 2026-09-12

**Inputs this decision is bound to:** Discover (docs 01–08), Define (09, updated by T-014), the
existing-solutions deep dive (11), and the experiment results:
EXP-01 (sieve — narrowed), EXP-02 (integrity gate — pass), EXP-03 (PFS — confirmed),
EXP-04 (PQ — confirmed, reconfirmed on 6.1.0), EXP-05 (leakage), EXP-06 round 2 (failure diagnosis),
EXP-07 (Libreswan generalisation). Each score below cites the evidence it rests on.

---

## 1. The concepts

Eight genuinely different answers to the PS — including the ones competing teams are building, so
that the selection is made *against* them, not in ignorance of them.

| ID | Concept | Core idea | What it is *not* |
|---|---|---|---|
| **C1** | **ML traffic classifier + dashboard** | pcap → flow features → classifier predicts traffic type, cipher, mode; dashboard shows predictions and a score | What the observed PS-26160 competitor built (doc 11 §3.F) |
| **C2** | **Deterministic protocol auditor** | Parse plaintext IKE/ESP (reusing tshark), check against rules, emit a report. No ML, no time dimension | Not a monitor; not a measurement tool |
| **C3** | **Evidence-tiered posture engine** | Per-SA evidence record; every attribute placed at T0–T4 with an explicit verdict (PASS/FAIL/UNKNOWN/NOT-OBSERVABLE/CONTRADICTORY) against named baselines; structural signals (PFS, PQ, sieve, lifecycle) are first-class | Not a classifier product |
| **C4** | **Active IKEv2/PQ posture scanner** | Authorised probing of gateways: enumerate accepted proposals incl. ADDKE, test downgrade acceptance — "ike-scan for the IKEv2/PQ era" (fills G-07) | Not passive; needs authorisation per target |
| **C5** | **Endpoint-telemetry auditor** | Collect `swanctl`/vici / Libreswan / vendor configs (T2) and cross-check them against observed traffic (T0/T1) | Needs endpoint access; blind without it |
| **C6** | **PQ-migration assurance monitor** | Fleet-wide passive monitor focused on PQ adoption, offered-vs-selected downgrade, CBOM export (DST/NQM alignment) | Narrow: PQ only |
| **C7** | **LLM analyst copilot** | Feed Wireshark/Zeek output to an LLM that explains the capture in prose | Not a source of facts (DL-03) |
| **C8** | **Metadata-leakage auditor** | Measure what a passive observer learns (classifier as instrument, BER/MI), recommend padding | Not an identification tool (CS-01) |

*(Composite options are evaluated in §4 after the individual scoring, not smuggled in as a 9th row.)*

---

## 2. Criteria and weights — fixed BEFORE scoring

> **Written 2026-09-12, before any concept was scored**, and not edited after. This is the guard
> against tuning the matrix to fit a preferred answer. §5 tests how sensitive the winner is to the
> weights instead of arguing for these particular ones.

Scale: each concept gets 1–5 on each criterion, and every score cites its evidence. Weights sum to 100.

| # | Criterion | Weight | Why this weight |
|---|---|---:|---|
| W1 | **Problem fit** — coverage of PS sections A–E under 09-DEFINE's dispositions | 12 | It has to answer the PS the jury wrote |
| W2 | **Evidence strength** — how much of the concept is experimentally validated (EXP-01…07) | 12 | The project's whole method; the thing competitors lack (doc 11 §3.F) |
| W3 | **Gap fit / innovation** — does it fill a verified gap (doc 11 §6), or duplicate an existing tool? | 10 | Novelty that survives "doesn't Wireshark/Suricata already do this?" |
| W4 | **Technical feasibility** in our testbed and time | 9 | A concept that can't be built doesn't win |
| W5 | **Impact** — the jobs-to-be-done it serves (doc 03 J1–J7), and national-policy alignment (DST/NQM) | 9 | Why anyone would use it |
| W6 | **AI justification** — AI used where it measurably beats a non-AI baseline, and nowhere else | 7 | The PS title says "AI-driven"; only *honest* AI earns this |
| W7 | **Explainability** — every output traceable to evidence and a named standard | 7 | DL-03, DEC-007/008; analyst trust |
| W8 | **Safety of the tool itself** — false-assurance risk, active-probing risk, privacy | 6 | An assessment tool that invents a PASS is worse than none (DEC-008) |
| W9 | **Deployment feasibility** — offline/air-gapped, no cloud, NTRO-realistic | 6 | Government deployment context |
| W10 | **Demonstration value** — a live, falsifiable proof in front of a jury | 6 | SIH is judged live |
| W11 | **Dataset feasibility** — can we generate the ground truth it needs? | 5 | No public IPsec dataset exists (doc 05) |
| W12 | **Development complexity** (inverse: 5 = simplest) | 4 | Matters, but less than whether it's right |
| W13 | **Scalability** — fleet-scale use | 3 | Real but secondary for a prototype |
| W14 | **Maintainability / extensibility** | 2 | Rules-as-data (DEC-011) etc. |
| W15 | **Cost** — licences, hardware, cloud | 2 | Open-source stack assumed |
| | **Total** | **100** | |

---

## 3. Scores

Every cell (a 1–5 score plus the evidence behind it) is in
[`data/develop_scores.json`](data/develop_scores.json); the arithmetic is
[`data/develop_matrix.py`](data/develop_matrix.py) (re-runnable), and its output is
[`data/develop_results.json`](data/develop_results.json). Totals are on a 0–100 scale (Σ weight × score / 5).

| Rank | Concept | Total | Where it wins | Where it loses |
|---:|---|---:|---|---|
| 1 | **K1 = C3 + C6 + C8 (+ C5 optional)** *(composite, §4)* | **91.6** | Problem fit, evidence, impact, demo, honest AI | Largest scope (W4, W12) |
| 2 | **C3** Evidence-tiered posture engine | 86.4 | Evidence, gap fit, explainability, safety | Little AI; metadata only via modules |
| 3 | **C6** PQ-migration assurance monitor | 83.0 | Evidence (EXP-04 ×2 versions, EXP-07), DST/NQM impact, demo, feasibility | Narrow problem fit; novelty reduced now that Wireshark master parses ML-KEM |
| 4 | **C8** Metadata-leakage auditor | 77.8 | Gap fit (nobody does it), the only justified ML (EXP-05) | Synthetic-traffic caveat; privacy sensitivity |
| 5 | **C2** Deterministic auditor | 74.4 | Feasibility, explainability | Overlaps Suricata/Zeek; no time dimension; no AI |
| 6 | **C5** Endpoint-telemetry auditor | 71.4 | Authoritative; the IP-TFS contradiction shows its value | Needs endpoint access |
| 7 | **K2 = C1 + C3** *(composite)* | 69.8 | Covers A–E on paper | Adds confident-wrong labels (EXP-05) and ML where evidence says no |
| 8 | **C4** Active IKEv2/PQ scanner | 57.0 | Real gap (G-07) | Not experimentally validated; probing risk; PS is about captured traffic |
| 9 | **C1** ML classifier + dashboard | 46.2 | Easy to build | Evidence, safety, AI justification, gap fit |
| 10 | **C7** LLM copilot | 43.8 | Easy to prototype | Hallucinated verdicts = false assurance |

## 4. Composites — evaluated after the individual scoring

Two composites, both scored on the same fixed criteria:
- **K1 = C3 + C6 + C8, with C5 optional** — the posture engine as the core, with PQ posture +
  downgrade, and leakage measurement, as modules on top; endpoint cross-check when access exists.
- **K2 = C1 + C3** — the "AI-heavy" option: bolt a traffic-type classifier onto the engine.

**K2 scores below C3 alone (69.8 vs 86.4).** Adding the capability the PS literally asks for (a
predicted traffic type) *lowers* the score. It costs evidence, safety and AI-justification points,
because EXP-05 showed mixtures produce confident wrong labels. This is the cleanest single answer to
"why didn't you just build the classifier?"

## 5. Sensitivity — is the winner an artefact of the weights?

Tested: committed weights, equal weights, five deliberately skewed weightings (AI ×3, demo ×3,
feasibility ×3, evidence ×0.25, problem-fit ×3), and dropping each criterion in turn — 23 scenarios.

- **K1 wins 22 of 23.** Its margin over the runner-up ranges from +1.6 (dropping W1) to +9.5 (AI ×3).
- **The single flip:** with **feasibility weighted ×3** (W4, W12), **C6 alone wins** (86.5 vs C3 83.8).
  That is a genuine signal, not noise: **if time is the binding constraint, the PQ monitor on its own
  is the strongest single deliverable.** It shapes the build order in §7.
- **Weighting AI ×3 makes K1's lead *larger* (+9.5)**, not smaller, because K1 is the only
  candidate whose AI use is both present and experimentally justified. The AI-heavy alternatives (C1,
  K2, C7) score *worse* when AI justification is weighted up, since their AI isn't justified.

## 6. Red team — attacking the selection before committing to it

| Attack | Strength | Response |
|---|---|---|
| **"You scored your own concepts."** Self-scoring bias is real. | High | Mitigated three ways, not eliminated: weights committed in git before any scoring (`6425af2`); every score cites evidence in a file anyone can re-score; the 23-scenario sensitivity shows the result doesn't hinge on the exact weights. **Recommend a teammate or mentor re-score `develop_scores.json` independently** — a disagreement would be informative. |
| **"Composites always win — they cover more."** | Medium | True in general, which is why composites were scored after the individual concepts. But K2 shows it doesn't hold automatically: a composite that adds the wrong component scores lower. K1 beats C3 through W1/W5/W6/W10 and loses on W4/W12. |
| **"Too much to build in SIH time."** | **High** — the feasibility flip says exactly this | Staged build (§7): the MVP is **C3 core + C6**, both deterministic and the most validated; C8 is stage 2; C5 is optional. If time runs out after stage 1, C6 alone is still the best single deliverable. |
| **"The PS says AI-driven — one ML component is too little."** | Medium | AI appears where it measurably beats the simple baseline (C8: F1 0.995 vs 0.51) and nowhere it doesn't. Three components the Define phase *expected* to need ML (PFS, failure diagnosis, fingerprinting) were tested and shown not to. That is a stronger AI story in front of a technical jury than decorative ML — and the observed competitor's ML is trained on hand-typed Gaussians. |
| **"Your leakage numbers are from synthetic traffic."** | High, for absolute numbers | Conceded in EXP-05's RESULT. The product reports per-tunnel measured leakage on the operator's *own* traffic, so it inherits no synthetic number. What the synthetic experiment established is the method and the controlled contrast (padding vs none). |
| **"PQ novelty is gone — Wireshark master parses ML-KEM now."** | Medium | Correct for *dissection* (DEC-017). K1's PQ value is *assessment*: offered-vs-selected downgrade, DST/NQM mapping, fleet scale, and working in the tools SOCs actually run (Suricata/Zeek/nDPI can't parse ADDKE). EXP-07 also showed that a naïve notify-based detector would be wrong on Libreswan. |
| **"Only two implementations tested."** | Medium | Stated as the scope of every claim. Vendor stacks (Cisco, Palo Alto, Fortinet) are untested; the evidence model marks implementation-dependent signals as such (DEC-020). |
| **"Mode inference is still untested."** | Low–medium | Correct, and marked UNTESTED in 09-DEFINE. It must not ship as a claim before it is tested; until then, mode is reported from T2 or as NOT-OBSERVABLE. |
| **"Passive analysis can't assess anti-replay enforcement (DISA V-207212)."** | Known | That is exactly what the tier model is for: NOT-OBSERVABLE at T0/T1, answered at T2 (C5) — never a false PASS. |

## 7. Selection

> **Selected: K1 — TunnelScope as an evidence-tiered IPsec posture engine (C3), with a PQ-migration
> and downgrade assessor (C6) and a metadata-leakage measurement module (C8); endpoint-telemetry
> cross-checking (C5) where access exists.**

**Build order** (driven by the §5 feasibility flip and the red team's scope attack):
1. **Stage 1 — MVP, deterministic core:** C3 evidence records + assessment engine with named
   baselines, and C6 PQ posture/downgrade. Everything in it is experimentally validated
   (EXP-01/02/03/04/06/07). If the project stopped here, it would already be defensible.
2. **Stage 2:** C8 leakage measurement — the one justified ML component (EXP-05).
3. **Stage 3 (optional):** C5 endpoint cross-check (T2), producing CONTRADICTORY findings such as
   the IP-TFS black-hole in `testbed/NOTES.md` #13.

**Rejected, with reasons:**
- **C1 (ML classifier)** — fails on evidence, safety and AI justification; it's what the observed
  competitor built.
- **C7 (LLM copilot)** — hallucinated verdicts are false assurance. An LLM appears *only* inside K1
  for templated report prose generated from the evidence record, never as a source of facts.
- **K2** — adding identification lowers the score (§4).
- **C4 (active scanner)** — deferred, not rejected: the gap is real (G-07), but it's unvalidated, it
  carries authorisation and probing risk, and the PS is about captured traffic. A future-work item.
- **C2** — subsumed by C3.

## 8. What would change this decision

- An independent re-score that ranks C3 or C6 above K1 in the committed-weights scenario.
- The SIH deadline turning out to be short enough that even Stage 1 is at risk → **C6 alone**.
- A vendor stack contradicting a "protocol fact" signal (sieve, PFS gap, IKE_INTERMEDIATE presence).
- Real-traffic data showing the leakage metric unstable (EXP-05's P5-5 failing outside the lab) → drop C8.
