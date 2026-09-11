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
