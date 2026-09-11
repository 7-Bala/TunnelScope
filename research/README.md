# SIH26160 — Research Repository

**Problem statement:** AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
(NTRO). **Phase:** Discover + Define complete. **RESEARCH FROZEN — active work moved to
`registers/EXPERIMENT-REGISTER.md`.** **Last updated:** 2026-09-09.

> ⚠️ **No architecture, technology stack, or ML model has been selected.** Concept generation is
> Phase 3 (DEVELOP) and must produce ≥5 genuinely distinct concepts evaluated on a weighted matrix.
> Everything below is evidence and analysis, not design.

## Reading order

| # | Document | What it settles |
|---|---|---|
| 0 | [00-RESEARCH-PLAN.md](00-RESEARCH-PLAN.md) | Problem classification, 22 research questions, methodology comparison, gated sequence |
| 1 | [01-DISCOVER-domain.md](01-DISCOVER-domain.md) | Protocol fact base, **vantage taxonomy V0–V5**, **Observability Matrix**, requirement challenges |
| 2 | [02-DISCOVER-prior-art.md](02-DISCOVER-prior-art.md) | Tool-by-tool teardown, practitioner pain evidence, licensing, gap list |
| 3 | [03-DISCOVER-stakeholders.md](03-DISCOVER-stakeholders.md) | Four roles, workflows, JTBD, FP/FN asymmetry, ethics envelope |
| 4 | [04-DISCOVER-ml-evidence.md](04-DISCOVER-ml-evidence.md) | The ETC credibility crisis; what ML can and cannot do; **the measurement reframing** |
| 5 | [05-DISCOVER-datasets.md](05-DISCOVER-datasets.md) | Dataset landscape, generation methodology, leakage controls, combinatorics |
| 6 | [06-DISCOVER-gaps-and-posture.md](06-DISCOVER-gaps-and-posture.md) | **The posture decision (DEC-005)**, validated gaps, contradictions, DEFINE readiness |
| 7 | [07-DISCOVER-pq-and-late-findings.md](07-DISCOVER-pq-and-late-findings.md) | Post-quantum observability gap; **PQ-6 length-only KEM detector**; the unifying thesis |
| 8 | [08-DISCOVER-convergent-prior-art.md](08-DISCOVER-convergent-prior-art.md) | **Two self-corrections**; the TLS framework that independently validates our architecture |
| — | [SOURCES.md](SOURCES.md) | Tiered source register |
| — | [registers/](registers) | Research log · Assumptions · Open questions · Decisions · Risks |

## The five things to know

1. **The ESP cipher suite, mode, PFS and identities are inside the *encrypted* part of IKE**
   (RFC 7296). Most of PS §C cannot be *read* passively — only constrained or inferred.
   Corroborated independently by multi-vendor practitioner guidance.
2. **AES-128 vs AES-256 is information-theoretically unrecoverable from ESP.** No AI changes this.
3. **The encrypted-traffic-classification literature is in a documented credibility crisis** —
   ET-BERT drops 98% → 10.9% under honest evaluation; Random Forest on protocol features beats
   pretrained transformers. Pretrained traffic transformers are rejected (DEC-006).
4. **The gap is real but not where the PS says it is.** It is in interpretation, evidence
   discipline, temporal measurement and exposure quantification — not identification-from-ciphertext.
5. **strongSwan negotiates hybrid ML-KEM IPsec today. Wireshark's master branch now parses it
   (issue #21072 fixed 2026-03-14), but the tools SOCs run — Suricata, Zeek, nDPI, Arkime — do not,
   and nothing *assesses* PQ posture or downgrade.** India's DST Task Force mandates crypto inventory
   and downgrade prevention for CII by 2027. *(Corrected 2026-09-11 — see doc 11.)*

## Decisions on the record

DEC-001 methodology · DEC-002 Observability Gate · DEC-003 vantage taxonomy ·
DEC-004 covering arrays over cross-product · **DEC-005 passive-first, evidence-tiered posture** ·
DEC-006 reject pretrained traffic transformers · DEC-007 name the authority behind every verdict ·
DEC-008 UNKNOWN/NOT-OBSERVABLE first-class · DEC-009 dataset split rules ·
DEC-010 CONTRADICTORY first-class · DEC-011 rules-as-versioned-data · DEC-012 novelty claim scoping

## Define + Exit Review (added 2026-09-09, continued session)

| # | Document | What it settles |
|---|---|---|
| 9 | [09-DEFINE.md](09-DEFINE.md) | Refined problem statement, requirement dispositions, **AI Necessity Matrix**, non-accuracy success metrics, rejected scope |
| 10 | [10-RESEARCH-EXIT-REVIEW.md](10-RESEARCH-EXIT-REVIEW.md) | **Honest exit review; STATUS: RESEARCH FREEZE — MOVE TO EXPERIMENTATION** |
| — | [registers/EXPERIMENT-REGISTER.md](registers/EXPERIMENT-REGISTER.md) | 8 sequenced experiments with hypotheses, ground truth, falsification criteria — replaces further literature search |

**Current phase: broad Discover research frozen. Active work = EXPERIMENT-REGISTER, run against the
testbed. DEVELOP (≥5 concepts) may proceed in parallel but no concept may be selected before EXP-02
(the leakage/contamination gate) has run once on real data.**

## Existing-solutions deep dive (added 2026-09-11)

| # | Document | What it settles |
|---|---|---|
| 11 | [11-EXISTING-SOLUTIONS-DEEP-DIVE.md](11-EXISTING-SOLUTIONS-DEEP-DIVE.md) | Per-solution mechanism / build / maintenance / PS coverage for 20+ tools, products and competing SIH projects. **Withdraws "Wireshark can't decode PQ IKE"** (fixed 2026-03-14); CS-05 restated as PQ *assessment + downgrade detection* (DEC-017) |
| — | [data/solutions-maintenance-2026-09-11.json](data/solutions-maintenance-2026-09-11.json) | Live GitHub maintenance metrics behind §4 |
