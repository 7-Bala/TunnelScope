# TunnelScope — System Architecture (T-030)

**Date:** 2026-09-12 · **Phase:** BUILD (first act) · **Selected design:** K1 (DEC-023) — evidence-tiered
IPsec posture engine + PQ/downgrade assessor + metadata-leakage module, endpoint cross-check optional.

This document is implementation-ready: it names components, the data that flows between them, the
technology for each, and traces every component to a requirement in `research/09-DEFINE.md`. Design
decisions are recorded as ADRs in §7. Nothing here re-opens the DEVELOP selection.

---

## 1. The one-sentence shape

> A pcap (or live tap, or endpoint export) goes in; a set of **per-SA evidence records** is built by
> deterministic extractors that reuse mature parsers; a **rule engine** turns those records into
> **verdicts that each cite their evidence and a named standard**; a single **ML instrument** measures
> metadata leakage; and two **reports** plus a **score** come out — with `UNKNOWN`, `NOT-OBSERVABLE`
> and `CONTRADICTORY` as first-class answers, never guesses.

## 2. Design invariants (from the research — violate none of these)

| # | Invariant | Source |
|---|---|---|
| I1 | **Deterministic-first.** Exactly one ML component (leakage). Everything else is rules over structure. | EXP-01/03/04/06/07/08; DEC-018/019/024 |
| I2 | **Every finding carries its vantage tier (T0–T4), its evidence pointer (packet+field), and its confidence.** | DEC-003 |
| I3 | **Every verdict names the authority it is judged against.** No unqualified "compliant". | DEC-007 |
| I4 | **`UNKNOWN` / `NOT-OBSERVABLE` / `CONTRADICTORY` are first-class outputs.** Absence of evidence never renders as PASS. | DEC-008/010 |
| I5 | **Rules and baselines are versioned DATA, not code.** | DEC-011 |
| I6 | **Reuse parsers (tshark); never rebuild them.** Our value is above the parser. | doc 11 |
| I7 | **Ground truth is causal (config + T2), never the analyzer's own inference.** | DEC-009, dataset datasheet |
| I8 | **The LLM (if used) generates prose from the evidence graph only — never facts.** | DL-03 |
| I9 | **Offline / air-gapped by default.** No cloud dependency in the core path. | NTRO deployment context |

## 3. Component architecture

```
                         ┌─────────────────────────────────────────────────────────┐
  pcap / live tap  ─────▶│ INGEST  (tunnelscope/ingest)                             │
  (T0/T1)                │  tshark -T ek  →  normalized IKE/ESP record stream       │
                         └───────────────┬─────────────────────────────────────────┘
  swanctl/pluto export ─┐                │
  (T2)                  ├───────────────▶│ EVIDENCE  (tunnelscope/evidence)         │
  IKE/ESP keys (T3) ────┘                │  extractors → per-SA EvidenceRecord      │
                         ┌───────────────┤   • ike_meta      (version/mode/notifies)│
                         │               │   • cipher_sieve  (EXP-01)               │
                         │               │   • pfs           (EXP-03)               │
                         │               │   • pq_addke      (EXP-04/07)            │
                         │               │   • failure_diag  (EXP-06)               │
                         │               │   • sa_lifecycle  (rekey/SPI churn)      │
                         │               │   • mode          (EXP-08 → NOT-OBS/T2)  │
                         │               │   • cve_earlychild(EXP-09)               │
                         │               │   • metadata_leak (EXP-05, ML instrument)│
                         │               └───────────────┬──────────────────────────┘
                         │                                │  EvidenceRecord[]  (SQLite + JSON)
                         │                                ▼
                         │               ┌──────────────────────────────────────────┐
                         │               │ ASSESS  (tunnelscope/assess)              │
                         │               │  rule engine over rules/*.yaml            │
                         │               │  baselines: RFC 8221/8247/9395, SP800-77r1,│
                         │               │  DISA VPN SRG, DST/NQM                     │
                         │               │  → Verdict{PASS/FAIL/UNKNOWN/NOT-OBS/CONTRA}│
                         │               └───────┬───────────────┬───────────────────┘
       CROSSTIER ◀───────┘                       │               │
   (T0/T1 vs T2/T3 →                              ▼               ▼
    CONTRADICTORY)                        ┌────────────┐   ┌──────────────┐
                                          │ SCORE      │   │ PQ ASSESSOR  │
                                          │ cited,     │   │ downgrade +  │
                                          │ sensitivity│   │ CBOM export  │
                                          └──────┬─────┘   └──────┬───────┘
                                                 ▼                ▼
                                          ┌──────────────────────────────┐
                                          │ REPORT (exec + technical)     │──▶ Markdown/HTML/JSON
                                          │ API (FastAPI)  ·  CLI          │──▶ later: dashboard
                                          └──────────────────────────────┘
```

## 4. The core data structure — `EvidenceRecord`

One per Security Association (keyed by IKE initiator+responder SPI, plus child SPIs). Every
attribute is a **`Finding`**, not a bare value:

```
Finding = {
  attribute:  "esp_cipher_family" | "pfs" | "pq_key_exchange" | ...
  status:     OBSERVED | MEASURED | INFERRED | UNKNOWN | NOT_OBSERVABLE | CONTRADICTORY
  value:      <the finding, or a candidate set, or null>
  vantage:    T0 | T1 | T2 | T3 | T4
  confidence: 1.0 for deterministic; a calibrated number for the leakage instrument
  evidence:   [ {pcap, frame, field, raw} ... ]   # every claim points at its packets
  method:     "EXP-01 sieve" | "EXP-04 signal-3" | ...   # which validated method produced it
}
```

`status` is the spine of the whole system (I4). A `Finding` with `status=NOT_OBSERVABLE` is a
first-class result the assessor and report must honour — it can never be silently upgraded to a value.

## 5. Requirement traceability (→ `research/09-DEFINE.md`)

| Component | 09-DEFINE requirement(s) | Validated by |
|---|---|---|
| ingest | R2 (capture IKE/ESP/AH) | reuse (I6) |
| evidence/ike_meta | R3 IKE version, R7 auth method (partial) | O at T1 |
| evidence/cipher_sieve | R5 cipher family | EXP-01 (CBC vs AEAD/stream, one-directional) |
| evidence/pfs | R14 PFS | EXP-03 (256-B rekey gap) |
| evidence/pq_addke | R8 key exchange + PQ | EXP-04, EXP-07 |
| evidence/failure_diag | R-new (why a tunnel failed) | EXP-06 r2 (macro-F1 1.000) |
| evidence/sa_lifecycle | R9 SA characteristics, R12 lifetime | F-02 (measured, not read) |
| evidence/mode | R4 tunnel/transport | EXP-08 (NOT-OBSERVABLE at T0; T2/topology) |
| evidence/cve_earlychild | R-new (CVE-2026-78135) | EXP-09 (0 FP, vantage-aware) |
| evidence/metadata_leak | R10/R15 metadata exposure | EXP-05 (the one ML instrument) |
| assess | R11 compliance, R13 replay | rules as data; multi-baseline (I3) |
| pq | R8 PQ + downgrade, PS §E CBOM | EXP-04/07; DST/NQM |
| crosstier | cross-tier consistency | DEC-005 constraint 4; NOTES #13 IP-TFS case |
| score | R16 risk/confidence score | cited construction (T-035) |
| report | PS §E exec + technical | from evidence graph (I8) |

**Explicitly NOT built** (09-DEFINE rejected scope): inner-traffic identity as a fact (R6 AES key
length at T0 declined; R10 reframed to leakage); no pretrained traffic transformer; no unqualified
"compliant"; no unauthorized active probing (T4 stays out of the MVP).

## 6. Technology choices (rationale in ADRs)

| Layer | Choice | Why |
|---|---|---|
| Language | **Python 3.11+** | matches all experiment code; scikit-learn for the one ML component; fast to build |
| Parser | **tshark** (`-T ek`), shelled out | I6; the experiments already depend on it; GPL boundary respected by shelling out |
| Evidence store | **SQLite** + JSON export | offline (I9), zero-config, queryable, reproducible |
| Rules/baselines | **YAML** files under `rules/`, each versioned with its source citation | I5 |
| ML instrument | **scikit-learn** RandomForest + 1-NN Bayes bound | EXP-05, already validated; interpretable |
| API | **FastAPI** (optional, off by default) | lightweight; core works as a CLI without it |
| Reports | **Markdown → HTML** (templated); optional LLM for prose only | I8 |
| Packaging | a `tunnelscope` Python package + `pyproject.toml`; testbed stays separate | clean separation |

## 7. Architecture Decision Records

- **ADR-001 — Reuse tshark for parsing, shelled out (not linked).** Rebuilding an IKE/ESP parser
  duplicates mature, better-tested code (doc 11) and would be our weakest component. Shelling out to
  `tshark -T ek` keeps a clean GPL boundary and gives an independent oracle for free. *Consequence:*
  tshark is a runtime dependency; we pin a minimum version and degrade gracefully on PQ transform
  IDs that older tshark prints numerically (we carry the IANA ID→name table ourselves).
- **ADR-002 — `status` (OBSERVED/…/NOT_OBSERVABLE/CONTRADICTORY) is mandatory on every Finding.**
  The type system enforces it: there is no code path that produces a bare value. This is I4 made
  structural rather than aspirational.
- **ADR-003 — Rules and baselines are data, loaded and versioned, not Python.** A baseline is a YAML
  document citing its authority and clause; adding DISA or DST rules is a data change, not a code
  change. Enables the multi-baseline requirement (I3) and auditability.
- **ADR-004 — One ML component, quarantined in `leakage/`.** It emits bits-of-leakage and a
  Bayes-error bound, never a traffic label (DEC-021). It cannot write a value-typed Finding for any
  other attribute. This keeps the credibility crisis (doc 04) out of the assessment path.
- **ADR-005 — SQLite over a server DB.** Air-gapped NTRO deployment (I9); a single file is the whole
  state; trivial to ship with a capture for reproducibility.
- **ADR-006 — The core is a library + CLI; the API and dashboard are optional shells.** Guarantees
  the tool runs offline in a forensic workflow with no services running.

## 8. Build order (DEC-023, full staged build — no deadline)

1. **Stage 1 (MVP):** ingest → evidence (ike_meta, cipher_sieve, pfs, pq_addke, failure_diag,
   sa_lifecycle, mode, cve_earlychild) → assess (rules + baselines) → score → reports → CLI.
   Everything deterministic and validated. **This is a defensible product on its own.**
2. **Stage 2:** leakage module (the ML instrument) + its report section.
3. **Stage 3 (optional):** crosstier (T2/T3 ingestion + CONTRADICTORY findings); API; dashboard.

## 9. Testing strategy

- Unit tests per extractor, fed the **committed testbed captures** with their causal ground truth
  (`dataset/MANIFEST.csv`) — the extractor's output must match T2.
- The assessment engine is tested against the deliberate-misconfiguration arms (EXP-06) — **zero
  false PASS** is the hard acceptance criterion (09-DEFINE §4).
- The AES-128/256 negative control (EXP-02) is a standing pipeline test: any extractor that claims to
  read key length from ESP fails CI.
- End-to-end: `dataset/validate.py` must pass; every experiment's RESULT reproduces from the tracked
  captures.
