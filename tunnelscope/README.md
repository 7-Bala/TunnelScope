# TunnelScope

**Evidence-tiered IPsec/IKE posture and post-quantum migration assessment.**
SIH26160 (NTRO). Selected design: `research/12-DEVELOP.md` (DEC-023).

TunnelScope reads an IPsec packet capture and produces a security assessment in which **every
finding declares what it is (observed / inferred / measured / unknown / not-observable /
contradictory), from which vantage point, and with which evidence**, and **every compliance verdict
names the standard it is judged against**. It reports what a capture actually supports and never
scores absence of evidence as compliance.

## What it does

| Capability | Method | Validated by |
|---|---|---|
| IKE version, exchanges, IKE-SA crypto suite | plaintext IKE parse (T1) | reuse |
| ESP cipher family | one-directional CBC-vs-AEAD sieve | EXP-01 |
| **Post-quantum key exchange + downgrade** | ADDKE transform + IKE_INTERMEDIATE presence | EXP-04, EXP-07 |
| PFS | CREATE_CHILD_SA rekey length gap | EXP-03 |
| Negotiation-failure diagnosis | structural signatures | EXP-06 |
| Tunnel/transport mode | **reports NOT-OBSERVABLE at T0** (honest) | EXP-08 |
| Metadata leakage | size/timing entropy in bits (never a traffic label) | EXP-05 |
| CVE-2026-78135 pattern | vantage-aware early-Child-SA detector (0 FP/69, sensitivity 1/1) | EXP-09 |
| Cross-tier consistency (T2 vs wire) | reconcile endpoint telemetry → escalate / confirm / **CONTRADICTORY** | Stage 3, `build/02-CROSSTIER.md` |
| Multi-baseline compliance | rules as versioned data | RFC 8221/8247/9395, NIST SP 800-77r1, DISA VPN SRG, DST/NQM |
| CBOM export | CycloneDX 1.6 | DST/NQM |

## Install

```bash
pip install -e .        # needs Python 3.11+, and tshark on PATH (ADR-001)
```

## Use

```bash
tunnelscope analyze  capture.pcap          # evidence records (what was seen, from where)
tunnelscope assess   capture.pcap          # verdicts vs named baselines
tunnelscope cbom     capture.pcap          # CycloneDX CBOM (JSON)
tunnelscope report   capture.pcap          # executive + technical report
tunnelscope dashboard capture.pcap -o d.html  # self-contained offline HTML
tunnelscope crosstier capture.pcap t2.json    # reconcile T2 endpoint telemetry (Stage 3)
tunnelscope fleet captures/ -o fleet.html     # scan a directory: one view, per-tunnel evidence kept
tunnelscope analyze  capture.pcap --json   # machine-readable
```

## Design in one paragraph

A capture goes to **ingest** (tshark, reused not rebuilt), which feeds deterministic **extractors**
that build one **EvidenceRecord** per Security Association. Every fact is a `Finding` whose `status`
is structurally mandatory — there is no code path that yields a bare value, so "we didn't see it" and
"it isn't there" stay distinct. The **assessment engine** evaluates versioned YAML baselines against
the records; a finding that is UNKNOWN/NOT-OBSERVABLE yields an UNKNOWN/NOT-OBSERVABLE verdict, never
PASS/FAIL. **Scoring** is per-baseline and coverage-aware. **Reports** and the **CBOM** are generated
from the evidence graph only. Full architecture and ADRs: `build/00-ARCHITECTURE.md`.

## The one ML component

Only metadata-leakage measurement uses ML, and it is used as a **measuring instrument** (bits of
exposure), never as a traffic-type oracle (DEC-021). Every other capability is deterministic —
several that the design phase expected to need ML were tested and shown not to (PFS, failure
diagnosis, fingerprinting, mode).

## Trust and limits

- **Vantage tiers** T0 (passive ESP) → T1 (+IKE) → T2 (endpoint) → T3 (keys) → T4 (active). The tool
  is fully useful at T0/T1 and marks what only higher tiers can answer.
- Validated on strongSwan 5.9.8/6.1.0 and Libreswan 5.4. Vendor stacks (Cisco/Palo Alto/Fortinet)
  are untested. Mode inference and receiver-side replay enforcement are NOT-OBSERVABLE passively.
- End-to-end validation: `python3 build/validate_e2e.py` (69/69 captures match ground truth).

## Tests

```bash
python3 -m pytest tests/ -q        # unit + ground-truth tests
python3 dataset/validate.py        # dataset integrity (hashes, provenance, splits)
python3 build/validate_e2e.py      # end-to-end vs ground truth
```
