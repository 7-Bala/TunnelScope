# TunnelScope — End-to-End Validation (T-039)

Ran the full pipeline (ingest → evidence → assess) over **85 captures** and checked every finding against the causal ground truth in `dataset/MANIFEST.csv`.

**Result: 85/85 captures pass; 0 mismatch(es).**

## Coverage by experiment

- EXP-01/02-cipher: 12 captures
- EXP-03-pfs: 2 captures
- EXP-04-pq: 7 captures
- EXP-05-leakage: 1 captures
- EXP-06r2-failure-diagnosis: 35 captures
- EXP-07-libreswan: 10 captures
- EXP-08-mode: 2 captures
- EXP-15-suites-ah: 14 captures
- SYNTHETIC-replay: 2 captures

## Standing anti-overclaim checks (every capture)

- mode is claimed only when it matches ground truth, and tunnel mode only from AH's plaintext next header (EXP-08/14): enforced
- no ESP-side key-length finding ever exists (F-05/EXP-02): enforced

## Mismatches

None. Every finding matches ground truth, and the pipeline never overclaimed a NOT-OBSERVABLE attribute.
