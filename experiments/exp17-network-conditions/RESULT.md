# EXP-17 — Network conditions: delay, jitter and packet loss — RESULT (2026-09-21)

Pre-registration: `PREREG.md`. Numbers: `results/exp17_results.json`.

| # | Prediction | Result | Held or FAILED |
|---|---|---|---|
| P17-1 | Shipped classifier, wan profile, sessions pooled: window-level macro-F1 ≥ 0.70 | macro-F1 0.5257 (syn 0.5453, real 0.5308; bulk 0.0189, email 0.3733, icmp 1.0000, interactive 0.7904, messaging 0.8293, video 0.0000, voip 0.6936, web 0.5000) | FAILED |
| P17-2 | Shipped classifier, lossy profile, sessions pooled: window-level macro-F1 ≥ 0.50 | macro-F1 0.3802 (syn 0.4235, real 0.3440; bulk 0.0000, email 0.1071, icmp 0.9524, interactive 0.5038, messaging 0.6267, video 0.0000, voip 0.5556, web 0.2963) | FAILED |
| P17-3 | Retrained with impaired repetitions added (LORO over 3 impaired reps): macro-F1 ≥ 0.90 on both profiles | wan mean 0.9533 (rep1 0.9313, rep2 0.9559, rep3 0.9726), lossy mean 0.8398 (rep1 0.8089, rep2 0.8412, rep3 0.8692) | FAILED |
| P17-4 | Safety: ACK-size mode model calls zero tunnel-mode sessions transport on both profiles, Parts A and B | 0 transport answers (wan: 8 tunnel, 40 abstained; lossy: 12 tunnel, 36 abstained; total transport 0) | Held |
| P17-5 | Mixed-traffic detector wrongly flags ≤ 15% of single-class impaired sessions | wan flagged share 0.3333 (16/48), lossy flagged share 0.2083 (10/48) | FAILED |
| P17-6 | IKE under loss: 100% match on encryption, DH group and integrity; zero CVE-2026-78135 detection | 0 mismatches, 0 CVE FAIL (wan: 5 established, 5 PASS; lossy: 5 established, 5 PASS) | Held |

## Counts
- Sessions: 96 (48 wan, 48 lossy)
- IKE bring-ups: 10 (5 wan, 5 lossy)

## Warnings
None

## Not concluded
Interpretation is written by the reviewer.
