# EXP-20 — Real IPsec traffic (USBVPN2022) and real people (WireGuard matched-view): do they make the traffic classifier better on real traffic? — PRE-REGISTRATION (2026-09-25, before any training or metric)

Owner, 2026-09-25: "i want u to train the models on real data so look deeper for something available
for our usecase and download it and use it", then "make the model more accurate ... boost its accuracy
score". Plan: `build/14-ACCURACY-PLAN.md` (lever L1). Owner approved both downloads.

## Data (fixed; conversion outputs and hashes in `results/conversion_*.json`)
- **USBVPN2022** (Zenodo 7301756, CC BY 4.0): the `VPN/L2TP IPsec` folder only. Real websites,
  Google Meet, streaming, mail and SSH, driven by scripts, inside a real L2TP-over-IPsec tunnel (ESP
  in UDP 4500). Labels by activity file: mail -> email, meet -> voip, streaming -> video,
  non_streaming -> web, ssh -> interactive. Merged same-timestamp rows split by exact sums
  (`convert_usbvpn.py`). **This is the first real IPsec traffic the project has.**
- **WireGuard matched-view** (Zenodo 18945858, CC BY 4.0): ~80 h of real people at home; the
  outer (encrypted) packets of each inner flow. Labels from nDPI on the inner side, only when not
  guessed: VoIP -> voip, Chat -> messaging, Email -> email, Download -> bulk, Web -> web (separate
  arm, Q5: it probably contains video). Flows >= 20 packets and >= 6 s (`convert_wg.py`).
- Windows: the tool's own `window_features` and `MIN_WINDOWS` (3); at most 60 windows per USBVPN
  record, 20 per WireGuard flow; WireGuard web: a seeded sample of 3,000 flows; seed 20
  (`export_windows.py`). Counts (structure only, from the export run):
  - USBVPN: **6,069 windows, 994 records** — email 33 (5 records), voip 101 (2 records),
    web 4,510 (894 records), video 1,425 (93 records). No interactive windows (SSH records too short).
  - WireGuard: **11,450 windows, 1,186 flows**, split by session (train/test, never mixed):
    session 1 (train): bulk 35 (9 flows), email 24 (4), messaging 687 (55), voip 1,360 (96),
    web 3,696 (430); session 2 (test): bulk 284 (33), email 35 (5), messaging 1,323 (140),
    voip 1,368 (116), web 2,638 (298).
- The lab data and the VNAT windows are exactly those shipped today (DEC-036).

## The scoreboard (`build/models/benchmark.py`, T-110; frozen with this commit)
- **A, real IPsec (primary)**: USBVPN, 5 folds grouped by capture record; pooled out-of-fold
  macro-F1 over the classes present, 95% interval from 1,000 resamples of whole records, per-class
  F1 with its record count, and the abstain rule (TAU 0.60, consistency 0.70, per record): coverage
  and accuracy when answering. A recipe that does not learn from USBVPN is tested on all of it.
- **B, real people**: WireGuard; trained with session 1 only, tested on session 2. Primary "without
  web" (voip, messaging, email, bulk); "with web" reported as well.
- **C, real OpenVPN**: VNAT, 5 folds grouped by capture file (pooled macro-F1; EXP-19 continuity).
- **D, our lab**: EXP-16 real applications, leave one repetition out (as EXP-19 Q4b).
- Model for every recipe: the shipped Random Forest settings (200 trees, min_samples_leaf 2, seed 0).
  Nothing about the model, features, abstain rule or out-of-distribution gate changes in EXP-20.

## Recipes and questions
| Recipe | Learns from |
|---|---|
| R0 | lab + VNAT (shipped today) |
| R1 | R0 + USBVPN |
| R2 | R0 + WireGuard (without web) |
| R3 | R0 + USBVPN + WireGuard (without web): **the candidate** |
| R4 | R3 + WireGuard web |

- **Q1**: today's model (R0) on real IPsec (A) and real people (B): the first such measurement.
- **Q2**: does real IPsec data help real IPsec? R1 vs R0 on A.
- **Q3**: does real-people WireGuard data transfer to IPsec? R2 vs R0 on A; and B.
- **Q4**: the candidate R3 vs R0 on A, B, C, D.
- **Q5**: does WireGuard's nDPI "web" help or blur video and web? R4 vs R3.

## Ship bar (fixed now, applied mechanically by `analyze.py`)
R3 replaces the shipped training set only if **all** hold, versus R0:
1. A macro-F1 is at least **0.05 higher**;
2. D is no more than 0.02 lower; C is no more than 0.02 lower; B (without web) is no more than 0.02 lower;
3. on A, the abstain rule's accuracy when answering is not lower (if R0 answers at all);
4. each window file < 5 MB; the product's startup fit (n_jobs 1) < 5 s.
R4 replaces R3 only if Q5 holds (A macro-F1 not lower than R3, A video F1 no more than 0.02 lower,
C no more than 0.02 lower) **and** R4 clears the same bar. Otherwise nothing ships and the result is
still reported; any override is the owner's and is recorded as a separate decision.

## Known limits, stated now
- USBVPN traffic is scripted (Selenium, Meet) over a real IPsec tunnel; B (real people) is WireGuard,
  not IPsec. Only A may be quoted as "real IPsec".
- A has few email (5) and voip (2) records; their per-class F1 is reported with the count and is not
  quotable on its own. USBVPN has no usable interactive record (SSH records are 1-3 s).
- nDPI labels can be wrong; guessed labels are excluded, not corrected.
- Grouping by record is the finest grouping USBVPN offers; records from the same day can share
  websites.

## Rules
- No mapping, cap, seed, threshold or bar changes after this commit. Whatever fails is reported.
- `analyze.py` writes `results/summary.json`; `RESULT.md` quotes only that and is not edited after.
