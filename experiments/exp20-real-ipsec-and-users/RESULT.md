# EXP-20 — RESULT (2026-09-25)

Every number is from `results/summary.json` (computed by `analyze.py`) and `results/conversion_*.json`
(the converters). Pre-registration: `PREREG.md`, commit dc0020f, before any training or metric.

## Data actually used
**USBVPN2022** L2TP-over-IPsec (Zenodo 7301756): 994 real tunnel records -> **6,069 windows**
(email 33/5 records, voip 101/2 records, web 4,510/894 records, video 1,425/93 records; no usable
interactive records). **WireGuard matched-view** (Zenodo 18945858): 1,186 real flows from real
people at home -> **11,450 windows** across two sessions (bulk 319, email 59, messaging 2,010,
voip 2,728, web 6,334).

## Answers (macro-F1; A is pooled out-of-fold over 5 groups)
| | R0 shipped | R1 +USBVPN | R2 +WireGuard | **R3 candidate** | R4 +WG web |
|---|---|---|---|---|---|
| **A. Real IPsec (USBVPN), primary** | **0.174** | 0.608 | 0.085 | **0.757** | 0.665 |
| A coverage (answers, not "uncertain") | 0% | 93.7% | 0% | **93.6%** | 94.1% |
| A accuracy when answering | n/a | 99.7% | n/a | **99.8%** | 99.6% |
| B. Real people (WireGuard, without web) | 0.234 | 0.242 | 0.660 | **0.676** | 0.612 |
| C. Real OpenVPN (VNAT) | 0.879 | 0.883 | 0.873 | **0.879** | 0.885 |
| D. Our lab (real apps, LORO) | 1.000 | 1.000 | 0.996 | **0.996** | 0.996 |
| Startup fit (n_jobs=1, as shipped) | 1.46 s | 3.71 s | 2.63 s | **5.00 s** | 7.08 s |

## What Q1-Q5 show
- **Q1: today's shipped model on real IPsec traffic it never saw scores 0.174, and answers 0% of
  the time.** Every real IPsec record hits the abstain rule and comes back "uncertain" — the honest
  behaviour the abstain rule is designed for, but it means the traffic-type finding gives nothing on
  real IPsec traffic today.
- **Q2: adding the real IPsec data alone (R1) is the largest single lever**, 0.174 -> 0.608, and the
  model starts answering (93.7% coverage, 99.7% right when it answers).
- **Q3: WireGuard data alone, without any real IPsec data, makes real-IPsec performance *worse*
  (R2: 0.085)** — evidence for the plan's protocol-shift diagnosis (§2): a different tunnel's real
  traffic without any matching-protocol traffic confuses the model on IPsec. WireGuard data does
  help its own real-people test (B: 0.234 -> 0.660).
- **Q4: the candidate R3 (lab + VNAT + USBVPN + WireGuard, without WireGuard's "web") clears every
  accuracy bar by a wide margin**: A 0.174 -> 0.757 (bar was +0.05; this is +0.58), B holds gains
  (0.676, no drop), C and D are flat within the bar (0.879 vs 0.879; 0.996 vs 1.000, within 0.004).
- **Q5: WireGuard's nDPI "web" hurts real IPsec performance (R4 A 0.665 < R3's 0.757) and voip's
  own F1 collapses (0.222 vs 0.579)**, exactly the label-noise risk stated in advance (§3.3: nDPI
  files video under "Web"). **R4 does not replace R3.**

## Ship bar (pre-registered)
| Condition | R3 | R4 |
|---|---|---|
| A macro-F1 >= R0 + 0.05 | **Yes** (+0.583) | Yes (+0.491), but Q5 already rules R4 out |
| D not more than 0.02 worse | Yes (0.996 vs 1.000) | Yes |
| C not more than 0.02 worse | Yes (0.879 vs 0.879) | Yes |
| B (without web) not more than 0.02 worse | Yes (+0.442) | Yes |
| A abstain accuracy not down | Yes (R0 never answered) | Yes |
| Window files < 5 MB | Yes | Yes |
| **Startup fit (n_jobs=1) < 5 s** | **No — measured 5.00 s** | No — measured 7.08 s |

**Neither R3 nor R4 ships under the pre-registered bar.** Every accuracy condition passed by a wide
margin; the run failed on one operational condition only: the product's own single-threaded startup
fit (`tunnelscope.leakage.attacker._model`, `n_jobs=1`) takes about 5 seconds once training data
reaches ~20,000 windows, at or just past the 5-second line set in advance. The shipped
`traffic_windows.npz` (and the window-file additions) are unchanged by this experiment.

## What it shows, beyond the bar
- **Real IPsec data is not optional if the tool is to say anything about real IPsec traffic**: with
  none, the shipped model is silent on it (0% coverage); with some, it answers correctly nearly
  every time it does answer.
- The training-time cost is a **fixed, measured, single-number engineering fact**, not a modelling
  limitation: fitting the same R3 data with `n_jobs=-1` (parallel, the setting `benchmark.py` and the
  build-time trainer already use) took 0.68 s in three repeated trials, with predictions identical to
  `n_jobs=1` up to floating-point rounding (max difference 2.2e-16, i.e. not a real difference).
  Whether to change the live product's setting is a separate decision from this experiment's bar,
  which measured the code exactly as shipped, as pre-registered.
