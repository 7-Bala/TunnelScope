# EXP-19 — RESULT (2026-09-24)

Every number is from `results/summary.json` (computed by `analyze.py`) and `results/conversion.json`
(`convert_vnat.py`). Pre-registration: `PREREG.md`, commit 0e02a6c, before any training or metric.

## Data actually used
MIT Lincoln Laboratory VNAT, `VNAT_Dataframe_release_1.h5` (1,045,436,008 bytes, sha256
`5d0c3d76cd292f19e25b5229719264bc1ddd71920a20bb27a7dec6c7138914de`). Of 33,711 connections, the 82
OpenVPN tunnel flows (one per `vpn_*` capture file; UDP port 1195 on both ends; 15,487,445 real
packets) became **4,702 windows** from 82 connections: video 300 (5 files), VoIP 180 (3), messaging
3,420 (57), interactive 444 (8), bulk 358 (9). Sizes are IP lengths; "out" is the side that sent the
flow's first packet. Both decisions were made from structure only (`convert_vnat.py` docstring).

## Answers (macro-F1 over the 5 VNAT classes)
| | Result |
|---|---|
| **Q1** today's shipped model (lab-trained) on real VNAT traffic | **0.472** |
| **Q2** real-only model, 5 folds grouped by capture file | **0.744** (folds 0.772, 0.685, 0.704, 0.957, 0.601) |
| **Q3** real OpenVPN-trained model on our IPsec real-application sessions (1,255 windows) | **0.378** |
| **Q4a** combined model (lab + real) on held-out VNAT capture files | **0.741** (folds 0.758, 0.656, 0.717, 0.953, 0.620) |
| **Q4b** our lab real-app sessions, leave one repetition out | **1.000** with VNAT, 0.996 without |

## Ship bar (pre-registered)
| Condition | Held? |
|---|---|
| Q4a >= 0.80 | **No** (0.741) |
| Q4a >= Q1 + 0.10 | Yes (0.741 vs 0.472) |
| Q4b not more than 0.02 worse | Yes (1.000 vs 0.996) |

**The combined model does not ship under the pre-registered bar.** The shipped
`traffic_windows.npz` is unchanged by this experiment.

## What it shows
- **Our lab-trained model is weak on real traffic recorded by someone else (0.472).** This is the
  honest generalisation number the lab results could not give.
- **Adding real data helps a lot on real traffic (0.472 -> 0.741) and costs nothing on our lab
  cases (1.000 vs 0.996)**, but it does not reach the 0.80 bar. The spread across folds (0.60-0.96)
  and the imbalance (57 of 82 files are Skype chat; 3 VoIP and 5 video files) are the likely reasons.
- **Real OpenVPN traffic does not teach the model IPsec (0.378).** Packet sizes and timing carry the
  application, but each tunnel protocol wraps packets differently, so the protocol matters.
- VNAT has no web browsing, e-mail or ping, so those classes were not tested on real data.

## After the result
The verdict above stands as pre-registered. The owner then chose to ship the combined model anyway;
that decision, and what it changed, is recorded separately as DEC-036 (`research/registers/DECISIONS.md`).
