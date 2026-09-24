# Plan: make the traffic classifier more accurate on real traffic (EXP-20 to EXP-25, T-110 to T-117)

> **Status 2026-09-25: plan only.** Owner, 2026-09-25: "make the model more accurate ... boost its
> accuracy score ... look for datasets that match our use case". Every number marked
> **(measured)** came from a command run on this machine on 2026-09-24/25; anything else is
> **PROPOSED** and must not be quoted as a result.
>
> "Boost the score" here means **the model gets better at real traffic it has never seen**, measured
> on test sets frozen before any tuning. It never means a friendlier split, a test set the model
> trained on, dropping hard cases, or quoting only the best fold. Each of those would raise the number
> and make the tool worse, and a judge who asks "how did you split?" would find it.

---

## 1. Where we are (measured)

| Test (macro-F1) | Score | Source |
|---|---|---|
| Lab, held-out repetitions (EXP-15) | 0.986 | EXP-15 RESULT |
| Lab real applications, held out (EXP-16) | 0.995 | EXP-16 RESULT |
| Delayed / lossy network (EXP-17) | 0.984 / 0.914 | EXP-17 RESULT |
| **Lab-trained model on real public traffic (VNAT)** | **0.472** | EXP-19 Q1 |
| **Lab + real model on held-out real capture files** | **0.741** | EXP-19 Q4a |
| Real OpenVPN-trained model on our IPsec sessions | 0.378 | EXP-19 Q3 |
| **Any model on real IPsec traffic from a real network** | **never measured** | no data until now |

The lab numbers are near perfect because lab traffic is clean and repetitive. Every number on
traffic we did not generate is far lower. **The job is to close the lab-to-real gap, and to measure
it on real IPsec for the first time.**

## 2. Why it is not more accurate (diagnosis)

1. **Distribution shift, lab to real** (0.986 lab vs 0.472 real). Real apps change bitrate, pause,
   retransmit, and run background traffic; our generator and lab apps do not.
2. **Protocol shift** (0.378). OpenVPN, WireGuard and IPsec add different overheads and padding, so
   the same application has different packet sizes per tunnel. The model learned sizes, not
   "inner" sizes.
3. **Class imbalance in the real data.** VNAT: 57 of 82 real files are chat; 3 are VoIP; 5 are
   video (EXP-19). The model sees few real examples of the rare classes.
4. **Short context.** One window is 2 seconds with 31 numbers. VoIP's 20 ms rhythm, video's
   periodic chunk bursts and a chat's long silences are clearer over 10-30 s than over 2 s.
5. **Label noise risk in new data** (section 3.3): nDPI files most video under generic "Web".
6. **The abstain rule was tuned on lab data** (TAU 0.60, consistency 0.70). On real traffic it may
   answer too often (wrong) or too rarely (useless); nobody has measured it there.

## 3. Data

### 3.1 Sources found (searched 2026-09-24/25)

| Dataset | Tunnel | Real? | Labels | Fit | Status |
|---|---|---|---|---|---|
| MIT LL **VNAT** | OpenVPN | real apps, real network | file name | medium (not IPsec) | **in use** (EXP-19) |
| **USBVPN2022** (Zenodo 7301756, CC BY 4.0, 811.7 MB zip) | **L2TP over IPsec (ESP, NAT-T)** + PPTP, L2TP, SSTP, OpenVPN, WireGuard | real websites, Meet, streaming, mail, SSH, driven by scripts | activity file | **high: the only public labelled IPsec traffic found** | **downloaded, sha/size checked** |
| **WireGuard matched-view** (Zenodo 18945858, CC BY 4.0, 1.3 GB) | WireGuard, and the **inner plaintext of the same packets** | **real people, 10 devices, ~80 h at home** | nDPI on the inner side | **high: most real data available** | **downloaded, md5 and all 6 sha256 match** |
| ISCXVPN2016 (UNB) | OpenVPN | real users | activity | medium | server unreachable 2026-09-24; a Kaggle copy exists (CS240-ISCXVPN2016), contents unchecked |
| CESNET-QUIC22 / TLS-Year22 | none | real ISP, 500k users | service | low: only the first 30 packets per flow (too short for 2-s windows) | not downloaded |
| MIRAGE-2019/2022/VIDEO (Univ. Napoli) | none | real volunteers, mobile apps | app | medium (inner traffic, could be ESP-wrapped like 3.4) | registration form needed |
| MAWI (WIDE backbone) | real ESP (protocol 50) | real | **none** | for the out-of-distribution gate only | not downloaded |
| ESPect (another team's IPsec analyser) | IPsec | **generator-made** | yes | none (lab-grown, no captures published) | rejected |

### 3.2 USBVPN2022 L2TP-IPsec: what is in it (measured)

- JSON per activity; each record one flow with per-packet `bytes` (sign = direction; value = **IP
  length**, shown by the 29-byte NAT-T keepalive = 20 IP + 8 UDP + 1), timestamps to 1 us.
  Tunnel flows are UDP 4500 on both ends (ESP in UDP). A few ICMP and management-port (8291)
  records are not tunnel traffic and are dropped.
- Records: mail 5 (about 25-30 s each), meet 2 tunnel flows (1.5-2 min), streaming 91 tunnel
  flows (about 35-40 s), non_streaming 1,759 (mostly 6-10 s, one website visit each), ssh 5
  (1-3 s: **too short for 3 windows, so no interactive class from this source**).
- **15-28% of packets sit in "merged" rows** (streaming 25.8%, non_streaming 27.9%, meet 20.2%,
  mail 1.3%, ssh 0%): several same-direction packets with one identical timestamp, `bytes` = their
  sum. They sum to combinations of the capture's common sizes (1556 = 1500 + 56; 2752 = 2 x 1376).
  Handling (decided from structure only): split into n packets whose sizes are the most frequent
  combination of the same capture's single-packet sizes that sums exactly; equal split only when no
  combination fits; the share of each case is reported.

### 3.3 WireGuard matched-view: what is in it (measured)

- `packet_matches.parquet`: **41,515,695** matched packets in session 1 (session 2 not yet counted), each
  with the outer encrypted packet (time, direction, UDP length; IP length = UDP + 20) and the inner
  plaintext packet (5-tuple, time, length). `flows.parquet`: 226,454 inner flows with nDPI labels.
- Usable flows (label not guessed, >= 20 packets, >= 6 s): 58,936. By nDPI category (fixed mapping):
  VoIP 449 -> voip (Telegram, Teams, WhatsApp, Viber calls); Chat 476 -> messaging;
  Email 79 -> email; Download 263 -> bulk; Web 46,011 -> web **(see risk below)**; Collaborative,
  Social, Cloud, SoftwareUpdate and the rest are not mapped (ambiguous).
- **Risk:** no flow is labelled as video (Media: 2 flows); nDPI files YouTube-over-QUIC under
  generic "Web/QUIC". Using "Web" as the web class could teach "video is web", our known weak spot.
  So WireGuard "Web" is tested in its own arm (EXP-20 Q5) before it may be used.

### 3.4 Real traffic as IPsec would carry it (the key idea)

The WireGuard data holds each real inner packet with its real timing. ESP sizes are exact arithmetic
(our cipher sieve, EXP-01): tunnel mode AES-GCM-16 adds 20 (outer IP) + 8 (SPI, sequence) + 8 (IV)
+ pad to 4 bytes + 2 + 16 (ICV). Re-wrapping each inner packet with that arithmetic gives **real
human traffic with the packet sizes a strongSwan AES-GCM tunnel would produce.** Timing is kept
(encryption adds microseconds). Same for AES-CBC-HMAC and for transport mode.
**This is simulation of the wrapper, not of the traffic**, and it is validated before use (T-113):
the arithmetic must reproduce our own lab captures exactly.

## 4. The scoreboard (frozen before any training; T-110)

One script, one table, same splits every time (`build/models/benchmark.py`, splits committed):

| Test set | Split (never mixes one capture into train and test) | Why |
|---|---|---|
| **A. Real IPsec: USBVPN L2TP-IPsec** | grouped by capture record, 5 folds | **primary metric: real IPsec** |
| B. Real users: WireGuard session 2 | train on session 1 only, test on session 2 (different days) | real people, time shift |
| C. Real OpenVPN: VNAT | grouped by capture file, 5 folds (as EXP-19) | continuity |
| D. Our lab | leave one repetition out (as EXP-15/16/17) | must not get worse |

Reported for each: macro-F1, per-class F1, and **selective accuracy with coverage** (how often it
answers, and how often it is right when it does). The **primary number** is A; the ship bar is
PROPOSED in section 6. Test folds are never used to choose features, settings or thresholds; those
use a separate dev split inside the training folds.

## 5. The levers, in order (one experiment each, one change at a time)

| # | Lever | Hypothesis (PROPOSED) | Experiment |
|---|---|---|---|
| L1 | **Add real IPsec (USBVPN) and real-user (WireGuard) data** | more real, IPsec-shaped data raises A and B without hurting D | EXP-20 |
| L2 | **Re-wrap real inner traffic as ESP** (3.4) | real traffic in true ESP sizes transfers to IPsec better than WireGuard sizes do | EXP-21 |
| L3 | **Protocol normalisation**: convert each packet size to its inner size before features (per protocol: ESP from the cipher family the tool already finds; WG +32 +pad16; OpenVPN, L2TP-IPsec from their overheads) | fixes the 0.378 cross-protocol failure, lets all sources teach one model | EXP-22 |
| L4 | **Better features** (keep the 31, add): rhythm (strongest period in packet times, e.g. VoIP 20 ms), burst length and gaps, up/down byte ratio, size entropy, and a 10-s context summary of neighbouring windows | longer context separates video/web and chat/idle better | EXP-23 (ablation: each group on and off) |
| L5 | **Model and weighting**: RandomForest vs ExtraTrees vs HistGradientBoosting (all already in scikit-learn 1.9.1; fit 1.4 / 0.5 / 2.2 s on today's 9,369 windows, measured), class-balanced and per-source weights, probability calibration | the lab's volume stops drowning real data; calibrated probabilities make the abstain rule mean the same on real traffic | EXP-24 |
| L6 | **Session-level decision and abstain retuned on real dev data** | answers become right more often at a stated coverage | EXP-25 |

Why this order: data first (the biggest measured gap is data), then make the data comparable (L2,
L3), then features, then model, then the decision rule. Tuning a model on the wrong data first
would polish the lab number and not the real one.

## 6. Ship bars (PROPOSED; fixed in each PREREG before its run)

A change ships only if, on the frozen scoreboard: **A improves by >= 0.05 macro-F1 over the
current shipped model** (or, for EXP-20, A is reported for the first time and B/C do not drop),
**D drops by no more than 0.02**, B and C do not drop by more than 0.02, the abstain rule's wrong
answers on A do not rise, the model file stays < 5 MB, and startup training stays < 5 s. If a bar
fails, the owner decides, as with DEC-036, and the RESULT keeps the pre-registered verdict.

## 7. Tasks

| Task | What | Files | Done when |
|---|---|---|---|
| T-110 | Scoreboard: `benchmark.py`, frozen split files, baseline row for today's model | `build/models/benchmark.py`, `build/models/splits/` | baseline table committed; re-run gives identical numbers |
| T-111 | USBVPN converter (L2TP-IPsec first; other five protocols as extra arms), merged-row splitting | `experiments/exp20-*/convert_usbvpn.py` | counts and merged-row handling reported; sha of input recorded |
| T-112 | WireGuard converter: per-flow outer packet streams from `packet_matches`, nDPI mapping 3.3 | `experiments/exp20-*/convert_wg.py` | per-class flow and window counts; guessed labels excluded |
| T-113 | ESP re-wrapper + its validation against our own lab captures | `tunnelscope/leakage/encap.py` (pure arithmetic), tests | the arithmetic reproduces every ESP length in the EXP-15 GCM/CBC captures from their known inner sizes, or the gap is explained |
| T-114 | EXP-20 run (L1) | `experiments/exp20-*/` | RESULT; ship per bar or owner decision |
| T-115 | EXP-21 + EXP-22 (L2, L3) | `leakage/attacker.py` (feature input only), experiments | RESULT each |
| T-116 | EXP-23 + EXP-24 (L4, L5) | `leakage/attacker.py`, `make_traffic_data.py` | ablation table; RESULT each |
| T-117 | EXP-25 (L6) + product, dashboard text, deck slide 9, README | as listed | full check_all, findings differential explained, CI green |

Each experiment: PREREG committed before training -> `analyze.py` -> `results/summary.json` ->
RESULT.md quoting only that -> DECISIONS/REGISTER rows -> TODO line.

## 8. What could go wrong (and the answer)

| Risk | Answer |
|---|---|
| Real test data leaks into training (same capture both sides) | grouped splits by capture/record/session; a test asserts no group is on both sides |
| Tuning on the test folds | dev split inside training folds only; test folds read once per experiment |
| nDPI "Web" contains video (label noise) | tested as its own arm (EXP-20 Q5); used only if it does not hurt video/web |
| USBVPN merged rows distort sizes | exact-sum split, share reported, sensitivity run with merged rows dropped |
| Scripted browsing (USBVPN) is less varied than people | WireGuard real users are test set B; report both |
| One source dominates (46,011 web flows) | per-connection window cap (as EXP-19, 60) and per-source weights |
| Re-wrapping is wrong for some cipher | validated against our own captures first (T-113); only validated modes used |
| Better on real, worse on lab | D is a ship bar |
| A new feature breaks the live pipeline or the attacker tests | feature change behind the same `window_features` signature; `tests/test_attacker.py` and the findings differential run every time |
| Startup gets slow | measured per change; bar < 5 s |

## 9. What this plan does not do

- No deep or pretrained traffic model (DEC-006: they collapse under honest splits; a random forest
  on these features beats them). No new pip dependency; everything is in scikit-learn 1.9.1.
- No pickled model file; the shipped artefact stays plain training arrays.
- No claim of "IPsec accuracy" from OpenVPN or WireGuard alone; only test set A is quoted as that.
- No change to the rule engine, verdicts, or anything outside the traffic classifier and its tests.

## 10. Owner decisions (recommended defaults)

1. **Primary metric = test set A (real IPsec, USBVPN)**, reported with B, C and D. *(Recommended.)*
2. **USBVPN "meet" (Google Meet video calls) -> voip** (real-time conversation). Alternative: leave
   it out. *(Recommended: map it, and report its per-class F1 separately.)*
3. **WireGuard "Web" only after EXP-20 Q5 shows it does not blur video and web.** *(Recommended.)*
