# EXP-51 — Stop the traffic classifier reading link speed as traffic type; set the gate on unseen families — PRE-REGISTRATION

**2026-10-07, before any candidate is scored and before any lab-H or lab-G capture. The owner approved the bars in section 7, labs H
and G, and re-cloning labs A and B on 2026-10-07 ("go with the recommended"). No candidate in section 4 has been run on any data.**

## 1. Where the scores stand (from earlier RESULT files, not re-run)
| Test | Shipped K4 | Best candidate so far (K8, not shipped) |
|---|---|---|
| Lab D ungated macro-F1 (EXP-43, spent) | 0.833 | not scored |
| Lab F ungated macro-F1 (EXP-45, spent) | 0.603 | 0.724 |
| Lab F gated answers | 4 of 6 right, 6 of 46 answered | 9 of 9 right, 9 of 46 answered |
| Leave-one-family-out mean, eight families | 0.455 | 0.514 |
| USBVPN held out | 0.043 | 0.036 |

## 2. Diagnosis measured today (2026-10-07), before writing the candidates
Shipped recipe (K4: v2 features, balanced, augmented), families on disk (lab-tgen, lab-real-apps, vnat, usbvpn, wireguard, lab-c;
the lab A and B clones are gone, so this is a six-family run and its numbers are not comparable with EXP-42's table). Scratch script,
no new candidate scored.

1. **USBVPN held out: 0.040 macro-F1. Of 894 scored web sessions, 442 are called bulk, 444 video, 0 web.** Video: 47 of 93 right.
   Email (5 sessions) and voip (2) are all wrong.
2. **Cause: the model uses absolute rate as a class signal.** A USBVPN web session is one scripted page load: median 13,105 packets
   in 10.0 s. Its web windows average 1,370 packets/s (context feature); lab C's web windows 62, lab-tgen's 178. Four of the model's
   six most important features are absolute rates (`ctx_bps` 0.066, `ctx_pps` 0.059, `bps` 0.040, `pps` 0.039). Rate depends on
   the link and the generator, not on the kind of traffic. The augmentation scales time by 0.8 to 1.25; the gap is about 8 to 20 times.
3. **USBVPN's macro-F1 is fragile by construction:** four classes, two of them with 5 and 2 sessions. Perfect web and video with
   email and voip wrong would still score about 0.5.
4. **Lab F errors are by tool, not by chance or cipher** (`results/lab_f_sessions.csv` of EXP-45): the same 9 of 23 variants are wrong
   on both ESP suites (18 of 46 sessions): `bulk.ncdl`, `bulk.rsyncd` -> video; `video.tstcp` -> bulk; `interactive.cmatrix` -> web;
   `interactive.watch` -> voip; `messaging.mqtt0` -> interactive; `messaging.zmq` -> voip; `email.imaps` -> web;
   `icmp.traceroute` -> interactive. Bulk against video is again a rate confusion.
5. **The gate throws away right answers.** On lab F the shipped pair abstained on 20 sessions whose ungated guess was right, and
   answered 6 (4 right). 30 of 46 singles were flagged mixed. EXP-45 already showed the thresholds, set by cross-validation inside
   the training families, understate false flags on a new lab (7.6% predicted, 32.6% measured).
6. **Lab D** has 4 sessions per class; only interactive (mosh, 0 of 4) and voip (0.67) are wrong. One session moves a class by up to 0.33.

## 3. What can honestly be "fixed"
- Labs D and F have been looked at. Any change chosen with their errors in view will score better on them and that gain proves
  nothing. They are reported here as **development checks only**, with a no-regression guard.
- The leave-one-family-out mean and USBVPN held out are cross-validation numbers and may be improved, but only by candidates fixed
  below before any is scored.
- **The claim rests on lab G, a new untouched lab** (section 6). No lab G, no new accuracy claim and nothing ships.

## 4. Candidates (all fixed here; trained with K8's ensemble unless stated)
| | Change | Why (from section 2) |
|---|---|---|
| R0 | K8 as in EXP-45 (v2, nine families, ExtraTrees + RandomForest) | baseline |
| R1 | **v3 features**: drop the 10 absolute count/byte/rate columns (`out_n`, `out_bytes`, `in_n`, `in_bytes`, `pps`, `bps`, `ctx_pps`, `ctx_bps` and the two `iat<1ms` shares); add their rate-free forms: in/out packet ratio, in/out byte ratio, sizes divided by the session's largest packet per direction, inter-arrival times divided by the session's median, share of windows' packets in the busiest 200 ms | finding 2 |
| R2 | R0 + **speed augmentation by class**: bulk, web and email copies get a time scale drawn log-uniformly from 1/8 to 8 (their pace is set by the link); voip, video, interactive, messaging and icmp keep 0.8 to 1.25 (their pace is set by the application). 4 copies per session | finding 2 |
| R3 | R1 + R2 | |
| R4 | R3 + **session stage**: a second forest over session descriptors (share of windows with traffic, spread of window rate over the session, direction asymmetry, the mean and spread of the window probabilities), trained on out-of-family window probabilities | findings 1 and 4: web is bursty, bulk steady, video steady and one-way |
| R5 | R4 + lab H in training (section 5) | every earlier experiment: more kinds of generator is the lever that moved most |

**Gate (applies to the chosen model):** drop the 46-dimension nearest-neighbour distance cut and the in-family mixed threshold.
Set all three thresholds (out of distribution, mixed, confidence) from **leave-one-family-out predictions pooled over families**:
the loosest thresholds at which pooled held-out answers are at least 90% right. One procedure, no hand tuning.

## 5. Lab H, a new training family
Same gateways and capture point as labs C to F. Its purpose is to break the link between rate and class: **every variant runs at
three link profiles** (`netem rate` 2 Mbit/s, 20 Mbit/s, unshaped). Tools not used in labs A to G:
headless Chromium loading a mirrored set of real pages (the fast page load USBVPN has and no lab has); capped and uncapped downloads;
DASH video over TCP and RTP video; `mosh` and `ssh` with replayed typing; ZeroMQ, XMPP and IRC messaging; IMAPS and SMTP; several
ping and traceroute forms. About 24 variants x 3 profiles x 2 repetitions x 45 s. Tool list is fixed in the generator's commit,
before lab G's.

## 6. Lab G, the only test that can ship anything
Built after lab H, tools different from every earlier lab and from lab H, two ESP suites, two link profiles not used in lab H
(5 Mbit/s with 40 ms delay; 50 Mbit/s). **At least 8 sessions per class** (labs D and F had 4 and about 6: too few). At least 16 mixed.
Captured after the candidate is chosen. Scored once.

## 7. Predictions and bars
| # | Prediction | Bar |
|---|---|---|
| P51-1 | Rate-free features help unseen families | R1 leave-one-family-out mean >= R0 + 0.03 |
| P51-2 | Speed augmentation helps USBVPN | R2 USBVPN held out >= 0.20, web recall >= 50% |
| P51-3 | The chosen candidate beats K8 | leave-one-family-out mean >= 0.57 (K8 0.514) |
| P51-4 | No harm on seen generators | grouped-by-session >= 0.96 |
| P51-5 | Lab G, ungated | chosen >= shipped K4 + 0.10 macro-F1 |
| P51-6 | Lab G, gated | >= 90% of answers right AND >= 50% of singles answered |
| P51-7 | Lab G, mixed | >= 80% of mixed sessions not answered with a single label |
| Guard | Labs D and F (spent, development only) | chosen ungated >= 0.80 on D and >= 0.70 on F |

**Choice rule:** highest leave-one-family-out mean among candidates that pass P51-4 and the guard; the earliest row within 0.01 of
the best wins. **Ship rule:** P51-5, P51-6 and P51-7 all hold on lab G. Otherwise nothing ships and the RESULT says so.

## 8. Not in this experiment
Deep or pretrained traffic models (rejected earlier; one 2025 cross-data-set study, arXiv 2507.06430, as summarised by a fetch tool
and not read in full, reports a transformer at 0.28 transferred accuracy against 0.24 for one-nearest-neighbour). Relabelling USBVPN. New public data sets: none found with labelled IPsec packets; Dalhousie NIMS VPN 2024
is flow records behind a subscription, so not usable.
