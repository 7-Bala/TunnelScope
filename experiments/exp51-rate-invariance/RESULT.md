# EXP-51 — Rate-free features, speed augmentation, a session stage, a gate set on held-out families, labs H and G — RESULT (2026-10-08)

Pre-registration `cb86075`; scorer `16120c9` (before any candidate was scored); labs H and G fixed in `2c3cad2`; addendum A `fcfa1e2`
(after R0 to R4, before any model saw lab H); lab H tables `93d9760`; choice and gate `e20575e` (before any lab-G capture); lab G tables
`be1c28a` (before the scorer ran on them). Scores in `results/partial.json`, `results/choice.json`, `results/summary.json`; every lab-G
session in `results/lab_g_sessions.csv`.

## Verdict by the pre-registered ship rule
**Nothing ships.** The rule needed P51-5, P51-6 and P51-7 on lab G: P51-6 failed (the gate answers too few sessions).
The shipped classifier (K4, DEC-054) and its gate stay as they are.

| # | Prediction | Result | |
|---|---|---|---|
| P51-1 | rate-free features: R1 >= R0 + 0.03 held-out mean | 0.467 vs 0.514, **-0.047** | **falsified** |
| P51-2 | speed augmentation: R2 USBVPN held out >= 0.20, web recall >= 50% | **0.034**, web recall **0 of 894** | **falsified** |
| P51-3 | chosen candidate's held-out mean >= 0.57 | R6 **0.561** (K8/R0 0.514) | **failed** (by 0.009) |
| P51-4 | grouped by session >= 0.96 | 0.988 | held |
| P51-5 | lab G ungated: chosen >= shipped + 0.10 | **0.855 vs 0.631, +0.224** | held |
| P51-6 | lab G gated: >= 90% of answers right AND >= 50% of singles answered | 20 of 20 right, but **20 of 64 answered (31%)** | **failed** |
| P51-7 | lab G: >= 80% of mixed sessions not answered | **14 of 16** | held |
| Guard | lab D >= 0.80 and lab F >= 0.70 (spent labs, development only) | R6 0.833 and 0.774 | held |

## Candidates (leave-one-family-out session macro-F1; "eight" = EXP-42's original families)
| | eight | all | grouped | lab D | lab F | lab-tgen | lab-real-apps | vnat | usbvpn | wireguard | lab-a | lab-b | lab-c | lab-e | lab-h |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R0 (K8) | 0.514 | 0.536 | 0.987 | 0.833 | 0.724 | 0.706 | 0.716 | 0.564 | 0.036 | 0.264 | 0.520 | 0.500 | 0.804 | 0.719 | |
| R1 rate-free features (v3) | 0.467 | 0.483 | 0.986 | 0.833 | 0.556 | 0.469 | 0.684 | 0.455 | 0.038 | 0.255 | 0.475 | 0.600 | 0.760 | 0.614 | |
| R2 speed augmentation | 0.449 | 0.470 | 0.987 | 0.833 | 0.671 | 0.630 | 0.710 | 0.450 | 0.034 | 0.344 | 0.287 | 0.500 | 0.638 | 0.638 | |
| R3 both | 0.520 | 0.531 | 0.986 | 0.833 | 0.559 | 0.527 | 0.662 | 0.530 | 0.033 | 0.400 | 0.466 | 0.780 | 0.767 | 0.616 | |
| R4 R3 + session stage | 0.445 | 0.448 | 0.609 | 0.599 | 0.583 | 0.290 | 0.545 | 0.169 | 0.063 | 0.406 | 0.484 | 0.780 | 0.827 | 0.471 | |
| R5 R4 + lab H | 0.524 | 0.530 | 0.760 | 0.833 | 0.768 | 0.391 | 0.732 | 0.254 | 0.225 | 0.449 | 0.549 | 0.765 | 0.827 | 0.596 | 0.514 |
| **R6** R0 + lab H (addendum A) | **0.561** | 0.566 | 0.988 | 0.833 | 0.774 | 0.745 | 0.795 | 0.599 | 0.030 | 0.260 | 0.623 | 0.500 | 0.933 | 0.711 | 0.467 |
| R7 R3 + lab H (addendum A) | 0.544 | 0.553 | 0.987 | 0.824 | 0.714 | 0.605 | 0.716 | 0.603 | 0.028 | 0.410 | 0.378 | 0.780 | 0.833 | 0.731 | 0.445 |

Eligible (grouped >= 0.96, lab D >= 0.80, lab F >= 0.70): R0, R6, R7. **Chosen: R6** (highest eight-family mean; no earlier row within 0.01).
R0 reproduces EXP-45's K8 (0.514).

## Lab G (64 single and 16 mixed sessions; trained nothing, chose nothing; scored once)
Ungated, per class (session F1):

| | bulk | email | icmp | interactive | messaging | video | voip | web | macro |
|---|---|---|---|---|---|---|---|---|---|
| shipped K4 | 0.80 | 0.86 | 0.40 | 0.78 | 0.71 | 0.38 | 0.84 | 0.29 | **0.631** |
| chosen R6 | 0.89 | 1.00 | 0.93 | 0.89 | 0.86 | 0.67 | 0.94 | 0.67 | **0.855** |

R6 by link profile: 0.902 at 5 Mbit/s with 40 ms delay, 0.804 at 50 Mbit/s. R6 is wrong on 9 of 64 sessions: `video.httplive` -> web (4 of 4),
`messaging.tcpjson` -> interactive (2), `web.pyreq` -> bulk (2), `icmp.ping200` -> voip (1). The shipped model is wrong on 23, among them
all four Firefox page loads (called video), which R6 gets right.

Through the gate:

| | singles answered | right | not answered | mixed sessions answered with one label |
|---|---|---|---|---|
| shipped K4 + shipped gate | **0 of 64** | - | 47 abstained, 17 out of distribution | 0 of 16 |
| R6 + the gate set on held-out families (confidence >= 0.65, mixed score < 0.65, no distance cut) | **20 of 64** | **20** | 44 | 2 of 16 (both `bulk.pyhttp+interactive.sshbc`, called bulk) |

Of R6's 44 unanswered singles, 35 had the right guess; all 44 were stopped by the confidence threshold (8 also by window agreement, 1 also
by the mixed check). The gate's held-out estimate (32% answered, 93% right, 82% of mixed held back) matched lab G (31%, 100%, 88%): setting
the gate on held-out families predicts a new lab; setting it by cross-validation inside the families (EXP-45) did not.

## What this says
1. **My diagnosis was half right and my fix was wrong.** The shipped model does lean on absolute rates (four of its six most important
   features), but removing them (R1) or stretching time in training (R2) made unseen families worse, not better, and USBVPN's web
   sessions were still never called web (0 of 894). Rate carries real class information; taking it away costs more than it saves.
2. **More kinds of generator is again the only lever that worked.** Lab H (23 tools at three link speeds, with real-browser page loads)
   lifted the held-out mean from 0.514 to 0.561 and gave 0.855 on lab G against 0.631. This is the fourth experiment in a row with
   that finding (EXP-41/43, EXP-45, this one).
3. **The session stage as designed is broken** (R4: 0.609 on seen generators). It is trained on out-of-family window probabilities, which
   are flat, and then meets in-family probabilities, which are sharp. Not a tuning problem; the design is wrong.
4. **USBVPN held out is not fixed** (0.03 for every eligible candidate). R5 reached 0.225 with 35% web recall but breaks seen traffic.
   Its macro-F1 is also capped near 0.5 by two classes with 5 and 2 sessions.
5. **The gate is honest and too cautious.** It answers one session in three and was right every time on lab G; the bar was one in two.
   Confidence on unseen tools is low even when the guess is right (35 of 44).
6. **The shipped product answered none of lab G's 64 sessions.** That is safe, and it is also the measure of how little the shipped
   gate lets through on tools it has not seen.

## Readings of the PREREG fixed in the scorer before scoring (`16120c9`)
v3's exact columns; the speed copies replace EXP-42's copies; the session stage's 20 descriptors and its pairwise training; the mean for
P51-1/P51-3 and the choice is over the original eight families; the gate's grid, its family-weighted pooling and tie order; P51-6 over all
captured singles. All are in the scorer's docstring.

## Deviations and incidents
- **Addendum A** added R6 and R7 after R0 to R4 were known (and their lab-D and lab-F guard scores), before any model saw lab H. The chosen
  candidate is one of them. Without the addendum the choice would have been R0 (K8), whose lab-G score was not measured.
- Lab H: `voip.amrnb` dropped (no encoder), 23 variants, 138 sessions, no retries. Third link profile 100 Mbit/s, not unshaped (table
  size). Pages are generated locally, not mirrored from the internet. The PREREG's example list for lab H named some tools that labs D
  and F had used (mosh, ZeroMQ, IRC, IMAPS); lab H uses none of them, so the lab-D and lab-F guards are not helped by shared tools.
- Lab G: `voip.g7231` replaced by `voip.siren` and `icmp.pinga` by `icmp.ping200` after a smoke test that looked at packet counts only
  (ffmpeg cannot send G.723.1 over RTP; adaptive ping floods an unshaped link). `voip.alaw60` uses G.711, the codec of one lab-D tool,
  with 60 ms packets and talk spurts. 80 sessions, no retries.
- The scorer was rehearsed on stand-in data (10-tree forests, three or four families, lab F's tables posing as lab G) writing only to a
  scratch folder; I saw those stand-in scores. They say nothing about the real run.
- Three fixes to the scorer during the rehearsal, before `16120c9`: the helper forests predict single rows on one thread; a mixed
  detector with no mixed training row scores 0; rehearsal switches.
- The addendum commit `fcfa1e2` was made without the fast check, because the unit tests reload gateway configurations and lab H was
  being captured; the check passed at the next commit (`93d9760`).
- The R0 to R4 scoring ran on the host while the lab-H image was built and partly while lab H was captured (at low priority). Lab H is
  training data only. Nothing heavy ran during the lab-G capture.
- Labs A and B were cloned again at the pinned commits (175 and 217 capture files; lab B's handshake-only captures are not traffic sessions, as in EXP-42).

## What is now used up
Lab G has been looked at. Lab H is training data. A further attempt needs a new pre-registration and a new lab.
