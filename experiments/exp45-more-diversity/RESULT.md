# EXP-45 — More kinds of real traffic (labs E and F) — RESULT (2026-10-04)

Pre-registration `1acd160`; harness and scorer `9477d65` (before any scored capture); lab E tables `4b85b9f`, lab F tables `f4be868`
(both committed before the scorer ran). Scores in `results/summary.json`, every lab-F session in `results/lab_f_sessions.csv`.

## Verdict by the pre-registered ship rule
**Nothing ships.** The model needed P45-2 and P45-6: P45-6 failed. The mixed check needed P45-4, P45-5 and P45-7: P45-5 failed.
The shipped classifier (K4, DEC-054) and the shipped mixed-traffic check stay as they are.

| # | Prediction | Result | |
|---|---|---|---|
| P45-1 | best of K7/K8/K9 >= K4 + 0.03 on the original eight families' leave-one-family-out mean | K8 0.514 vs K4 0.455, **+0.059** | held |
| P45-2 | on lab F the chosen model beats the shipped K4 by >= 0.05 ungated macro-F1 | 0.724 vs 0.603, **+0.121** | held |
| P45-3 | chosen model's lab-F interactive F1 >= 0.5 | **0.75** (shipped K4: 0.33) | held |
| P45-4 | the mixed check meets catch >= 80% and false flags <= 10% in cross-validation with 92 mixed sessions | tau 0.20: **83.7%** caught, **7.6%** flagged | held |
| P45-5 | with the new check, <= 25% of lab-F singles are flagged mixed | **32.6%** (15 of 46); the current check flags 63% (29 of 46) | **failed** |
| P45-6 | on lab F >= 90% of gated answers right AND >= 50% of singles answered | 9 of 9 right (100%), but **9 of 46 answered (19.6%)** | **failed** |
| P45-7 | >= 80% of lab-F mixed sessions flagged or abstained | **16 of 16** not answered | held |

## Candidates (leave-one-family-out session macro-F1)
| | nine-family mean | original eight | worst family | grouped by session | lab-tgen | lab-real-apps | vnat | usbvpn | wireguard | lab-a | lab-b | lab-c | lab-e |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| K4 (shipped recipe, eight families) | 0.487 | 0.455 | 0.043 | 0.977 | 0.587 | 0.664 | 0.536 | 0.043 | 0.203 | 0.451 | 0.500 | 0.658 | 0.744 |
| K7 (nine families) | 0.507 | 0.477 | 0.056 | 0.981 | 0.706 | 0.716 | 0.570 | 0.056 | 0.260 | 0.490 | 0.500 | 0.517 | 0.744 |
| **K8** (K7, ExtraTrees + RandomForest soft-voted) | **0.537** | **0.514** | 0.036 | 0.987 | 0.706 | 0.716 | 0.564 | 0.036 | 0.264 | 0.520 | 0.500 | 0.804 | 0.719 |
| K9 (K7, family weight ~ sqrt(sessions)) | 0.503 | 0.478 | 0.034 | 0.987 | 0.715 | 0.695 | 0.547 | 0.034 | 0.268 | 0.547 | 0.500 | 0.517 | 0.706 |

All four passed EXP-42's two guards against K4; **K8 was chosen** (highest nine-family mean, no earlier row within 0.01).
K4's eight-family mean reproduces EXP-42's 0.455. USBVPN (scripted web visits) stays the worst family for every candidate (0.03 to 0.06):
lab E did not help it.

## Lab F (46 single and 16 mixed sessions; trained nothing, chose nothing)
Ungated, per class (session F1):

| | bulk | email | icmp | interactive | messaging | video | voip | web | macro |
|---|---|---|---|---|---|---|---|---|---|
| shipped K4 | 0.40 | 0.80 | 0.80 | 0.33 | 0.50 | 0.57 | 0.67 | 0.75 | **0.603** |
| chosen K8 | 0.50 | 1.00 | 0.80 | 0.75 | 0.50 | 0.57 | 0.67 | 1.00 | **0.724** |

Through the product's gate (single sessions):

| | answered | right | out of distribution | abstained | flagged mixed |
|---|---|---|---|---|---|
| shipped K4 + shipped check | 6 | **4** | 10 | 30 | 30 |
| chosen K8 + shipped check | 5 | 5 | 12 | 29 | 29 |
| chosen K8 + new check (the pair that would have shipped) | 9 | 9 | 12 | 25 | 15 |

Mixed sessions answered with a single label: shipped pair 2 of 16 (both `bulk.rsyncd+interactive.watch`, called video);
chosen model with either check 0 of 16.

## What this says
1. **More kinds of traffic did help recognition, again.** One new family lifted the held-out mean by 0.06 and lab F by 0.12, and
   interactive sessions are no longer lost (0.75 on lab F). The soft-voted pair of forests was the best of the candidates.
2. **The gate, not the classifier, is what failed.** On lab F the gate lets through only 9 of 46 sessions: 12 are judged out of
   distribution (all icmp traceroute/ping1000, most interactive, half of voip and a third of video), 15 are flagged mixed, and 10 fail
   the confidence or consistency threshold. The answers it does give are all right, but a tool that answers one session in five is
   below the bar set before the data.
3. **The new mixed check is better than the current one and still over-flags unseen single traffic** (33% on lab F against a 25%
   bar; the current check flags 63%). Its cross-validated false-flag rate was 7.6%: cross-validation inside the training families
   understates what happens on a new lab.
4. **A claim to correct.** On lab D the shipped model's gated answers were 11 of 11 right. On lab F they are **4 of 6**: two bulk
   transfers (`rsync` daemon, `nc` download) were confidently called video. "When it answers, it is right" does not hold on lab F
   for the shipped model.

## Readings of the PREREG fixed before capture (scorer docstring, `9477d65`)
Repetition 1 on the first suite and 2 on the second; 64 lab-E mixed = 8 pairs x 2 pairings x 2 repetitions x 2 suites; P45-1 on the
original eight families; P45-6 scored with the pair that would ship, over all captured singles; "shipped K4" = the product's own model.

## Deviations and incidents (all before any scored capture unless stated)
- Lab E has 29 variants (the PREREG says "about 26"): 58 single sessions, 55 with enough windows to score; 64 mixed.
- Lab F: `voip.ilbc` dropped (the image has no iLBC encoder), so 46 single sessions, not 48. `video.tstcp` fixed (the client started
  before the server was listening) and `email.swakstls` fixed (the image lacked the Perl TLS module, now in the Dockerfile).
  Some lab-F tools differ from the PREREG's prose list (e.g. `swaks` over TLS and IMAPS instead of `mailx` through a relay; a third
  video variant, Theora RTP); the variants are those in `testbed/scripts/labef_gen.sh` at `9477d65`.
- A 6-second rehearsal of the harness on lab F wrote its 62 throwaway sessions into `testbed/captures/exp45/` by mistake (the
  rehearsal-folder switch had not been applied). They were deleted before the harness was committed; only their packet counts had
  been looked at. Nothing from them reached a model or a score.
- The scorer was rehearsed on stand-in tables from labs C and D with 20-tree forests, writing only to a scratch folder.
- One lab-E session (`icmp.hping`, cbc128) was retried by the harness's packet-count rule (2 packets on the first attempt).
- Lab A and lab B captures were fetched again (the earlier copies were gone); file names and sizes are identical to the run EXP-42
  cached (175 and 180 files).
- A host-side unit-test run (at low priority) overlapped part of the lab-E capture; lab E is training data only.

## What is now used up
Lab F has been looked at. It can no longer serve as an untouched test; a further attempt needs a new pre-registration and a new lab.
