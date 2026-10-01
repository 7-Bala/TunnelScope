# EXP-38 — Why the traffic-type model does not transfer to another lab — RESULT (2026-10-01)

Pre-registration `9d7a03c`, scorer `584da2f` (both committed before the run). Data: `ipsec-pcap-lab` commit `c0cf256`,
`metadata.csv` hash as pinned; 175 known and 29 out-of-distribution captures; 0 read errors. Scores in
`results/summary.json`, per-capture stage and ungated label in `results/captures.csv` (no packet-level data). The
captures were deleted after this file was written. Permission to use the data was relayed verbally by the project
owner ("do whatever you want"); there is still no licence file, so nothing from the captures is redistributed.

## 1. Scores

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P38-1 | The out-of-distribution gate stops >= 80% of the 175 | **23.4%** (41 of 175) | **falsified** |
| P38-2 | The shipped model, ungated, scores macro-F1 < 0.50 | **0.262** (accuracy 0.272, 169 captures that have windows) | held |
| P38-3 | Our features separate their classes (train R01-03, test R05): macro-F1 >= 0.80 | **1.000** (101 train captures, 33 test captures) | held |
| P38-4 | ... across profiles (leave-one-profile-out): mean macro-F1 >= 0.70 | **1.000** (P01..P05 each 1.000) | held |
| P38-5 | Shipped windows + their R01-03 give macro-F1 >= 0.80 on their R05 | **1.000** | held |
| P38-6 | ... and our own grouped cross-validation loses <= 0.02 | 0.9196 -> 0.9222 (**+0.003**) | held |

## 2. Where the 175 captures stopped (the census EXP-37 could not give)

| Stage | Captures | Share |
|---|---|---|
| answered | 5 | 2.9% |
| abstained by the confidence / agreement / mixed-traffic rules (after passing the OOD gate) | **107** | **61%** |
| out-of-distribution gate | 41 | 23% |
| fewer than 3 full windows ("insufficient") | 22 | 13% |

The gate is not the main loss. Most captures get through it and the model is then not confident or not consistent,
which is what a model that does not recognise the traffic looks like. P38-2 agrees: with no gate at all it is right
27% of the time, over-calls video (49 of 169) and voip (34), and names 24 captures "interactive shell", a class this
lab does not have. Loosening the thresholds would turn abstentions into wrong answers, not right ones.

## 3. What the perfect within-lab scores do and do not mean

- They say our 31 window features **can** separate this lab's seven classes, so the failure is in what the shipped
  model was trained on, not in the features. The decision rule in the PREREG for this branch ("shift is real") applies.
- They do **not** show cross-lab generalisation. The classes here come from deliberately distinct generators and are
  easy to tell apart, which the other team's own README implies; R05 shares the lab, the profile set and the
  generators with R01-R03. Leave-one-profile-out removes the cipher/mode/IKE/IPv6/encapsulation confound, and still
  scores 1.000, which is a real result, but it is still one lab.
- The R05 test set has 33 captures (web has only 3 with enough windows); 33 of 33 supports an accuracy above about
  0.9, not 1.0.
- 22 captures never reach the model: 18 of the 25 `web` captures are shorter than three 2-second windows (median
  1 window), plus 3 `file_transfer` and 1 `icmp`. The six that have no window at all are excluded from P38-2..P38-5,
  and the product says "insufficient", which is the right answer for them.
- Exploratory: the inbound-direction features shift most (largest packet size, share of 1024-1600 byte packets, mean
  size, each about +1 training SD), consistent with this lab sending larger inbound packets. Shipped model on the 25
  `ood_eval` captures (DNS-like, SSH-like, gaming-like, database, remote-desktop flows), ungated: 19 called voip, 4
  messaging, 2 web. It names a confident-looking class for traffic that is none of its classes, which is why the
  gates exist.

## 4. What changes

- **No change to what ships.** EXP-37's README sentence stands. The cause is now known: the model underneath does not
  transfer, and the gates are behaving correctly by abstaining.
- **Candidate task (not started):** add this lab's windows to training. P38-5 and P38-6 say it does not hurt our
  in-lab score (+0.003) and fits its own held-out runs. It would still need its own pre-registration and a **third
  lab with different generators** as the test, because this lab can no longer grade a model trained on it. The
  second public set found earlier (`ashwin02-cyber/SIH_2026`) has no licence and no permission, so it needs the same
  request first; the alternative is our own captures with new generators.
- **Do not claim** cross-lab accuracy for traffic type anywhere until that third-lab test exists.
