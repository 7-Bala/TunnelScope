# EXP-41 — A third lab with sustained traffic and new generators — RESULT (2026-10-02)

Pre-registration `a4521a2` (erratum `3b9a94c`), scorer and harness `d6f43e8`, lab-C data `f5c9c3f`: all committed before any scoring. Lab C is
32 captures (8 classes x 2 tunnel configurations x 2 repetitions, 60 s each, per-packet tables in `testbed/captures/exp41/`). Labs A and B
were re-downloaded at the pinned commits and manifest hashes, then deleted. Scores in `results/summary.json`; per-capture window counts in
`results/captures.csv`.

## 1. Scores

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P41-1 | Shipped model does not transfer: M0 ungated macro-F1 on C < 0.70 | **0.442** (accuracy 0.531) | held |
| P41-2 | Lab C's classes are separable by our features (train repetition 1, test repetition 2) macro-F1 >= 0.90 | **1.000**, every class 1.000 (16 train, 16 test captures) | held |
| P41-3 | Training on lab A helps: M1 >= M0 + 0.10 | M1 0.468, gain **+0.026** | **falsified** |
| P41-4 | Adding lab B helps: M3 >= M0 + 0.10 | M3 0.468, gain **+0.026** | **falsified** |
| P41-5 | M3 through the gates: coverage >= 50% and accuracy >= 90% | coverage **12.5%** (4 of 32), all 4 correct | **falsified** (coverage) |
| P41-6 | Reverse: M4 (shipped + C) on lab A >= 0.362 | **0.245** (shipped alone: 0.262) | **falsified** |
| P41-7 | No harm to our own data when A, B and C windows are added: CV loses <= 0.02 | 0.9196 -> 0.9206 (**+0.001**) | held |

## 2. What it shows

- **Per class, on lab C (macro-F1 by class):** the shipped model is right for **bulk 0.80, e-mail 1.00, voip 1.00**, partly for messaging
  0.40 and web 0.33, and wrong for **icmp 0.00, interactive 0.00, video 0.00**. Lab A's windows lift web to 0.50 and messaging to 0.44 and
  change nothing else. Where it fails, it fails completely for the class, not diffusely.
- **The classes are learnable.** Trained inside lab C the same features give 1.000 (P41-2), as they did inside lab A (EXP-38). So the missing
  thing is not a feature: it is that each lab's tool puts a class into a different shape, and a model trained on other tools' shapes does not
  know this one. Likely, untested: C's ping is 228-byte echoes every 0.7 s, its interactive session is telnet over a pty with human-paced typing,
  and its video is one-way MPEG-TS over UDP, none of which resembles what the model learned for those names.
- **More labs of the same kind do not close it.** Adding 2,362 lab-A windows and 511 lab-B windows moved lab C's score by 0.026, and adding
  lab C moved lab A the wrong way (0.262 to 0.245). Lab B's windows are in the forest (they change 53 of lab C's 775 window predictions, by up to
  0.235 in probability) but do not flip a single whole-capture prediction, so M1 and M3 coincide.
- **The cipher alone moves the shipped score:** M0 is 0.468 on the GCM captures and 0.396 on the CBC ones (exploratory, same traffic shapes,
  different per-packet overhead).
- The decision rule written in advance applies: neither P41-3 nor P41-4 holds and P41-2 holds, so **do not retrain on the public labs**; the gap is
  specific to each lab's generators. The README states this. No model, gate or threshold was changed.

## 3. Deviations and limits, stated plainly

1. **One capture was replaced, for a lab fault.** `gcm-icmp-rep2` came out with 4 packets instead of about 166 because the gateway sent an ICMP
   Redirect for the first forwarded packet and `ping` stops on it. It was re-run once with the same harness and again got 4 packets, so I found the
   cause (the redirect) and disabled redirect sending on both gateways through the compose file. It then gave 168 packets. This was done before any
   scoring and without looking at any model output. The other 31 captures were taken before that change; their packet counts per class are tight
   (bulk 33,518-33,835; video 6,185-6,250; voip 6,019-6,021; icmp 166-168), so none was cut short by it, and the host's routing never changed (it
   stayed via the tunnel gateway).
2. **Smoke test.** Before the PREREG, each class ran for 8 seconds so the packet counts and sizes could be checked (disclosed in the PREREG). The
   bulk rate was changed from 20 to 5 Mbit/s between that test and the real run, as the PREREG states.
3. **Thin per class:** 4 captures per class, 2 configurations, one tunnel stack (strongSwan 6.1), one network. A single wrong capture moves a class's
   F1 a lot; the per-class numbers above are coarse. The headline findings (P41-2 at 1.000, the +0.03 gain) are not close to any bar.
4. P41-6's bar was built from EXP-39's measurement of the shipped model on lab A (0.262); this run reproduced it (0.2619).
5. M0 on the GCM captures alone (0.4681) equals M1 on all captures (0.4681). Two different quantities; M0 by configuration was recomputed
   independently (all 0.4417, GCM 0.4681, CBC 0.3955), so it is a coincidence, not a wiring fault.
6. Labs A and B are other teams' data used with their authors' verbal permission; nothing from them is committed. Lab B contributes windows only for
   icmp, web and a few for video (EXP-39).

## 4. What changes

- **README:** one sentence on this result in the honest-limits paragraph. Nothing ships.
- **If the traffic-type claim is to improve,** the data that helps is data with each class's real shapes from many tools, not more of the same
  labs; and any model retrained on lab C has no unseen lab left to be tested on. A fourth lab would be needed before such a model could be quoted.
- Lab C stays in the repository (image, generators, harness, data) as a repeatable test bed: `testbed/scripts/run_exp41.sh`.
