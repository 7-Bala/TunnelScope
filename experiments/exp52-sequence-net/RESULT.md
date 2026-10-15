# EXP-52 — A sequence network trained by us, alone and averaged with the shipped forest — RESULT (2026-10-15)

Pre-registration `48a8307`; scorer `3522974`, then `6988ebb`, `46a9d2d`, `d2b3dca` (each committed before the scoring it affects; see "Deviations").
Scores in `results/partial.json` (every candidate, every held-out family) and `results/choice.json` (the choice rule, the bars, the gate).
Trained on a Colab T4 (`colab_train.py`, the same `netlib.py` as on the Mac); scored on the Mac with EXP-51's own forest code.

## Verdict by the pre-registered ship rule
**Nothing ships.** The rule needed P52-2 (the combination beats the forest by 0.03 on held-out families) and the lab-I bars; P52-1 and P52-2
failed, so no lab I was built. The shipped classifier (R6, DEC-066) and its gate stay as they are. The NumPy inference
(`tunnelscope/leakage/seqnet.py`) was built and tested but nothing calls it.

| # | Prediction | Result | |
|---|---|---|---|
| P52-0 | the scorer reproduces R6 | S0 eight-family mean **0.5606** vs EXP-51's 0.561 | held |
| P52-1 | the network alone carries the signal (>= 0.50) | N1 **0.4789** | **failed** |
| P52-2 | best combination >= R6 + 0.03 held-out | best E2@0.5 **0.5633** (+0.0027); E1@0.25 0.5613 (+0.0007) | **failed** |
| P52-3 | no harm on seen generators (grouped >= 0.96) | S0 0.9879 (the choice is S0) | held |
| P52-4 to P52-7 | lab I and the shipping checks | not run (nothing passed P52-2) | n/a |
| Guard | lab D >= 0.80, lab F >= 0.70 | S0 0.833 and 0.774 | held |

## Candidates (leave-one-family-out session macro-F1; "eight" = EXP-42's original eight families)
| | eight-mean | all-mean | grouped | lab D | lab F |
|---|---|---|---|---|---|
| S0 (R6) | 0.5606 | 0.5662 | 0.988 | 0.833 | 0.774 |
| N1 network, with packet gaps | 0.4789 | 0.4854 | 0.942 | 0.833 | 0.686 |
| N2 network, direction and size only | 0.5191 | 0.5423 | 0.921 | 0.667 | 0.723 |
| E1 (S0 + N1), w = 0.25 / 0.5 / 0.75 | 0.5613 / 0.5571 / 0.5077 | 0.5622 / 0.5562 / 0.5141 | 0.987 / 0.983 / 0.971 | 0.833 | 0.758 / 0.710 / 0.686 |
| E2 (S0 + N2), w = 0.25 / 0.5 / 0.75 | 0.5558 / **0.5633** / 0.5445 | 0.5812 / 0.5804 / 0.5615 | 0.984 / 0.980 / 0.954 | 0.833 / 0.833 / 0.667 | 0.783 / 0.746 / 0.773 |

Chosen by the rule: **S0**, because neither combination beat it by 0.01 (the best gains 0.0027).

## What the numbers say
- **The network alone is worse than the forest** (0.479 against 0.561). It needs more kinds of traffic than these ten families give it, as expected for a
  network trained from scratch on about 30,000 windows.
- **Packet timing hurts the network.** Without the gap channel (N2) it scores 0.519, higher than with it (0.479). That is consistent with EXP-51's finding that a
  model can read link speed as a class signal (the network sees raw gaps); this experiment did not test that explanation directly.
- **Averaging with the forest changes almost nothing** on held-out families (+0.0007 to +0.0027), well inside what a different set of seeds could move.
- **Where it differs, per family** (session macro-F1, forest S0 / network N2): USBVPN 0.030 / 0.170, WireGuard 0.260 / 0.425, lab H 0.467 / 0.694, but
  lab C 0.933 / 0.833, lab tgen 0.745 / 0.596, lab real-apps 0.795 / 0.697, lab E 0.711 / 0.577. The size-only network is better on the hard, unusual families and worse on
  the ones the forest already handles. The eight-family mean rewards neither. A combination that picks per family is a different experiment and would need its own pre-registration
  and a new lab; this result does not show it works.
- **The gate for S0** set by EXP-51's procedure on these predictions (confidence >= 0.65, mixed score < 0.65, no distance cut) reproduces the shipped gate: weighted answered share 0.324, 93.4% of
  answers right, 81.5% of mixed sessions held back. USBVPN: 0 of 994 answered.

## Deviations and incidents
- **Labs A and B** were rebuilt from the packet streams cached by EXP-51 plus the two label files at the pinned commits (the pcap clones were gone and GitHub was too slow to clone again). Counts match EXP-51's: 175 and 180 sessions, none unlabelled.
- **A device bug**: `netlib._dev()` never chose CUDA, so the first Colab run used the CPU (the T4 showed 0%). Found in the first minutes, fixed (`46a9d2d`), and the run restarted from the beginning; nothing from the CPU run was kept.
- **The ingest stage** looked for the window-to-session map in the wrong file; fixed (`d2b3dca`) before any scoring, and `lofo` now refuses to train a fold on the Mac unless asked. One `lofo` start ran by mistake before the fix; it was stopped within seconds and wrote nothing.
- **Colab runtime**: the page lost its link to the runtime twice (the second time during the final download). The training process kept running on the same virtual machine and finished all 32 fold-and-variant runs once each; a copy of the first 25 was saved to the Mac as insurance and was not used.
- **Lab I was not built.** The pre-registration said that if the choice were S0, lab I would still be captured so the RESULT could say whether R6 holds on a new lab. It was not, because nothing could ship and a new lab is a large piece of work; that question stays open (lab G, EXP-51, is the last new-lab test of R6).
- **One architecture, one set of hyperparameters, three seeds.** No tuning was done on held-out scores. A different architecture or recipe needs a new pre-registration.

## What is now used up
Lab G was not touched. No new lab was used. The ten families' held-out scores above are cross-validation numbers.
