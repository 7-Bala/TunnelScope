# EXP-52 — A sequence network trained by us, alone and averaged with the shipped forest — PRE-REGISTRATION (2026-10-15)

Written before any sequence network is trained, before any candidate in this file is scored, and before lab I exists.

## 1. Question
Does a small neural network that reads each window's raw packet sequence (direction, size, gap), trained from scratch on our own
families, classify traffic better than the shipped forest (R6, DEC-066), on its own or averaged with it?

## 2. Why now (owner, 2026-10-15)
The owner asked how to improve accuracy, was told that EXP-42 had already tried gradient boosting (K6, 0.437 against the forest's 0.455
leave-one-family-out) and that the only model type different enough to matter is one that reads the raw sequence, and chose "the forest
plus sequence network", approving PyTorch as a dependency. Known weak spots of R6 that a sequence model might reach, from EXP-51's
RESULT: live HTTP video called web (4 of 4 on lab G), messaging called interactive (2), and families unlike the training data
(USBVPN held out 0.030).

## 3. What stays fixed
- Data: the families R6 trains on, loaded by `build/models/corpus.py` and EXP-51's loaders (EXP-42's eight, lab E, lab H), same
  sessions, same labels, same mixed sessions.
- Windows: exactly the windows R6 scores (`tunnelscope.leakage.attacker.window_features`: 2-s buckets, complete windows, >= 3 packets).
  Every candidate scores the same windows, so per-window and per-session scores are comparable row for row.
- Session label: the mean of window probabilities, as R6 does.
- Evaluation: EXP-51's leave-one-family-out session macro-F1, its "eight" mean over EXP-42's original families, grouped-by-session, and
  the lab-D and lab-F guards (spent labs, development only). R6 is re-run by the same scorer as row S0 and must reproduce EXP-51's R6
  (eight mean 0.561) within 0.005, or the scorer is wrong and nothing below is scored.
- Gate: EXP-51's procedure (thresholds set from pooled leave-one-family-out predictions, the loosest at which held-out answers are at
  least 90% right), re-run for the chosen candidate. No hand tuning.

## 4. The sequence input (fixed here)
Per window, the packets in time order, each as three numbers: direction (+1 out, -1 in), log2(IP length) / 11, and
log10(gap to the previous packet in the window, in seconds, floored at 1e-6) / 6 (first packet: 0). A window longer than 256 packets is
cut to 256 by keeping evenly spaced packets (the first and last always kept); a shorter one is padded with zeros and a mask.
No count, rate or session-level number is added: the network sees only the sequence.

## 5. The network (fixed here)
A 1D-CNN: three convolution blocks (64, 64, 128 channels, kernel 5, batch norm, ReLU), masked mean and max pooling over the sequence,
one hidden layer of 64, softmax over the eight classes. Class weights as R6 (balanced by family and class). Adam, learning rate 1e-3,
batch 256, 30 epochs, early stopping on a validation split taken from the TRAINING families only (10% of their sessions, by session),
patience 5. Three seeds per fold; the three seeds' probabilities are averaged. Trained with PyTorch on this Mac's GPU (Apple M4, MPS);
if a fold does not finish, CPU, and the RESULT says which.

Augmentation, fixed: each training window is also used once with all gaps scaled by one factor drawn log-uniformly from 0.8 to 1.25
(R6's own mild copies). EXP-51's wide speed copies (1/8 to 8) are not used: they failed P51-2.

## 6. Candidates
| | What | Why |
|---|---|---|
| S0 | R6 as shipped (DEC-066), re-run | baseline, scorer check |
| N1 | the network of section 5 alone | does the sequence carry more than v2's 46 numbers? |
| N2 | N1 with the gap channel set to 0 (direction and size only) | EXP-51 found rate leaking into class; is timing helping or hurting the network? |
| E1 | average of S0 and N1 probabilities, weight w on the network | the owner's choice: forest plus sequence network |
| E2 | average of S0 and N2 probabilities, weight w on the network | |

w for E1 and E2 is the one of {0.25, 0.5, 0.75} with the highest leave-one-family-out eight mean, chosen inside the scorer and reported
for all three values.

## 7. Lab I, the only test that can ship anything
Built after the candidate is chosen and fixed in a commit; captured after that; scored once. Same gateways and router capture point as
labs C to H. Tools not used in labs A to H (the generator's commit lists them and the RESULT checks them against every earlier lab's tool
list). Link profiles not used before: 10 Mbit/s with 80 ms delay and 1% loss; 200 Mbit/s with no shaping. **At least 8 single sessions
per class (64 or more), at least 16 mixed.** Lab G is spent and is not used for any decision.

## 8. Predictions and bars
| # | Prediction | Bar |
|---|---|---|
| P52-0 | The scorer reproduces R6 | S0 eight mean within 0.005 of 0.561 |
| P52-1 | The network alone carries the signal | N1 eight mean >= 0.50 |
| P52-2 | The combination beats the forest on unseen families | best of E1/E2 eight mean >= S0 + 0.03 |
| P52-3 | No harm on seen generators | chosen grouped-by-session >= 0.96 |
| P52-4 | Lab I, ungated | chosen >= S0 + 0.05 session macro-F1 on lab I |
| P52-5 | Lab I, gated | >= 90% of answers right AND answered share >= S0's answered share on lab I (S0 with its shipped gate) |
| P52-6 | Lab I, mixed | >= 80% of mixed sessions not answered with a single label |
| P52-7 | Shippable without PyTorch | the shipped inference is NumPy only; on every lab-I window its probabilities equal PyTorch's within 1e-4; model file <= 5 MB; scoring one 2-s window takes <= 5 ms on this Mac |
| Guard | Labs D and F (spent) | chosen ungated >= 0.80 on D and >= 0.70 on F |

**Choice rule:** among E1 and E2 (at their chosen w) that pass P52-3 and the guard, the higher eight mean; if neither beats S0 by 0.01
the choice is S0 and lab I is still captured and scored for S0 alone, so the RESULT says whether R6 holds on a new lab.
**Ship rule:** P52-2, P52-4, P52-5, P52-6 and P52-7 all hold. Otherwise nothing ships, R6 stays, and the RESULT says so.

## 9. What is shipped if the rule holds
The network's weights as a NumPy file in `tunnelscope/models/`, inference written in NumPy inside `tunnelscope/leakage/` (no `torch`
import anywhere in the `tunnelscope` package; a test enforces it). PyTorch is a training-only dependency, in a `train` optional extra.
The gate is the one section 3's procedure gives for the chosen candidate.

## 10. Not in this experiment
Pretrained traffic models (DEC-006). Recurrent or transformer networks (one architecture is fixed so the comparison is clean; if the
1D-CNN fails P52-1 the RESULT says so and a different architecture needs a new pre-registration). Per-site calibration and large-scale
traffic generation (options discussed with the owner, separate experiments).
