# EXP-38 — Why the traffic-type model does not transfer to another lab — PRE-REGISTRATION (2026-10-01, before any run)

## Why
EXP-37 found the shipped traffic-type model answered 5 of 175 captures from `ipsec-pcap-lab` and was wrong all 5.
It could not say why. Three different causes need three different fixes:
1. a gate is too strict (the out-of-distribution gate, or the abstain rules) and the model underneath would do fine;
2. the model does not generalise to another lab's generators, but our features can separate their classes;
3. our features cannot separate their classes at all.
This experiment separates them. It changes nothing that ships: no model, gate or threshold is edited.

## Data and permission (fixed here)
`naman9271/ipsec-pcap-lab`, commit `c0cf25647b88c1cdb0649a43049e192e269f4cc6`, `metadata.csv` SHA-256
`81234b73e338a6945af19711e1303ffa0f1b174c0b33d0f139fd5e3e145d8a8c`. Sets used: `pcaps/known` (175 captures: 7 classes
x 5 profiles x 5 runs) and `pcaps/ood`. Ground truth = the generator's own `canonical_label` (a declaration, not an
endpoint log). The repository has no licence file; the owner told ours, and the project owner relayed on 2026-10-01,
that we may "do whatever we want" with it. That is a verbal permission, not a licence. So: captures stay outside the
repository, nothing derived from them that could be turned back into packets is committed, and redistribution waits
for something in writing. Their own split is used as published: R01-R03 train, R04 validation (unused here, nothing
is tuned), R05 locked test.

## What was seen before this was written
EXP-37 output on these captures: the shipped model committed on 5 of 175 (all wrong), the single capture inspected
(`voip_p01_R05`) was reported out-of-distribution, and the abstain note text. Not seen: window features, ungated
predictions, which gate stopped which capture, any within-lab model.

## Method (fixed here)
`analyze.py` builds records with the shipped `build_records`, takes the record with the most ESP packets, converts
packets with the shipped `_packets` and `window_features` (so features are exactly the product's), then:
- **Stage census** with the shipped `assess_exposure`: per capture, which of {insufficient windows, out-of-distribution,
  abstained by TAU/consistency/mixed, answered} applies.
- **Ungated shipped model**: the shipped forest (`_model()` first element), window-level `predict_proba`, capture
  label = argmax of the mean probability over all windows, no gate, no abstain.
- **Within-lab models**: `RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=-1, min_samples_leaf=2)`
  (the shipped settings) on their windows, capture label by mean probability.
- Class mapping: our `bulk` = their `file_transfer`; our `interactive` and `icmp`/`email`/`messaging` names are
  taken as they are; a prediction of `interactive` is wrong for every one of their classes. Metric: macro-F1 over
  their 7 classes, `sklearn.metrics.f1_score(..., average="macro", labels=<7 classes>, zero_division=0)`.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P38-1 | The out-of-distribution gate is what stops most captures: `in_distribution_share < 0.5` for >= 80% of the 175 known captures | < 80% |
| P38-2 | The shipped model itself does not transfer: ungated capture-level macro-F1 on the 175 known captures < 0.50 | >= 0.50 (then gating, not the model, is the main loss) |
| P38-3 | Our features separate their classes inside their lab: train R01-R03, test R05, capture-level macro-F1 >= 0.80 | < 0.80 (then stop: do not train on their data) |
| P38-4 | And across their profiles: leave-one-profile-out over P01-P05, mean capture-level macro-F1 >= 0.70 | < 0.70 |
| P38-5 | Adding their R01-R03 windows to the shipped training windows gives macro-F1 >= 0.80 on their R05 | < 0.80 |
| P38-6 | ...without hurting us: grouped 5-fold cross-validation on the shipped windows (groups = the shipped `session` column, same forest) loses <= 0.02 macro-F1 when their R01-R03 windows are added to every training fold | loses > 0.02 |
Exploratory, not scored: the five features with the largest median standardised shift between their windows and the
shipped windows; what the ungated model says on the 25 `ood_eval` captures; per-profile numbers.

## Reading the result (decided now)
- P38-3 falsified -> our features cannot separate their classes: report it, do not add their data, and say so in the README.
- P38-3 holds and P38-2 falsified -> the gate (P38-1) is the loss: open a separate, pre-registered task to recalibrate it.
- P38-3 holds and P38-2 holds -> the shift is real: P38-5 and P38-6 decide whether adding their lab to training is
  safe. Even if both hold, adding data to the shipped model is a separate task with its own pre-registration and a
  third lab to test on (EXP-38 cannot grade a model it trained on its own test set).
Every prediction is reported whether it holds or not. Captures are deleted after RESULT.md is written.
