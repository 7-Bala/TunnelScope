# EXP-39 — Does training on one lab help on another? Leave-one-lab-out, two directions — PRE-REGISTRATION (2026-10-01, before any run)

## Why
EXP-37 found the shipped traffic-type model does not transfer to lab A (`ipsec-pcap-lab`). EXP-38 found the gates are
behaving correctly, the model underneath scores 0.262 on lab A, and our features can separate lab A's classes when
trained inside lab A. Adding lab A to training changed our own cross-validation by +0.003. What EXP-38 could not
show is that training on one lab helps on a *different* one. This experiment tests exactly that, in both directions,
with a second public lab (B) that has different generators. It measures; it ships nothing.

## Data (fixed here; kept outside the repository, deleted afterwards)
Both authors gave the project owner their permission (relayed verbally, 2026-10-01; neither repository has a licence
file). No capture and no packet-level derivative is committed; only aggregate scores are.
- **Lab A**, `naman9271/ipsec-pcap-lab`, commit `c0cf25647b88c1cdb0649a43049e192e269f4cc6`, `pcaps/known`, 175 captures,
  7 classes (email, file_transfer, icmp, messaging, video, voip with RTP audio, web), `metadata.csv` SHA-256
  `81234b73e338a6945af19711e1303ffa0f1b174c0b33d0f139fd5e3e145d8a8c`.
- **Lab B**, `ashwin02-cyber/SIH_2026`, commit `ef0ffe9926ec44e78bb963d55f21f856369d2ba2` (2026-09-28), folder
  `real_captures`, 216 captures, root `manifest.csv` SHA-256
  `244a5e5e49b9ecc8b5d938e9269994b41b0d763e300c237caafba2989fb970fa` (`config_version` v2-pfs-in-esp). The 36
  `handshake` captures are not traffic and are excluded; **180 captures** remain: 36 configurations x 5 classes
  (icmp, file_transfer, web, video, voip), 30 s each, one run per configuration. Generators per its README: icmp =
  10 pings; file_transfer = 10 MB `scp`; web = 30 `curl` GETs; video = ffmpeg test video in 50 KB range requests;
  **voip = 5 SIPp calls, SIP signalling only, no RTP**, so B's voip is not A's voip. Ground truth = its `manifest.csv`
  (the generator's declaration).

## What has been seen before this was written
Lab A: everything in EXP-37 and EXP-38 (stage census, ungated 0.262, within-lab 1.000, the feature shifts). Lab B: its
README, its manifest (classes, configuration grid, row counts) and the generator list above. Not seen: any lab-B
window feature, prediction or stage.

## Method (fixed here)
`analyze.py` takes the record with the most ESP packets per capture, converts it with the shipped `_packets` and
`window_features`, and keeps each capture's reduced ESP packet list (time, source, length) outside the repository.
Models are the shipped forest and gates retrained on different training windows by pointing the shipped
`attacker.DATA` at a temporary `.npz` and clearing the model cache; **no shipped file is edited** and the gate, the
abstain rules (TAU 0.60, consistency 0.70, mixed-traffic check) and `window_features` are the shipped code:
- **M0** shipped windows only.
- **M1** shipped + all 175 lab-A windows (`file_transfer` renamed `bulk`, the shipped name).
- **M2** shipped + all 180 lab-B windows (same renaming).
- **M3** shipped + both (used only for the no-harm check).
Ungated prediction = argmax of the mean window probability of the model's forest. Gated prediction =
`assess_exposure` with that model (its answer, or none). Class mapping: `bulk` = `file_transfer`; any other class
name outside the test lab's list counts as wrong. Metric: macro-F1 over the **test lab's** classes (B: 5, A: 7),
`f1_score(..., average="macro", labels=<test classes>, zero_division=0)`, on captures that have at least one window.
**Coverage** = answered / captures with at least `MIN_WINDOWS` (3) windows; captures with fewer are counted and
reported separately, never dropped silently.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P39-1 | Shipped model ungated on lab B (M0): macro-F1 < 0.60 | >= 0.60 |
| P39-2 | Training on lab A helps on lab B: M1 ungated macro-F1 on B >= 0.60 and >= M0 + 0.15 | either part fails |
| P39-3 | M1 through the shipped gates on B: coverage >= 50% and accuracy among answered >= 0.90 | either fails |
| P39-4 | Training on lab B helps on lab A: M2 ungated macro-F1 on A >= 0.60 and >= 0.262 + 0.15 | either part fails |
| P39-5 | M2 through the shipped gates on A: coverage >= 50% and accuracy among answered >= 0.90 | either fails |
| P39-6 | No harm to our own data: grouped 5-fold CV on the shipped windows (groups = `session`, same forest) loses <= 0.02 macro-F1 when both labs' windows are added to every training fold (M3 vs M0) | loses > 0.02 |
Exploratory, not scored: per-class results; B without voip (SIP is not RTP); the share of captures with under 3
windows per class (icmp and voip are sparse by construction); M3's gated answers on both labs (not a test, M3 has seen
both); the five features with the largest shift of lab B against the shipped windows.

## Reading the result (decided now)
- P39-2 and P39-4 both hold -> learning transfers between labs in both directions; recommend (as a separate task,
  owner decision, own pre-registration, golden/DEC updates) retraining the shipped windows with A and B. Retraining
  leaves no unseen lab to test on, so this experiment's two held-out directions are the evidence, and they are then
  quoted as exactly that.
- Exactly one direction holds -> partial; do not ship; say which.
- Neither -> two more labs do not fix it; do not ship; the README stays as it is.
- P39-6 failing blocks any shipping regardless of the others.
- Every prediction is reported whether or not it holds. Captures are deleted after RESULT.md is written.
