# EXP-29 — Which IKE implementation is on each end, from the plaintext alone? — PRE-REGISTRATION (2026-09-27, before any feature is looked at)

Owner, 2026-09-27: Batch A, roadmap T-127 (copy Corelight's VPN-provider fingerprinting, bridge its lack of
crypto grading). Owner approved downloads/trials the same day.

## Question
From plaintext only (IKE_SA_INIT payloads, Vendor IDs, notify types and order, proposal structure, and the
T-135 padding signal of encrypted messages), can TunnelScope name the implementation at each end of an SA —
strongSwan, Libreswan, MikroTik RouterOS — and say UNKNOWN otherwise, never naming the wrong one?

## Split (fixed now, by session and software version; features are looked at on TRAIN only)
- **Train:** strongSwan 5.9.8 EXP-01/02 captures (the 12 in `dataset/MANIFEST.csv`); Libreswan 5.4 EXP-07 arms
  `e7-gcm128`, `e7-gcm256`, `e7-cbc128`, `e7-cbc256`, `e7-chacha`; MikroTik RouterOS 7.24.4 EXP-26 M1–M4.
- **Test (held out):** every other capture with an IKE_SA_INIT: strongSwan 5.9.8 (other experiments/sessions)
  and 6.1.0 (EXP-04, EXP-05, EXP-15, EXP-17 IKE, EXP-27); Libreswan EXP-07's other 5 arms **and a new Libreswan
  session captured after the rules are frozen** (lab `lsw-a`/`lsw-b`); MikroTik M5–M8; EXP-10 (strongSwan
  initiator, OpenBSD `iked` responder — no `iked` training data exists, so its end must come out UNKNOWN).
- Synthetic/forged fixtures (`testbed/captures/synthetic/`) are excluded.

## Method
Rules are written from the train set only and frozen in a commit before the test set is scored. The result
is a new finding `implementation` per SA with one value per end (`initiator`, `responder`), status INFERRED
with the matching signals as evidence, or UNKNOWN. Ground truth: the implementation recorded for each capture
(`dataset/MANIFEST.csv` implementation column, EXP-26/27 manifests, the EXP-10 topology).

## Hypotheses and bars
- **H1 (primary):** zero **wrong** labels on the test set (an end labelled as an implementation it is not).
- **H2:** at least 80% of test ends whose implementation was in training get a (correct) label.
- **H3:** the OpenBSD `iked` end in EXP-10 is UNKNOWN.
- **H4:** strongSwan 6.1.0 (a major version not in training) is recognised as strongSwan (counts inside H2),
  reported separately.

## Not changed
No other finding, rule or score changes. The implementation label is informational (it feeds later tasks,
e.g. T-130 vulnerability intelligence), and never raises or lowers a risk verdict on its own.
