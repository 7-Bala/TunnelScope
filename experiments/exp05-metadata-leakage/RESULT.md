# EXP-05 — Metadata Leakage: **TFC padding hides every packet size and buys no protection**

**Date:** 2026-09-12 · **Status:** DONE · **Pre-registration:** `research/registers/EXPERIMENT-REGISTER.md`
("EXP-05 — PRE-REGISTRATION", written before any capture) · **Numbers:** `results/exp05_results.json`
· **Data:** 52 sessions, per-packet tables in `testbed/captures/exp05/*.pkts.csv.gz`, raw pcaps
SHA-256'd in `manifest.csv` · **Code:** `analyze.py`, `testbed/scripts/{tgen.py,run_exp05.sh,gen_exp05_conf.py}`

## Question (CS-01)
How much can a passive observer at the keyless router learn about the *class* of traffic inside an
ESP tunnel, and how much does padding reduce it? The classifier here is a **measuring instrument
for adversary capability**, not a traffic-identification product.

## Setup
strongSwan 6.1.0, AES-GCM-256 tunnel mode, per-arm alias addresses. Five traffic-shape classes from a
seeded generator (voip, web, bulk, interactive, video). Arms: **base** (no padding), **tfc**
(`tfc_padding = mtu`), **mux** (two classes concurrently). 4 repetitions × 5 classes × {base, tfc}
plus 3 class pairs × 4 repetitions for mux, 20 s each. Session order shuffled with a fixed seed.
Features on 2-s windows; evaluation leave-one-repetition-out. **IP-TFS arm dropped:** Docker's
kernel lacks `CONFIG_XFRM_IPTFS` (`testbed/NOTES.md` #13).

## Result

| | **base** | **tfc (pad to MTU)** |
|---|---|---|
| Distinct ESP packet lengths | 244 | **1** |
| MI(class; packet size), bits/packet | 1.006 | **0.000** |
| MI(class; inter-arrival time), bits/packet | 1.007 | **1.006** |
| MI(class; direction), bits/packet | 0.053 | 0.054 |
| Random Forest macro-F1, leave-one-rep-out (complete windows) | **1.000 ± 0.000** | **0.995 ± 0.009** |
| Depth-2 tree ("two-threshold rule") macro-F1 | 0.507 | 0.506 |
| 1-NN error → Bayes-error lower bound (Cover–Hart) | 0.005 → ≥ 0.003 | 0.005 → ≥ 0.003 |
| Permutation null (labels shuffled by session) | 0.122 | 0.136 |
| On-wire bytes vs base | 1.00× | **1.54×** |

Maximum possible MI is log₂5 = 2.32 bits. **Secondary analysis** (all windows, including each
session's final partial window): base F1 0.946, tfc 0.955 — same conclusions (see "What was surprising").

Multiplexing (a single-class model applied to two-class tunnels; hit = top-1 prediction is one of
the two classes present; chance 0.40): **0.655 overall**. voip+web 1.00, bulk+voip 1.00,
**video+interactive 0.00 — labelled "web" in every window.**

## Predictions vs outcome

| # | Prediction | Outcome |
|---|---|---|
| P5-1 | base leaks heavily (F1 > 0.8; size MI > 1 bit) | ✅ F1 1.000; size MI 1.006 bits |
| P5-2 | tfc removes the size channel (size MI ≈ 0) | ✅ exactly 0 — one packet length |
| P5-3 | …but tfc does NOT remove class leakage (F1 > 0.5) | ✅ **stronger than predicted: F1 0.995 — padding changed nothing** |
| P5-4 | multiplexing degrades the adversary | ✅ on average (0.655 vs 1.000), but see below: mixtures can yield *confident wrong* labels |
| P5-5 | metric stable (fold std < 0.1); null ≈ chance | ✅ std ≤ 0.009; null 0.12–0.14 (at or below chance) |

## What worked
- **The controlled contrast is clean.** Same traffic and seeds; only padding differs. Padding drove
  size information to exactly zero and left class inference untouched, because **timing carries the
  same ~1 bit/packet** with or without padding.
- **The measurement is stable and passes its null control.** Fold-to-fold spread ≤ 0.009; shuffled
  labels fall to chance.
- **It produces an operator-meaningful finding no config check can:** *"Your tunnel pads every packet
  to 1480 bytes, which costs 54% more bandwidth, and a passive observer still identifies your traffic
  class 99.5% of the time."*

## What failed / limits — read these before quoting any number
- **The absolute F1 (≈1.0) is NOT a claim about real-world traffic.** The five classes are
  synthetic shape models, deliberately distinct in rate and timing (constant 50 pps VoIP,
  rate-capped bulk, 1-s video segments). Perfect separability is a property of *these shapes*.
  Real traffic overlaps far more. What transfers is the **relative** result (padding vs no
  padding, size vs timing channels) and the **method**; the headline number does not.
- IP-TFS could not be tested (kernel), so constant-rate padding — the countermeasure that *would*
  target timing — remains untested. strongSwan's own docs say Linux AGGFRAG doesn't send at a
  constant rate anyway.
- One implementation, one path, no loss or jitter injected. Timing features may be less clean over
  real WAN paths.

## What was surprising
1. **Padding bought literally nothing.** We predicted "drops but stays above chance"; it didn't drop.
2. **Every error in the first analysis was the same window.** In the all-windows run, every
   misclassification in every fold was window #10 — the final partial window after the generator
   stopped, holding only TCP teardown. That's why base's fold-to-fold F1 was an identical 0.9462.
   Found by inspecting the errors rather than accepting the score; both variants are reported.
3. **Mixtures can produce confidently wrong answers.** A tunnel carrying video + interactive traffic
   was called "web" in 100% of windows. Any product that reports "traffic type inside ESP" as a
   fact would state something false with full confidence. That is the strongest evidence yet for the
   CS-01 reframing: **measure exposure; don't assert identity.**

## Bugs caught and fixed before the final numbers (not result-driven)
- A dry run showed "size MI" of 0.053 bits under TFC padding, where only one packet length exists
  and size MI must be exactly 0. The size bins had been keyed on (direction, size). Each channel is
  now measured alone, and direction is reported separately.
- The partial-final-window artifact (above). The primary analysis uses complete windows; the
  all-windows figures are kept in the results.

## What assumption changed
**AI Necessity, CS-01:** a learned model *is* justified here, for a specific reason: a depth-2 rule
measures only about half the leakage (F1 0.51 vs 0.995). **A weak instrument would understate
exposure by ~50% — a false-assurance failure.** This is the one place in the project where ML
beats the simple baseline by a margin that matters. It's still an instrument; its output is a
leakage figure, not a traffic label.

## What should change
- The metadata-exposure capability reports **bits of leakage per channel** (size / timing /
  direction) plus the adversary-capability estimate and the Bayes-error bound, and **never** a
  traffic-type label for a tunnel as a fact.
- Recommendations must be honest: *padding to MTU hides sizes and does not hide your traffic class
  from a timing-aware observer*. Rate-shaping (constant-rate IP-TFS) is the countermeasure that
  would matter, and it isn't available in mainline Linux AGGFRAG today.
