# EXP-43 — Lab D, the final untouched test: does EXP-42's chosen model beat the shipped one on traffic nobody trained on? — PRE-REGISTRATION (2026-10-02, after EXP-42's selection, before any lab-D capture)

## Why
EXP-42 chose K4 (v2 rhythm and shape features, family and class balancing, size/time augmentation, RandomForest) by
leave-one-family-out, where it beat today's recipe by 0.043 on average. Those numbers chose the model; they cannot grade it,
because the same eight families were looked at to choose. Lab D was specified in EXP-42's PREREG (`bad8196`) before any score
existed, and nothing from it has been trained on or tuned against. Only this result may be quoted as "accuracy on traffic it has
never seen", and only this result decides whether K4 replaces the shipped model.

## Lab D (fixed)
Image `sih26-labd`; hosts behind the strongSwan 6.1.0 gateways; capture at the keyless router, ESP headers only; per-packet tables
committed, pcaps hashed. Tools, all absent from every training family: bulk `aria2c` (8 connections, 1 MB/s cap) from
`lighttpd`; web `httrack` (depth 4, 2 connections, 300 KB/s) on a 40-page/60-asset site; video GStreamer `videotestsrc
pattern=snow` -> x264 900 kbit/s -> RTP/UDP one way; voip GStreamer G.711 PCMU 20 ms RTP both ways; messaging IRC (`ngircd`,
`ii` clients on both sides, 15-155 byte messages every 0.8-5.8 s); email `msmtp` -> OpenSMTPD; interactive `mosh` with
human-paced typing (90-390 ms per key); icmp `fping -l -p 1000`. Two ESP suites never used in any family: **ChaCha20-Poly1305**
(IKE AES-GCM-256/PRF-SHA384/ECP-384) and **AES-256-CBC + HMAC-SHA-384** (IKE MODP-3072). The router adds `netem delay 15ms 5ms
loss 0.2%` both ways. 8 classes x 2 suites x 2 repetitions x 60 s = **32 captures**. Ground truth: the generator that ran, and
`swanctl --list-sas` per suite.

Seen before this was written: an 8-20 s smoke test of each tool for packet counts, directions and sizes (to make the tools
work: lighttpd's index file, OpenSMTPD's recipient, IRC message newlines and join wait, mosh's TERM, locale, terminal size and
spawn quoting were fixed then). No model output on lab D exists.

## Models (fixed)
- **S** = the shipped model, through the shipped product path (`assess_exposure` on each capture's ESP packets).
- **K4** = v2 features, every session of the eight EXP-42 families (sessions with at least 3 windows) plus their two augmented
  copies, family/class balanced weights, `RandomForestClassifier(n_estimators=200, random_state=0, min_samples_leaf=2)`. Its
  gate is the shipped logic applied to K4: out-of-distribution if fewer than half the windows are within the 99th percentile
  nearest-neighbour distance of K4's standardised training windows; then answer only if the mean top probability >= 0.60, at
  least 70% of windows agree, and the shipped mixed-traffic check (order-free statistics of the probabilities) does not flag it.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P43-1 | The shipped model does not generalise to lab D: S ungated macro-F1 < 0.60 | >= 0.60 |
| P43-2 | K4 beats it: K4 ungated macro-F1 >= S + 0.10 | < +0.10 |
| P43-3 | K4's answers stay trustworthy: accuracy among K4's gated answers >= 0.90, and K4 gives at least as many correct gated answers as S | either fails |
| P43-4 | The gain does not depend on one cipher: K4 >= S on each suite separately (ChaCha20 and AES-CBC/SHA-384) | K4 < S on either |

## Ship rule (decided now)
K4 replaces the shipped model only if **P43-2 and P43-3 both hold**. Then: `window_features` becomes v2 in the product, the
training build uses the eight families, the abstain thresholds stay as they are, the findings differential and all checks are
run, and DEC/README record the lab-D number as the accuracy on unseen traffic. The shipped training file must stay under 5 MB
and train in under 5 s at startup; if K4's full training set does not, a reduced set (fewer windows per session, or float16) is
allowed only if its lab-D ungated macro-F1 is within 0.02 of K4's, measured once and reported. If the rule is not met, nothing
ships, the README says what was learned, and the shipped model stays. Lab D's sessions are never added to training in this
experiment. Every prediction is reported whether or not it holds.
