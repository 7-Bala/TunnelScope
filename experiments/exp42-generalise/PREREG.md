# EXP-42 — Make the traffic classifier generalise to generators it has never seen — PRE-REGISTRATION (2026-10-02, before any leave-one-family-out number, the baseline's included)

## Why
EXP-37, 38, 39 and 41 showed the traffic-type model is near perfect inside any one lab and weak on any lab it has not seen
(0.26 on lab A, 0.44 on lab C), and that adding two more labs of the same kind did not help. The owner asked for the model
to be "accurate" and to "detect everything correctly". The honest form of that goal is: **raise accuracy on traffic from
generators the model has never seen, while it keeps saying "uncertain" when it does not know.** Nothing here changes what
the product claims until a final, untouched test (lab D, EXP-43) says so. Levers L3 to L6 of `build/14-ACCURACY-PLAN.md`
(never run until now) are what is tested.

## Data: eight families, each held out in turn (fixed here)
Loaded by `build/models/corpus.py` (T-156) as raw per-session packet streams; a family is one source of generators.
`lab-tgen` (EXP-05/15/16-Libreswan/17-synthetic, 360 sessions), `lab-real-apps` (EXP-16/17 real applications, 160),
`vnat` (MIT LL, OpenVPN, 82; use cleared, DEC-052), `usbvpn` (USBVPN2022 L2TP-IPsec, 1,118), `wireguard` (real people,
1,267; nDPI "web" excluded as in the shipped model), `lab-a` (ipsec-pcap-lab `c0cf256`, 175), `lab-b` (ashwin02 SIH_2026
`ef0ffe9`, 180 traffic captures, few usable windows), `lab-c` (EXP-41, 32). Labs A and B: other teams' data used with
their authors' permission relayed by the owner; kept outside the repository. Sessions with fewer than 3 two-second windows
are never scored (the product's own floor) and are counted.

## Measure (fixed here)
For each family F: train on every other family, predict each F session as the argmax of its mean window probability,
score **session-level macro-F1 over F's classes**. Primary metric = **mean over the eight families**; also reported: the
worst family, the grouped-by-session score (all families pooled, 5 folds), and the leaky random-window score (only to show
the inflation, never quoted).

## Candidates (fixed here; one change at a time, then combined)
| ID | Features | Training | Model |
|---|---|---|---|
| K0 | v1 (the shipped 31) | as is | RandomForest, shipped settings |
| K1 | v1 | **balanced**: every family carries equal total weight, classes equal within a family | RF |
| K2 | v1 | K1 + **augmentation**: each training session also enters twice more with a constant size offset drawn from [-40, +80] bytes and a time scale drawn from [0.8, 1.25] (seeded), so the model cannot lean on one tunnel's exact overhead or one generator's exact pace | RF |
| K3 | **v2** = v1 + rhythm and shape features (below) | K1 | RF |
| K4 | v2 | K1 + K2 | RF |
| K5 | v2 | K1 + K2 | ExtraTrees (same tree count and leaf size) |
| K6 | v2 | K1 + K2 | HistGradientBoosting (scikit-learn defaults, balanced weights) |

**v2 adds, per window:** packets and bytes per second; upload share of bytes; how often consecutive packets change direction;
per direction the share of packets within 8 bytes of the session's largest packet in that direction and the coefficient of
variation of inter-arrival times; the size entropy over 16 bins of 100 bytes; the strongest rhythm (peak of the normalised
autocorrelation of 10 ms packet counts at lags 10-200 ms) and its lag; the share of packets less than 5 ms after the previous
one; and the mean of packets-per-second, bytes-per-second and upload share over the two windows on each side (context). No
feature uses the label, the family, the cipher or anything the product cannot compute from the ESP packets it already reads.

## Selection rule (fixed here)
The chosen candidate has the highest mean leave-one-family-out macro-F1, provided (a) its worst family is no more than 0.05
below K0's worst family and (b) its grouped-by-session score is no more than 0.02 below K0's. If two candidates are within
0.01 of each other, the simpler one (earlier in the table) is chosen. The chosen candidate is then trained on all eight
families and is the only one taken to lab D.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P42-1 | K0 (today's recipe) generalises poorly: mean leave-one-family-out macro-F1 < 0.60 | >= 0.60 |
| P42-2 | Balancing alone helps: K1 mean >= K0 mean + 0.03 | < +0.03 |
| P42-3 | Augmentation helps: K2 mean >= K1 mean + 0.03 | < +0.03 |
| P42-4 | The new features help: K3 mean >= K1 mean + 0.03 | < +0.03 |
| P42-5 | The chosen candidate beats K0 by >= 0.10 mean macro-F1 | < +0.10 |
| P42-6 | Nothing is bought by hurting known traffic: the chosen candidate's grouped-by-session score is within 0.02 of K0's | worse by > 0.02 |

## Final test (EXP-43, lab D; its own pre-registration after selection and before any lab-D capture)
A fourth lab of ours with tools in none of the families above: bulk = `aria2c` multi-connection download from `lighttpd`;
web = `httrack` copying a static site from `lighttpd` with a throttle; video = GStreamer H.264 over RTP/UDP; voip = GStreamer
G.711 (PCMU) RTP both ways, 20 ms; messaging = IRC (`ngircd`, scripted clients both ways); email = `msmtp` to `opensmtpd`;
interactive = `mosh`; icmp = `fping`. Two ESP suites not used before (ChaCha20-Poly1305; AES-256-CBC with HMAC-SHA-384) and a
delayed, slightly lossy path (netem on the router). Only lab D's number may be quoted as "accuracy on traffic it has never
seen"; the leave-one-family-out numbers here choose the model, they do not grade it. If a tool cannot be made to run, the
replacement is recorded before capture.

## What would change in the product
Only after EXP-43, and only if the chosen candidate beats the shipped model on lab D: `window_features` (if v2 wins), the
training data build (`build/models/make_traffic_data.py`), the abstain thresholds re-checked on the leave-one-family-out
predictions, the findings differential explained, a DEC entry. Every prediction above is reported whether or not it holds.
