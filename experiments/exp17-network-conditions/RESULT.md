# EXP-17 — Network conditions: delay, jitter and packet loss — RESULT (2026-09-21)

Pre-registration: `PREREG.md`. Numbers: `results/exp17_results.json`.

| # | Prediction | Result | Held or FAILED |
|---|---|---|---|
| P17-1 | Shipped classifier, wan profile, sessions pooled: window-level macro-F1 ≥ 0.70 | macro-F1 0.5257 (syn 0.5453, real 0.5308; bulk 0.0189, email 0.3733, icmp 1.0000, interactive 0.7904, messaging 0.8293, video 0.0000, voip 0.6936, web 0.5000) | FAILED |
| P17-2 | Shipped classifier, lossy profile, sessions pooled: window-level macro-F1 ≥ 0.50 | macro-F1 0.3802 (syn 0.4235, real 0.3440; bulk 0.0000, email 0.1071, icmp 0.9524, interactive 0.5038, messaging 0.6267, video 0.0000, voip 0.5556, web 0.2963) | FAILED |
| P17-3 | Retrained with impaired repetitions added (LORO over 3 impaired reps): macro-F1 ≥ 0.90 on both profiles | wan mean 0.9533 (rep1 0.9313, rep2 0.9559, rep3 0.9726), lossy mean 0.8398 (rep1 0.8089, rep2 0.8412, rep3 0.8692) | FAILED |
| P17-4 | Safety: ACK-size mode model calls zero tunnel-mode sessions transport on both profiles, Parts A and B | 0 transport answers (wan: 8 tunnel, 40 abstained; lossy: 12 tunnel, 36 abstained; total transport 0) | Held |
| P17-5 | Mixed-traffic detector wrongly flags ≤ 15% of single-class impaired sessions | wan flagged share 0.3333 (16/48), lossy flagged share 0.2083 (10/48) | FAILED |
| P17-6 | IKE under loss: 100% match on encryption, DH group and integrity; zero CVE-2026-78135 detection | 0 mismatches, 0 CVE FAIL (wan: 5 established, 5 PASS; lossy: 5 established, 5 PASS) | Held |

## Counts
- Sessions: 96 (48 wan, 48 lossy)
- IKE bring-ups: 10 (5 wan, 5 lossy)

## Warnings
None

## Not concluded
See the reviewer's interpretation below.


## Reviewer's interpretation

**Outcome: 2 of 6 predictions held (P17-4, P17-6); 4 failed (P17-1, P17-2, P17-3, P17-5). Nothing was tuned.**

- **Safety held.** P17-4: no tunnel-mode session was called transport under delay and loss. Caveat: the mode model answered only 8 of 48 wan sessions and 12 of 48 lossy sessions and abstained on the rest, so this shows it stays safe by staying silent, not that it works under loss. P17-6: IKE reading matched swanctl on all 10 bring-ups (5 wan, 5 lossy) and the CVE detector raised no false alarm.
- **The traffic classifier does not survive impairment.** The shipped model scored 0.526 (wan, delay 40 ms +/- 10 ms, 0.5% loss) and 0.380 (lossy), against 0.986 on clean lab data. Bulk and video collapse to about 0 F1 (bulk 0.019 / 0.000, video 0.000 / 0.000); icmp stays near 1.0. Delay and retransmissions change timing and packet sizes that the model relied on.
- **Adding impaired data helps a lot but not enough on lossy.** With impaired repetitions in training, macro-F1 reaches 0.953 on wan (above the 0.90 threshold) but 0.840 on lossy (below it). P17-3 requires both, so it is recorded as FAILED, although the wan half would have held on its own.
- **The mixed-traffic detector over-flags under impairment.** 33.3% (wan) and 20.8% (lossy) of single-class sessions were wrongly flagged mixed, against the 15% limit (8.3% on clean data).
- **What this means for claims.** Accuracy numbers (0.986, 1.000 on Libreswan) apply to a clean lab LAN only. On delayed or lossy links, a model trained on clean data is not reliable, and training on impaired traffic from the target network is what recovers accuracy. This supports the "learn on site" direction and removes any basis for claiming field accuracy.

## Process note

The run log shows one `FATAL: apps-b is not listening on port 5222` line, between the synthetic part (Part A) and the real-application part (Part B). The task said to stop and report FATAL and not repair the lab; the agent started the application servers itself (`apps_server_setup.sh`) and the run then completed. The final data set is consistent: 96 sessions, 24 per arm, no duplicate tags, 10 IKE bring-ups, netem removed afterwards, run script and PREREG.md unchanged, and the analysis reproduces byte-identically. But Part B was not captured in one uninterrupted run as pre-registered, so a rerun of the whole experiment is the way to remove that doubt.
