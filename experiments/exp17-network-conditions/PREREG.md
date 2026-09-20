# EXP-17 — Network conditions: delay, jitter and packet loss — PRE-REGISTRATION (2026-09-20, before capture)

Every capture so far was taken on a Docker LAN: sub-millisecond delay, no loss, no jitter. A real link
has all three. EXP-16 showed that accuracy tracks how closely training traffic resembles the target;
network conditions are the next thing that changes traffic without changing the application. This
experiment measures how much, and whether the safety properties survive.

## Design
`tc netem` on the router's egress on BOTH interfaces (eth0 and eth1), so each direction is impaired and
the round trip sees double. Capture stays at the router, `-s 96`, as in EXP-15/16.

| Profile | Per-direction impairment | Round-trip effect |
|---|---|---|
| `wan` | delay 40 ms, jitter 10 ms, loss 0.5% | about +80 ms RTT |
| `lossy` | delay 80 ms, jitter 20 ms, loss 2% | about +160 ms RTT, retransmissions visible |

- **Part A (synthetic):** the 8 generator classes through the strongSwan `t-tun` tunnel, 3 repetitions per
  class per profile (48 sessions, 20 s).
- **Part B (real applications):** the 8 real-application classes of EXP-16 through the `e16` tunnel, 3
  repetitions per class per profile (48 sessions, 20 s).
- **Part C (IKE robustness):** 5 tunnel bring-ups per profile with the whole exchange captured (IKE + ESP),
  checked against swanctl's own output. Packet loss makes IKE **retransmit**, which repeats message IDs;
  this is the one place where a detector built on message IDs (CVE-2026-78135) could misfire.

The classifier under test is the **shipped** one (trained without any impaired data).

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P17-1 | Shipped classifier, `wan` profile, sessions of Parts A and B pooled: window-level macro-F1 **≥ 0.70** | < 0.70 |
| P17-2 | Same, `lossy` profile: macro-F1 **≥ 0.50** (degradation expected, retransmissions change timing) | < 0.50 |
| P17-3 | Retrained with the impaired repetitions added to the training set (leave-one-repetition-out over the 3 impaired repetitions; all earlier data always in training): macro-F1 **≥ 0.90** on both profiles | < 0.90 on either |
| P17-4 | **Safety:** the ACK-size mode model calls **zero** tunnel-mode sessions "transport", on both profiles, Parts A and B (all sessions are tunnel mode) | any tunnel session called transport |
| P17-5 | Mixed-traffic detector wrongly flags **≤ 15%** of single-class impaired sessions (its rate on clean data was 8.3%) | > 15% |
| P17-6 | **IKE under loss:** on every bring-up that establishes, IKE encryption, DH group and integrity read by TunnelScope equal swanctl's, on **100%** of runs, and the CVE-2026-78135 detector reports **no detection** on any run | any mismatch or any detection |

## Rules for this experiment
- Whatever fails is reported as failed. No profile is re-run to improve a number.
- Bring-ups that fail to establish under loss are reported as a count, not dropped silently.
- No threshold, model or rule is changed in response to these results inside this experiment; a change
  needs its own dated addendum and a decision-log entry.
