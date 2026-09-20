# Experiments and lab rules (apply when editing experiments/** or testbed/**)

- **Pre-register first.** A `PREREG.md` with a table of numbered predictions and "falsified if" columns
  must be committed BEFORE any capture for that experiment. Do not run a capture before that commit exists.
- Report every prediction as it came out. A failed prediction stays failed. Never re-run a capture to get a
  better number. Never change a threshold after seeing results without a dated "Addendum" saying so.
- Never edit `results/*.json` by hand. They are written by the experiment's `analyze.py`.
- Evaluation is always leave-one-repetition-out (all windows of a session stay in one fold).
- Lab: `cd testbed && docker compose up -d <services>`. Containers: `sih26-router` (keyless capture point),
  `sih26-alice-pq`/`sih26-bob-pq` (strongSwan gateways), `sih26-apps-a`/`-b` (real app hosts behind them),
  `sih26-lsw-a`/`-b` (Libreswan). Capture only at the router. Router `eth0` faces 10.10.2.0/24, `eth1` faces 10.10.1.0/24.
- Captures: `*.pcap` under `testbed/captures/exp05|exp15/traffic|exp16|live` are gitignored (large); the small
  per-packet tables `*.pkts.csv.gz` and `manifest.csv` are what get committed.
- Only lab-generated traffic against lab servers. No third-party websites, accounts or personal data.
- Ask before pulling any Docker image or downloading any dataset over 500 MB.
- Do not use a dataset with no licence file without written permission from its owner.
