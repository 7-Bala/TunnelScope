# EXP-32 — Site sensor: how fast does a downgrade reach the central view, and does anything else leave the site? — PRE-REGISTRATION (2026-09-27, before the code and any run)

## Why
A jury member's concern (owner, 2026-09-27): if a customer has to upload captures somewhere to get an audit, the
business is exposed for as long as that takes (detection delay) and audits must not disturb service (downtime).
T-139: a passive sensor at each site analyses locally and sends only signed findings reports to a central
collector, continuously. This experiment measures what that delivers in the live lab.

## System under test (design fixed here)
- `tunnelscope sensor` (site): the existing live pipeline (`--follow DIR` of rotating capture files, or
  `--interface`), local anomaly history, one report per analysed window, and a heartbeat report when no window
  was analysed for one window length. Reports: allow-listed fields only (tunnel addresses, IKE SPIs, posture,
  failed rule ids, findings status/value, gaps, anomalies, alerts, risk score); never packet bytes. Signed with
  HMAC-SHA256 (per-site key, Python standard library), monotonically increasing sequence number, written
  atomically to an outbox directory.
- Transport: files (outbox -> collector inbox by any file transfer; in the lab the outbox IS the inbox). No
  network listener is added; the server stays 127.0.0.1-only.
- `tunnelscope collect` (central): verifies signature, schema and sequence; rejects tampered, unknown-site and
  replayed reports (quarantined with the reason); updates per-site state; appends alerts tagged with the site.
- A site with no report for 3 of its declared windows is shown "stale: no data since ..., posture UNKNOWN".

## Lab protocol
Window W = 10 s (sensor `--window 10`, router `tcpdump -G 10` on the alice side of the router, IKE/NAT-T/ESP only).
Continuous pings through t-tun (alice-pq 10.10.1.210 -> bob-pq 10.10.2.210, every 0.5 s) so files rotate.
Collector polls its inbox every 1 s. States of t-tun (both ends, EXP-18's seeding code):
A = `proposals = aes256-sha384-ecp384-ke1_mlkem768` (post-quantum); B = `proposals = aes256-sha384-ecp384`
(classical). **10 cycles**: A (initiate), wait 2W; A again (initiate), wait 2W; B (initiate) = the change, time
t_change taken just before B's initiate; wait until the collector has recorded a downgrade or new-failure alert for
the tunnel or 6W passed. Latency = collector's record time of the first such alert - t_change.
Mid-run, once: the collector is stopped for >= 3W and restarted (reports wait in the inbox).

## Hypotheses and bars
- **H1 detection:** all 10 changes produce a central alert (10/10).
- **H2 latency:** median <= W + 10 s (20 s) and max <= 2W + 15 s (35 s). Expected from the design: a change is
  seen when its window closes (<= W) plus analysis and the 1 s poll.
- **H3 no false alerts:** 0 alerts attributed to windows with no change to B (A->A and B->A are not downgrades).
- **H4 nothing lost:** every sequence number the sensor wrote is accepted exactly once by the collector,
  including across the collector outage.
- **H5 nothing else leaves:** 100% of report files pass the strict allow-list validator; none contains a pcap
  magic number or any string longer than 300 characters.
- **H6 integrity (unit tests, not the lab):** a report with one changed byte, an unknown site, and a replayed
  sequence number are each rejected.
Downtime is not measured as a hypothesis: the sensor only reads files a capture process writes; it has no path
to the tunnel. Ping loss over the run is reported for completeness.

## Rules
Scored by `analyze.py` in this folder from the run's raw log (`results/raw.jsonl`), the sensor outbox listing,
the collector state and quarantine. No bar changes after this commit; RESULT.md quotes analyze.py only;
deviations are dated addenda before the runs they govern.
