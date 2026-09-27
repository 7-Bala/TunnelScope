# EXP-32 — Site sensor: detection latency and what leaves the site (T-139) — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (4acdf78, before the code and any run). Code c77deaf, harness and analysis 3d5f467,
both before the run. One run, live lab, W = 10 s. Scored by `analyze.py` -> `results/summary.json`.

## Headline
**All pre-registered bars hold.** Each of 10 post-quantum -> classical changes on the live tunnel reached the
central collector as an alert in **7.6-10.3 s (median 8.9 s)**, with no false alerts, no report lost across a
30 s collector outage, and only allow-listed findings leaving the site.

| Hypothesis | Bar | Result |
|---|---|---|
| H1 detection | 10/10 | **10/10** |
| H2 latency | median <= 20 s, max <= 35 s | **median 8.885 s, max 10.34 s** (10.34, 8.89, 8.88, 8.94, 7.6, 10.15, 7.58, 10.13, 7.61, 7.57) |
| H3 false alerts | 0 | **0** of 11 alerts outside a change (10 PQ downgrades + 1 first-time rule failure, cycle 1) |
| H4 nothing lost | each sequence accepted once | **56 written (1-56), 56 accepted, last 1-56, 0 missing, 0 quarantined, inbox empty** |
| H5 allow-list | 100% | **56/56 valid**, no pcap magic, largest report 6,279 bytes |
| H6 integrity | unit tests | changed byte, unknown site, replay each rejected (`tests/test_sensor.py`; 8 mutation checks caught) |

Collector outage: stopped at +223 s, restarted at +253 s (30 s = 3W) during cycle 5; cycle 5's change was then
detected in 7.6 s. No heartbeat reports were needed (pings kept every window busy).

## What this does and does not show
- Latency is bounded by the window: a change is seen when its capture file closes (<= W), then analysis and the
  1 s poll. W = 10 s here; the default is 30 s, so expect up to about a window plus a few seconds in production.
  File transfer between site and centre was a local move here; a real transfer adds its own delay.
- One lab, one tunnel, one kind of change (PQ loss). Other alert kinds use the same path.
- Ping loss: the ping summary line was lost (ping was killed, not stopped), so no loss figure is reported. The
  sensor only reads files a capture process writes; it has no path to the tunnel.

## Disclosed after the run
- Harness bug: its log of the collector's output lines crashed on the first line (a result field named `kind`
  clashed with the logger's parameter), so `raw.jsonl` holds 0 such lines. The collector itself was unaffected. H4
  is scored from the collector's persisted state and quarantine, both named as sources in the PREREG; `analyze.py`
  says so, and `run_exp32.py` has the logger fixed for any later run.

## Decision
DEC-043.
