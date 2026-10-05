# EXP-49 RESULT — Analysis throughput on one Mac (T-125), 2026-10-04

Numbers are quoted from `results/summary.json` / `results/scored.json` (harness at commit `d2bd250`, the scored run) and `results/confound.json` (addendum A). Bars and predictions: `PREREG.md`.

## Hardware and what was measured
Apple M4 (10 cores), 16 GB, macOS 27.0.1, Python 3.13.5, TShark 4.6.4, sandbox and CPU limits as the product runs them. **Window analysis only** (`report.analyze` on a capture file, in a
fresh process): the bound on sustained live operation. **No live capture was measured**: `/dev/bpf0` is root-only on this Mac and capture permission was not granted, so nothing here says how many
packets per second `dumpcap` can capture, nor anything about a SPAN or TAP. Traffic is synthetic native ESP over IPv4 (original length 1,400 B, stored 80 B like the headers-only sensor), with
ground truth from the generator; one scenario merges the real handshake of `exp15/s-ecp256.pcap`.
**The machine was not idle:** the one-minute load average was 4.1-4.2 during the first runs and 5.5-6.5 during the later ones; another work session (a Python and a tshark process) was running on this
Mac, which the pre-registration asked to avoid. Absolute times below therefore carry that load (about +-20% between runs of different periods, see the interleaved check).
A smoke run of scenario A up to 10^5 packets preceded the scored run (same harness, same numbers within 3%; its output was deleted).

## Results (median of the repetitions; 3 up to 10^5 packets, 1 above, as pre-registered)
| Scenario | Packets | Wall s | Packets/s | Represented Gbps | Share of time in tshark | Python peak RSS | File |
|---|---|---|---|---|---|---|---|
| A one tunnel | 10^4 | 0.55 | 18,291 | 0.205 | 92% | 55 MB | 1 MB |
| A | 10^5 | 2.45 | 40,753 | 0.456 | 84% | 220 MB | 10 MB |
| A | 10^6 | 30.1 | 33,227 | 0.372 | 60% | 1,772 MB | 96 MB |
| A | 3x10^6 | 92.9 | 32,279 | 0.362 | 74% | 3,725 MB | 288 MB |
| B 1,000 tunnels | 10^6 | 41.0 | 24,372 | 0.273 | 51% | 1,897 MB | 96 MB |
| C real handshake + ESP | 10^5 | 2.97 | 33,714 | 0.377 | 85% | 222 MB | 10 MB |
| D full 1,400 B packets | 10^5 | 2.97 | 33,687 | 0.377 | 85% | 218 MB | 142 MB |

Four `tshark` passes per capture in every run. The largest `tshark` child stayed at about 104 MB. "Represented Gbps" is the sum of the original packet lengths times 8 over the wall time (what the
sensor stands for), not a rate that was carried on any link.

## Bars
- **H1 no silent loss: PASS.** 15 of 15 measured runs (all sizes, all scenarios): the packets the pipeline accounts for (in the SA records, as unique frames, and in `capture_summary`) equal the generator's count exactly,
  and the sum of their IP lengths equals the generator's sum. No packet was lost or double-counted at any size up to 3,000,000 packets (scenario C counts the 54 real ESP packets of the handshake capture too, counted independently of tshark).
- **H2 a timeout is loud: PASS.** With `TUNNELSCOPE_TSHARK_TIMEOUT=2` on 10^6 packets, `tunnelscope analyze` exited with code 2, wrote nothing to stdout, and said `tshark timed out after 2s ... raise TUNNELSCOPE_TSHARK_TIMEOUT if this capture is genuinely large`.
- **H3 a damaged file is flagged: PASS.** Both cuts (inside the last packet; inside the last record header) were flagged `truncated` and the analysis counted 99,999 packets, the whole packets before the cut.
- **H6 nothing else changes: PASS.** `git diff origin/main -- tunnelscope` is empty.

## Predictions
P1 time linear in N between 10^5 and 10^6: **held**, but only just: per-packet time at 10^6 is 1.23 times that at 10^5 (bar 1.25), with one repetition at 10^6 and a different load. P2 30,000-150,000 packets/s
(0.3-1.7 Gbps): **held**, 32,279-40,753 packets/s (0.36-0.46 Gbps) at 10^5 and above. P3 memory above 0.5 KB per packet and above 1.5 GB at 3x10^6: **held**, 1.24 KB per packet, 3.7 GB at 3x10^6.
P4 full packets within 30% of headers-only: **held**. The scored runs showed D 21% slower than A, but C (headers-only plus a handshake) was exactly as slow as D and the load differed; the interleaved check (addendum A:
A, D, A, D, A, D at 10^5 packets, load 3.9-4.1 throughout) gave medians 2.41 s and 2.45 s, a ratio of 1.016. Stored bytes make no measurable difference; the 21% was the machine's load.
P5 tshark more than half of the time: **held** in every run (51-92%); its share falls as N grows because Python's per-packet work grows faster than tshark's.

## What this says (H5, derived, not measured on a link)
- On this Mac one analysis process keeps up with about **32,000-40,000 ESP packets per second** (a 30-second window of about 1,000,000 packets in 30 s), which is **0.36-0.46 Gbps of 1,400 B packets**. It is a per-packet limit:
  at 80 B stored per packet, a link carrying more than about 33,000 ESP packets per second will outrun the analysis, whatever its bit rate. Small packets are the worse case (33,000 packets/s of 100 B is 26 Mbit/s).
- **Memory is the first wall, not time:** about 1.2 KB of Python memory per packet (every ESP packet becomes a dict), so a 30-second window at 33,000 packets/s (1,000,000 packets) needs about 1.8 GB, and the 120-second default tshark
  timeout is far from reached (the 3x10^6-packet file took 93 s in all four passes, each pass well under 120 s). A burst window of 10^7 packets would need about 12 GB, more than this machine's 16 GB leaves free.
- Many tunnels cost more per packet than one (B took 36% longer than A at 10^6 (41.0 s against 30.1 s), one repetition each; the cause was not isolated).
- This is the whole product path, not a Gbps claim about a link: the 1-10-100 Gbit/s "high-speed sensor" of the task text is **not shown, and not close**: this design reaches roughly 0.4 Gbps of represented 1,400 B traffic on one core of this Mac.

## Reported from code reading, not measured: capture-side drops are silent
`tunnelscope/live/live.py` starts `dumpcap` with `-q` and `stdout=DEVNULL`; its stderr is read only if it exits within the first second. A packet that `dumpcap` drops because the kernel buffer filled is therefore not reported
by live mode. The analysis side is not silent (H1-H3); the capture side is, by this reading. Proposed as a separate task (T-165 in TODO), not done here.

## Not shown
Live capture rate, SPAN/TAP, NICs, any Linux server, multi-core or multi-process scaling (the analysis is one Python process; tshark is single-threaded per pass; running windows in parallel could multiply the packet rate and the memory), IPv6, AH, ESP-in-UDP, a
quiet machine (the load above), more than one repetition above 10^5 packets.
