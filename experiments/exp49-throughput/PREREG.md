# EXP-49 — Analysis throughput on one Mac (T-125) — PRE-REGISTRATION (2026-10-04, before any measurement)

## Why, and what this can and cannot say
T-125 asks for a "high-speed live sensor ... Benchmark in Gbps on stated hardware; no dropped-packet silent errors". TunnelScope's live and site-sensor paths hand each
closed capture window (ring files written by `dumpcap`, or a directory another sensor fills) to the normal analysis: several `tshark` passes over the file plus Python
(`report.analyze`). Nothing here has ever been timed. Two limits are fixed before starting:
1. **No live capture is measured.** On this Mac `/dev/bpf0` is root-only (no ChmodBPF); granting capture permission is a system change that is not made. So no
   statement is made about how many packets per second `dumpcap` can capture on any interface, nor about a SPAN or TAP. The measurement is of the **window analysis**:
   how fast TunnelScope turns a capture window into findings, which is the bound on sustained live operation (windows are analysed one after another).
2. **Traffic is synthetic where it must be**, with known ground truth: packets written by a generator we control (`gen.py`), ESP between fixed host pairs, original
   length 1,400 B stored to 80 B like the shipped headers-only sensor (DEC-044; the pcap record keeps the original length). It is not a statement about any real link.

## Hardware and software (recorded by the harness, quoted from `summary.json`)
Apple M4, 10 cores, 16 GB, macOS 27.0.1; Python 3.13.5; TShark 4.6.4; the repository at the commit recorded in the summary; sandbox as the product runs it (`sandbox-exec`,
`RLIMIT_CPU`); nothing else heavy running (Docker Desktop stopped for the run if it is the only other load; the load average before each size is recorded).

## What is measured (fixed here)
Harness `bench.py`; every measurement is a **fresh Python process** running `tunnelscope.report.analyze(pcap)` (the function the live window and `analyze` use), reporting wall
seconds, the seconds spent inside `tshark` passes (sum of `_run_fields` calls, and their number), peak resident memory of the Python process and of the largest `tshark`
child (`getrusage`). Throughput: packets/s, file MB/s, and **represented on-wire Gbps** = sum of the pcap records' original lengths x 8 / wall seconds.
- **Scenario A (one tunnel):** N ESP packets, two directions, one SPI each, sequence numbers 1..N/2 per direction, one address pair, 50,000 packets/s of capture time.
  N = 10^4, 10^5, 10^6, 3x10^6. Headers-only (stored 80 B, original 1,400 B). Repetitions: 3 up to 10^5, 1 from 10^6 (stated, because of run time).
- **Scenario B (many tunnels):** N = 10^6 headers-only ESP packets spread over 1,000 host pairs (one SPI pair each). 1 repetition.
- **Scenario C (handshake + ESP):** the real IKE_SA_INIT/IKE_AUTH of `testbed/captures/exp15/s-ecp256.pcap` merged (mergecap) in front of scenario A, N = 10^5, 3 repetitions.
- **Scenario D (full packets):** scenario A at N = 10^5 with the 1,400 B stored whole, to show whether stored bytes matter (3 repetitions).
- **Loud failure (H2):** scenario A at N = 10^6 with `TUNNELSCOPE_TSHARK_TIMEOUT=2` through the CLI (`tunnelscope analyze`).
- **Damaged file (H3):** scenario A at N = 10^5 cut inside its last packet, and cut inside its pcap record header.

## Predictions (written now, to be checked, not assumed)
P1 time is linear in N within +-25% between 10^5 and 10^6 packets. P2 the whole analysis runs at 30,000 to 150,000 packets/s on this machine, which at 1,400 B represented
is 0.3 to 1.7 Gbps. P3 peak resident memory of the Python process grows with N (every ESP packet becomes a Python dict) at more than 0.5 KB per packet, so 3x10^6 packets
needs more than 1.5 GB. P4 full packets (D) cost within 30% of headers-only (C-like) time at the same N (tshark reads the bytes but the fields are the same). P5 `tshark`
passes are the larger part of the time (more than 50%).

## Bars
- **H1 (no silent loss, the T-125 acceptance):** at every size and scenario, the number of ESP packets the pipeline accounts for (the sum of `len(record._esp)` over the SA
  records returned by `build_records`, and the number of SA records) equals what the generator wrote, exactly, and the sum of their IP lengths equals the generator's sum
  of original lengths (minus the 14-byte Ethernet header). One difference fails H1 and is reported with the size.
- **H2 (a timeout is loud):** the CLI run with the 2-second timeout exits non-zero, names the timeout on stderr and writes no analysis output.
- **H3 (a damaged file is flagged, not trusted):** both cut files: the analysis reports `capture_truncated` (or exits with an error naming the damage), and when it
  analyses, the packets it counts equal the number of whole packets before the cut.
- **H4 (measured, no bar):** the table of the results above, with the predictions P1-P5 each marked held / not held.
- **H5 (derived, labelled as derived):** from H4, the highest packet rate a 30-second live window can be analysed in less than 30 s (so the sensor keeps up), and what that is
  in represented Gbps at 1,400 B per packet. Reported with the assumption it rests on (windows are analysed sequentially, one process).
- **H6 (nothing else changes):** the product code is untouched by this experiment (only files under `experiments/exp49-throughput/` and the registers/TODO change);
  `git diff origin/main -- tunnelscope` is empty.

## Reported from code reading, not measured
`live.py` starts `dumpcap` with `-q` and discards its output (`stdout=DEVNULL`); its error text is read only if it exits in the first second. So packets `dumpcap` drops
because the kernel buffer filled are not reported by live mode. This is read from the source and is the gap behind "no dropped-packet silent errors" for the capture
side; closing it is a separate task, not part of this experiment.

## Not claimed (fixed here)
Live capture rate on any interface; behaviour on a Linux server, a NIC, SPAN/TAP, 10/40/100 Gbit links; multi-process or multi-core scaling (the analysis is one Python
process; `tshark` is single-threaded per pass); IPv6, AH or ESP-in-UDP traffic; the cost of the traffic classifier on long flows beyond what `analyze` runs.
