# tunnelscope (the analysis engine)

**AI-powered IPsec VPN protocol analysis and security assessment.** The engine behind the dashboard,
the command line and the local server. Project overview: [`../README.md`](../README.md).

TunnelScope reads an IPsec packet capture, or a live stream, and tells you what each tunnel
negotiated, how it measures up against written security standards, and what to change. Every finding
says how it is known (observed, inferred or measured) and from which vantage point, and every verdict
names the rule and the standard behind it.

## What it does

| Capability | How |
|---|---|
| IKE version, exchanges, IKE-SA cipher, integrity, PRF and DH group | plaintext IKE parse |
| ESP cipher family | packet-length structure (IV, ICV and alignment rules) |
| Post-quantum key exchange and downgrade | ADDKE transform and IKE_INTERMEDIATE exchange |
| Perfect forward secrecy | size of the CREATE_CHILD_SA rekey |
| Rekey cadence | time between observed rekeys |
| Tunnel or transport mode | AH next-header field; ESP packet-size analysis |
| Replay behaviour | per-SPI ESP/AH sequence numbers |
| Negotiation-failure diagnosis | message sizes and notify codes |
| Metadata exposure | size and timing entropy, in bits |
| Traffic type inside the tunnel | Random Forest over packet size and timing, with a confidence |
| Mixed-traffic detection | second Random Forest over the first model's per-window probabilities |
| Change and downgrade detection | per-tunnel anomaly model over the tunnel's own history |
| Known-vulnerability patterns | rules over IKE message order and payloads |
| Endpoint cross-check | endpoint telemetry reconciled with the wire findings (`build/02-CROSSTIER.md`) |
| Compliance | versioned YAML baselines: DISA VPN SRG, RFC 8247, RFC 8221/4303, DST/NQM post-quantum |
| Threat matrix and risk score | threats rated by likelihood and impact, one 0-100 score |
| Fixes | remediation plan for every failed rule; automatic apply and verify for strongSwan settings |
| CBOM | CycloneDX 1.6 |
| Evidence ledger | hash-chained findings and verdicts, verifiable later |

## Install

```bash
pip install -e .        # needs Python 3.11+, and tshark on PATH
```

## Use

```bash
tunnelscope analyze  capture.pcap          # evidence records (what was seen, from where)
tunnelscope assess   capture.pcap          # verdicts vs named baselines
tunnelscope explain  capture.pcap          # the verdicts in plain English
tunnelscope cbom     capture.pcap          # CycloneDX CBOM (JSON)
tunnelscope report   capture.pcap          # executive + technical report
tunnelscope ledger   capture.pcap          # tamper-evident evidence ledger
tunnelscope ledger-verify ledger.json      # check the ledger's hash chain
tunnelscope dashboard capture.pcap -o d.html  # self-contained HTML dashboard
tunnelscope crosstier capture.pcap t2.json    # reconcile endpoint telemetry with the wire
tunnelscope fleet captures/ -o fleet.html     # scan a directory: one view, per-tunnel evidence kept
tunnelscope watch capture.pcap --history DIR  # compare a tunnel with its own normal
tunnelscope live --follow DIR              # analyse a live stream window by window
tunnelscope config swanctl.conf            # read a config file: its crypto in the same names as the wire findings
tunnelscope reconcile capture.pcap swanctl.conf --conn NAME   # does the traffic match the config?
tunnelscope analyze  capture.pcap --json   # machine-readable
tunnelscope doctor                         # check the stack
tunnelscope serve                          # local dashboard at http://127.0.0.1:8765
```

`tunnelscope --help` lists every command, including the multi-site `sensor`, `collect` and `sites`.

## Running it unattended

`doctor` verifies tshark is present and exposes every field the extractors read. The same check runs
automatically before any analysis command (once per process; set `TUNNELSCOPE_SKIP_PREFLIGHT=1` to skip it).

Exit codes let a monitoring job tell the cases apart:

| Code | Meaning |
|---|---|
| 0 | ran; nothing to report |
| 1 | ran; FAIL verdicts present (only with `--fail-on-findings`) |
| 2 | input error: capture missing, path absent, no captures in the directory |
| 3 | dependency error: tshark missing or changed |

```bash
tunnelscope fleet captures/ --json --fail-on-findings || alert   # 1 = findings, 2/3 = not scanned
```

`--fail-on-findings` is opt-in. On `fleet` it also trips on captures that failed to parse, and a path
with no captures is an error, so an empty scan is never mistaken for a clean one.
`TUNNELSCOPE_TSHARK_TIMEOUT` (default 120 s) bounds each tshark call. Reads of a capture are cached
on `(path, mtime, size)`; `TUNNELSCOPE_CACHE_CAPTURES` sets how many captures to keep (default 8, `0`
disables), and a capture that changes on disk is re-read.

## Design

A capture goes to **ingest** (tshark), which feeds **extractors** that build one **EvidenceRecord** per
Security Association. Every fact is a `Finding` with a mandatory status (observed, inferred or
measured) and a vantage. The **assessment engine** runs versioned YAML baselines against the records
and produces a verdict per rule. **Scoring**, the **threat matrix**, the **reports**, the **CBOM** and
the **ledger** are all generated from the evidence records. The **remediation** module turns failed
verdicts into plans and, for strongSwan settings, applies and verifies them. Architecture and design
decisions: [`../build/00-ARCHITECTURE.md`](../build/00-ARCHITECTURE.md).

## The models

All models are trained by us and ship as plain arrays; no pretrained or third-party model is used.

- **Traffic type**: Random Forest over 31 numbers per 2-second window (packet counts, sizes, timing
  gaps, size histogram, direction). Predicts voip, web, bulk file transfer, interactive shell, video,
  e-mail, messaging or icmp, with a confidence.
- **Mixed traffic**: Random Forest that picks out tunnels carrying more than one kind of traffic.
- **Tunnel or transport mode**: Random Forest over the share of ACK-sized packets.
- **Change detection**: Isolation Forest plus rules and robust statistics, per tunnel.

## Vantage tiers

Each finding states the vantage that produced it: T0 (the encrypted packets), T1 (plus the plaintext
handshake), T2 (endpoint telemetry), T3 (keys), T4 (active probing). T0 and T1 need nothing but a
capture; T2 adds the endpoint cross-check.

## Tests

```bash
python3 -m pytest tests/ -q        # unit and ground-truth tests
python3 dataset/validate.py        # dataset integrity (hashes, provenance, splits)
python3 build/validate_e2e.py      # every capture against its ground truth
```
