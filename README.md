# TunnelScope

**AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**
Smart India Hackathon 2026 · SIH26160 · NTRO

TunnelScope reads IPsec traffic, from a packet capture or a live sensor feed, and tells you what each
tunnel actually negotiated, how it measures up against security standards, and what to change. It
works passively: it needs no VPN keys and decrypts nothing.

## What it does

**Reads the tunnel**
- IKE version (v1 and v2), ESP or AH, SPIs, and the full life of every security association: setup,
  rekey and teardown
- IKE cipher, integrity algorithm, PRF and Diffie-Hellman group
- ESP cipher family, tunnel or transport mode, IPv4 and IPv6
- Perfect forward secrecy, rekey timing and ESP sequence-number (replay) behaviour
- ML-KEM post-quantum key exchange, and post-quantum downgrades (offered but not chosen)
- Traffic patterns that match known IPsec vulnerabilities

**Judges it**
- A rule engine checks every finding against written baselines: DISA VPN SRG, RFC 8247, RFC 8221 and
  RFC 4303, and a post-quantum readiness baseline. Each verdict cites the rule behind it.
- A threat matrix rates each threat by likelihood and impact and links it to its evidence.
- One 0-100 risk score comes with the drivers behind it.
- Every finding is tagged with how it is known: observed, inferred or measured.

**Uses AI where it helps**
- Random Forest models we trained ourselves predict the type of traffic inside an encrypted tunnel
  (web, video, voice, messaging, e-mail, file transfer, interactive sessions and more) from packet
  size and timing, with a confidence for each prediction.
- A second model detects tunnels that carry a mix of traffic.
- Anomaly detection compares each tunnel with its own history and flags cipher changes and downgrades.

**Fixes what it finds**
- Every failed check gets a remediation plan: what is wrong, which standard says so, and the exact change.
- For weak strongSwan settings it can apply the fix itself. The change is checked against an allowlist,
  tried on a copy, applied, confirmed with a fresh capture, and rolled back automatically if anything
  breaks. Every step goes into an audit log.

**Reports**
- Dashboard for single tunnels, fleets of tunnels and live traffic
- Executive summary and technical report
- CycloneDX cryptographic bill of materials (CBOM) for post-quantum migration planning
- Tamper-evident evidence ledger: every finding is hash-chained to the capture's SHA-256, and
  `tunnelscope ledger-verify` detects any later change
- Config check: compares a strongSwan or Libreswan configuration with what appeared on the wire

## How it works

```
pcap / live stream → tshark → evidence records → rule engine + AI models
                   → threat matrix, risk score → reports, CBOM, ledger, dashboard, fixes
```

| Part | Technology |
|---|---|
| Packet reading | tshark |
| Analysis engine, rules, CLI | Python, YAML rule files |
| Models | scikit-learn Random Forests |
| Dashboard | React and TypeScript |
| Lab | Docker: strongSwan, Libreswan, OpenBSD iked |

## Quick start

```bash
./start.sh          # checks the stack, builds the dashboard if needed, starts the engine, opens it
```

The dashboard opens at http://127.0.0.1:8765. Drop in a capture to see its findings.

```bash
./start.sh --dev                  # also run the dashboard dev server with hot reload
./start.sh --live-follow DIR      # also analyse a live stream (files a sensor rotates into DIR)
./start.sh status | logs | stop   # manage the running engine
```

## Command line

```bash
.venv/bin/tunnelscope report <capture.pcap>      # executive and technical report
.venv/bin/tunnelscope assess <capture.pcap>      # verdicts against the baselines
.venv/bin/tunnelscope explain <capture.pcap>     # the verdicts in plain English
.venv/bin/tunnelscope cbom <capture.pcap>        # CycloneDX cryptographic bill of materials
.venv/bin/tunnelscope ledger <capture.pcap>      # tamper-evident evidence ledger
.venv/bin/tunnelscope ledger-verify <ledger>     # check a ledger's hash chain
.venv/bin/tunnelscope fleet <directory>          # one view across many captures
.venv/bin/tunnelscope watch <capture.pcap> --history DIR   # compare a tunnel with its normal behaviour
.venv/bin/tunnelscope live --follow DIR          # analyse a live stream window by window (or --interface IFACE)
.venv/bin/tunnelscope config <swanctl.conf|ipsec.conf>                 # read a config file
.venv/bin/tunnelscope reconcile <capture.pcap> <config> --conn <name>  # does the traffic match the config?
.venv/bin/tunnelscope doctor                     # check the analysis stack
```

`tunnelscope --help` lists everything, including the multi-site `sensor`, `collect` and `sites` commands.

## Repository map

| Path | What is there |
|---|---|
| [`tunnelscope/`](tunnelscope/README.md) | Analysis engine, rule baselines, evidence extraction, models, CLI and local server |
| [`fleet-dashboard/`](fleet-dashboard/README.md) | React and TypeScript dashboard |
| [`testbed/`](testbed/TOPOLOGY.md) | Docker IPsec lab: strongSwan (classical and post-quantum), Libreswan, OpenBSD iked, and the capture scripts |
| [`dataset/`](dataset/README.md) | Captures with ground truth, a hashed manifest and validation tooling |
| [`experiments/`](experiments/RESULTS.md) | One folder per experiment, each with its pre-registration, analysis and result |
| [`research/`](research/README.md) | Domain research, design decisions and registers |
| [`build/`](build/00-ARCHITECTURE.md) | Architecture notes and the check scripts |
| [`TODO.md`](TODO.md) | Task tracker and changelog |

## Testbed and dataset

The Docker lab produces captures with known configuration, so every analysis can be checked against
what was actually set. It covers tunnel and transport mode, AES-128 and AES-256 in CBC, CTR and GCM,
ChaCha20-Poly1305, MODP and elliptic-curve groups, Curve25519, ML-KEM-768, PFS on and off, IPv4 and
IPv6, and AH, with real applications running through the tunnels. Captures are hashed in
`dataset/MANIFEST.csv`, and the correct answer for each one comes from the VPN endpoint's own logs.

## Why "TunnelScope"

A scope is an instrument for seeing what is in front of you. TunnelScope shows what a tunnel is really
doing and gives every result its evidence.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
