# TunnelScope

**AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework** (NTRO).

An evidence-tiered, vantage-aware IPsec/IKE observability and posture-assessment engine. Built on a
research-first Double Diamond process: every capability is placed on record as observable,
measurable, inferable, or not recoverable — before it's built — and every verdict names the standard
it's judged against and admits what it couldn't see.

## Quick start

```bash
./start.sh          # checks the stack, builds the dashboard if needed, starts the engine, opens it
./start.sh --dev    # same, plus hot-reload dev server
./start.sh --live-follow DIR   # also analyse a live stream (files a sensor rotates into DIR)
./start.sh logs     # live logs (also in ./logs/)   ·   ./start.sh stop   ·   ./start.sh status   ·   ./start.sh test
.venv/bin/tunnelscope report <capture.pcap>     # after ./start.sh has created the .venv
.venv/bin/tunnelscope config <swanctl.conf|ipsec.conf>   # read a config file offline: its crypto in the same names as the wire findings
.venv/bin/tunnelscope reconcile <capture.pcap> <config> --conn <name>   # does the traffic match the config? (exit 3 on a mismatch)
TUNNELSCOPE_NETWORK=on .venv/bin/tunnelscope intel <capture.pcap>   # known CVEs (NVD, EUVD, CISA KEV) for the VPN software seen
.venv/bin/tunnelscope export <capture.pcap> --format ecs      # SIEM export: one Elastic ECS JSON event per verdict (--format syslog = RFC 5424; --bulk-index NAME = Elasticsearch _bulk); --format zeek = Zeek tunnelscope.log; --format eve = Suricata EVE-shaped JSON
.venv/bin/tunnelscope live --follow DIR --history H --alerts alerts.jsonl --alert-format ecs   # live alerts as ECS (jsonl and syslog also; Filebeat or rsyslog ships the file)
```

## Repository map

| Path | What's there |
|---|---|
| [`TODO.md`](TODO.md) | The live task tracker — status, evidence, and what's next |
| [`research/`](research/README.md) | Discover → Define → Exit Review → existing-solutions deep dive |
| [`testbed/`](testbed/TOPOLOGY.md) | Docker IPsec lab (strongSwan classical + PQ, keyless passive vantage) |
| [`experiments/`](experiments/RESULTS.md) | Experiment results against the research hypotheses |
| [`report.md`](report.md) | Original problem-statement selection study (2026-08-29) |
| [`handoff/`](handoff/README.md) | Task prompts, review criteria, and agent handoff documentation |
| [`tunnelscope/`](tunnelscope/README.md) | Core Python analysis engine, rule baselines, evidence extraction, CLI and API |
| [`fleet-dashboard/`](fleet-dashboard/README.md) | React + TypeScript frontend dashboard for tunnel visualization |
| [`dataset/`](dataset/README.md) | Tracked pcaps, metadata manifest, and dataset validation tooling |
| [`build/`](build/00-ARCHITECTURE.md) | Architecture documentation, validation scripts, and diff guard checks |

## Status

The tool is built and operating as a passive IPsec analysis and posture assessment framework, checked by 392 unit tests, 60 browser checks and a dataset of 103 hash-verified captures. Current task tracking and the active roadmap are maintained in [`TODO.md`](TODO.md).

Core capabilities:
- Ingests IKE key-exchange handshakes and ESP/AH packets from pcap files or live network streams via tshark.
- Labels every finding with an explicit certainty tier (OBSERVED, INFERRED, MEASURED, UNKNOWN, or NOT_OBSERVABLE), ensuring unknown properties are never scored as safe.
- Judges observed facts against written cryptographic and posture baselines (DISA VPN SRG, RFC 8247, RFC 8221/4303, post-quantum readiness, and the CVE-2026-78135 pattern).
- Builds a threat matrix of 12 threats, each rated by likelihood and impact and tied to the evidence behind it.
- Computes an overall tunnel risk score on a 0–100 scale paired with an evidence-confidence metric.
- Predicts encrypted traffic categories using an in-house trained Random Forest model with its confidence.
- Detects behavioral anomalies and configuration drift from historical tunnel norms, such as cipher downgrades.
- Exports executive summaries, technical reports, and CycloneDX Cryptographic Bills of Materials (CBOM).
- Writes a tamper-evident evidence ledger (`tunnelscope ledger`): every finding and verdict hash-chained to the capture's SHA-256, so any later edit, deletion or reordering is detected (`tunnelscope ledger-verify`, optionally by re-running the analysis). It proves the record was not altered; it does not prove the analysis was right.
- Hosts a self-contained local web dashboard for interactive capture analysis.
- Fixes a failed rule and proves it, or undoes it: in the Docker lab, or (DEC-063) on a real strongSwan gateway over SSH. Before a real gateway can be changed, a named person accepts written terms and risks for that gateway (`tunnelscope gateway terms` / `accept`, or the dashboard), and every change needs the exact per-change sentence the preview shows. The same steps run on the gateway: dry run on copies, a load test in an isolated namespace on the gateway itself, baseline capture, backup plus a watchdog timer on the gateway, apply, fresh capture and forced rekey, else automatic byte-for-byte rollback. Proven end to end against two real strongSwan gateways reached only over SSH (`testbed/live-gateway/`, 22 checks, and a real-browser test).
- Every finding, verdict, score and posture judgment is made on your machine from the capture alone; no capture ever leaves it. The network is ON by default (DEC-045) for two extras only: known vulnerabilities for the fingerprinted VPN software (NVD, ENISA EUVD, CISA KEV, with MITRE ATT&CK/CAPEC names on each threat), looked up on every analysis and shown next to the verdicts without changing any of them, and optional remediation drafting by outside models (Groq, then Gemini, DEC-041), whose drafts are re-verified before anything runs. Only software names and lab rule/config text are sent. For an air-gapped install set `TUNNELSCOPE_NETWORK=off` and use an offline bundle made with `tunnelscope intel-bundle`. See `.env.example`.

## Honest limits

- The traffic-type model guesses what kind of traffic is inside the tunnel from packet sizes and timing (DEC-054). It is trained on eight families of traffic whose generators all differ: our lab generator and lab applications, real OpenVPN tunnels (MIT LL VNAT), real L2TP-IPsec tunnels (USBVPN2022), real people's WireGuard traffic, two other teams' public IPsec labs (with their authors' permission), and a third lab of ours. On lab D, a lab built afterwards with tools, ciphers (ChaCha20-Poly1305, AES-CBC/SHA-384) and a delayed, lossy path that no training family used, it scores **0.83 macro-F1** where the previous model scored 0.42, and every one of the 11 answers it gave was right (EXP-43, pre-registered). It is still wrong on interactive sessions there (0 of 4), and lab D is small (4 captures per class) and was built on our own gateways. Holding a whole family out of training (EXP-42) it averages 0.455, so traffic unlike all eight families can still be misread: that is when it says "uncertain". Earlier models and their numbers: EXP-19/20 (real public traffic), EXP-37 to EXP-41 (other labs).
- Tunnel/transport mode, the ESP key length, and how the peers authenticated cannot always be read from a capture. The tool says "unknown" when it cannot tell.
- Whether a receiver drops replayed packets is not visible from a capture.
- Drafting fixes with a model is opt-in (`TUNNELSCOPE_GENERATOR=1`) and did not meet its pre-registered ship bar (at least 0.80 confirmed, lower bound at least 0.60): the on-device model (MiniCPM5-2B) confirmed 0 of 16 (EXP-18, DEC-035) and is never downloaded by TunnelScope; the cloud chain confirmed 12 of 16 (Groq) and 13 of 16 (Gemini) (EXP-18b, DEC-041) and runs with 2 critique rounds (DEC-047), using the operator's own API keys. Every draft is re-checked by code, dry-run and verified live with automatic rollback, and only on the Docker lab; the hand-written fixes need no model.
- Everything was measured on one lab, two IPsec implementations (strongSwan, Libreswan), no real WAN.
- Live gateway fixes (DEC-063) are tested on real strongSwan gateways in network namespaces on one host, not yet on a production site, a vendor appliance, or anything but strongSwan's swanctl. That test host's kernel has no ESP, so its gateways use strongSwan's userspace ESP; the IKE handshake the fix changes and verifies is the real one. Each check restarts the tunnel for a few seconds, and a change that the other end cannot accept keeps the tunnel down until the rollback (seconds, or 180 s via the watchdog if TunnelScope loses contact).

## How it was validated

- `exp01-cipher-sieve`: EXP-01 — ESP cipher-family sieve: **PARTIAL**, it narrows to a 5–6-member ambiguity class, not the 2 predicted ([`experiments/RESULTS.md`](experiments/RESULTS.md))
- `exp02-negative-control`: EXP-02 — AES-128/256 negative control: **PASS**, the ESP-length sets are identical between the two key lengths ([`experiments/RESULTS.md`](experiments/RESULTS.md))
- `exp03-pfs-signature`: EXP-03 — PFS length signature: **CONFIRMED**, CREATE_CHILD_SA size differs with and without PFS by a 256-byte gap ([`experiments/RESULTS.md`](experiments/RESULTS.md))
- `exp04-pq-length-asymmetry`: EXP-04 — PQ key-exchange observability: **CONFIRMED, and exceeded**, 4 independent deterministic signals found ([`experiments/RESULTS.md`](experiments/RESULTS.md))
- [`exp05-metadata-leakage`](experiments/exp05-metadata-leakage/RESULT.md): EXP-05 — Metadata Leakage: **TFC padding hides every packet size and buys no protection**
- [`exp06-failure-diagnosis`](experiments/exp06-failure-diagnosis/RESULT.md): EXP-06 — Failure-Mode Diagnosis: Round 1 Result — **INCONCLUSIVE (testbed design flaw found)**
- [`exp07-libreswan-generalization`](experiments/exp07-libreswan-generalization/RESULT.md): EXP-07 — Cross-Implementation (Libreswan 5.4): **protocol facts hold; two signals are implementation-dependent**
- [`exp08-mode-inference`](experiments/exp08-mode-inference/RESULT.md): EXP-08 (T-044 / A7) — Tunnel vs Transport mode inference: **NOT-OBSERVABLE at T0**
- [`exp09-early-childsa-cve`](experiments/exp09-early-childsa-cve/RESULT.md): EXP-09 (T-022) — Passive detection of the CVE-2026-78135 pattern (early Child SA before auth)
- [`exp10-openbsd-iked-generalization`](experiments/exp10-openbsd-iked-generalization/RESULT.md): EXP-10 — Cross-Implementation (OpenBSD `iked` 7.9): a genuine third, independent codebase; core signals hold, one real diagnostic gap found
- [`exp11-auth-method-inference`](experiments/exp11-auth-method-inference/RESULT.md): EXP-11 (T-048) — Peer auth-method inference (R7/OQ-05): the disposition was half wrong, caught before shipping
- [`exp12-rekey-cadence`](experiments/exp12-rekey-cadence/RESULT.md): EXP-12 (T-048) — Rekey-cadence measurement (R9/R12): built, validated, and it found a real security-relevant bug
- [`exp13-cloud-vpn-proposals`](experiments/exp13-cloud-vpn-proposals/RESULT.md): EXP-13 — Cloud-VPN-style proposal sets — RESULT (2026-09-19)
- [`exp14-mode-size-floor`](experiments/exp14-mode-size-floor/RESULT.md): EXP-14 — Tunnel/transport mode — RESULT (2026-09-20)
- [`exp15-traffic-classes-suites-ah`](experiments/exp15-traffic-classes-suites-ah/RESULT.md): EXP-15 — Eight traffic classes, IKE/DH suites, AH — RESULT (2026-09-20)
- [`exp16-real-apps-cross-impl`](experiments/exp16-real-apps-cross-impl/RESULT.md): EXP-16 — Real applications, cross-implementation, mixed detector — RESULT (2026-09-20)
- `exp17-network-conditions`: no result yet

## Why "TunnelScope"

The project's core idea isn't guessing what's inside an encrypted tunnel — it's being honest about
what can actually be seen from each vantage point (passive capture, IKE visibility, endpoint
telemetry, keys, authorized active probing), and building a real assessment on top of only that.
"Scope" names the instrument; the tiers are the discipline behind it.

## Licence

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE) (copyright and the attributions for the vulnerability
and ATT&CK/CAPEC data TunnelScope uses).
