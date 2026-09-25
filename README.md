# TunnelScope

**SIH26160 — AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework** (NTRO).

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
- Hosts a self-contained local web dashboard for interactive capture analysis.
- Runs entirely offline and air-gapped by default: no external network requests, no third-party cloud model, for every finding, verdict, score, and posture judgment the tool makes. One optional, off-by-default feature is the exception (DEC-038): a remediation-drafting backend that calls Google Gemini, enabled only by an operator setting an API key and an explicit switch; it only ever proposes a candidate config edit for the lab, which is independently re-verified before anything runs, exactly like the on-device model it sits beside — see "Honest limits".

## Honest limits

- The traffic-type model was trained on lab traffic plus real public traffic: 4,702 windows from 82 real OpenVPN tunnels (MIT Lincoln Laboratory's VNAT dataset, EXP-19), 6,069 windows from 994 real IPsec tunnels (USBVPN2022 L2TP-IPsec, EXP-20 — the first real IPsec traffic the project has), and 5,116 windows from 458 real people's WireGuard sessions at home (EXP-20; its "web" class excluded — it mixed in unlabelled video and hurt accuracy). Before real IPsec data, the model scored 0.174 on real IPsec traffic and answered 0% of the time (always "uncertain"); with it, it scores 0.757 on real IPsec capture files it never saw and answers 93.6% of the time at 99.8% accuracy when it does (EXP-20, shipped by owner decision, DEC-037, after passing every accuracy condition but missing one operational bar — see DEC-037). Real OpenVPN traffic alone did not transfer to IPsec (0.378, EXP-19). Traffic unlike its training data can be misread.
- Tunnel/transport mode, the ESP key length, and how the peers authenticated cannot always be read from a capture. The tool says "unknown" when it cannot tell.
- Whether a receiver drops replayed packets is not visible from a capture.
- The remediation generator's local model (on-device, MiniCPM5-2B) failed its pre-registered ship bar (EXP-18: 0 of 16 confirmed fixes) and stays switched off (DEC-035). An optional second backend can call Google Gemini instead (DEC-038, owner override of the offline-only rule): off by default, needs an operator-set API key, and whether it clears the same bar is measured by EXP-18b before it ships.
- Everything was measured on one lab, two IPsec implementations (strongSwan, Libreswan), no real WAN.

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
