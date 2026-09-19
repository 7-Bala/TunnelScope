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
```

## Repository map

| Path | What's there |
|---|---|
| [`TODO.md`](TODO.md) | The live task tracker — status, evidence, and what's next |
| [`research/`](research/README.md) | Discover → Define → Exit Review → existing-solutions deep dive |
| [`testbed/`](testbed/TOPOLOGY.md) | Docker IPsec lab (strongSwan classical + PQ, keyless passive vantage) |
| [`experiments/`](experiments/RESULTS.md) | Experiment results against the research hypotheses |
| [`report.md`](report.md) | Original problem-statement selection study (2026-08-29) |

## Current phase

**Planning is complete (2026-09-12).** Every registered experiment has a result
([`experiments/RESULTS.md`](experiments/RESULTS.md)), and the DEVELOP gate has selected the design on
the record ([`research/12-DEVELOP.md`](research/12-DEVELOP.md)): an evidence-tiered IPsec posture
engine with a post-quantum/downgrade assessor and a metadata-leakage measurement module. **Next phase:
building**, starting with the system architecture (T-030). See [`TODO.md`](TODO.md).

## Why "TunnelScope"

The project's core idea isn't guessing what's inside an encrypted tunnel — it's being honest about
what can actually be seen from each vantage point (passive capture, IKE visibility, endpoint
telemetry, keys, authorized active probing), and building a real assessment on top of only that.
"Scope" names the instrument; the tiers are the discipline behind it.
