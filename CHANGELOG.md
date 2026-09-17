# Changelog

Every entry cites the T-ID / EXP-ID that drove it — full detail lives in `TODO.md` and the
referenced experiment's `RESULT.md`. This file is for someone who isn't reading the task tracker.

## [Unreleased] — 2026-09-17 (T-051, T-052, T-053)

**Fixed**
- IKE crypto is now read per SA. Previously the first IKE_SA_INIT response in a capture was used for
  every SA, so one NO_PROPOSAL_CHOSEN made all of them UNKNOWN (`cs-aes256gcm16-a7.pcap`).
- ESP traffic is no longer credited to earlier, failed SAs between the same hosts; those were being
  reported as `success` (`fail-proposal-mismatch.pcap`, `fail-ts-mismatch.pcap`).
- PQ: whether an additional key exchange was selected is read from the responder's plaintext
  proposal — `offered-but-not-used` is now OBSERVED, and a legitimate two-proposal offer no longer
  raises 'possible downgrade'. RFC 9370 NONE (Transform ID 0) handled. (DEC-025)

**Changed**
- PFS size rule (400 B) applies to MODP groups only; other groups report UNKNOWN until calibrated.
  ESP-only captures keep one record per host pair across rekeys. (DEC-026)

**Added**
- IKEv1 exchange detection (version only; IKEv1 deprecated by RFC 9395).
- `build/04-IMPLEMENTATION-PLAN.md`: adjudication of the review-panel dossier and the remaining plan.

**Process**
- A first implementation (T-051) passed all suites but, under a full-findings differential across
  130 captures (T-052), split rekeying ESP-only tunnels and relied on uncalibrated thresholds.
  Fixed in T-053; the differential is the merge gate (to be scripted, plan §5 P1).

## [0.2.0] — 2026-09-14 (T-049)

**Added**
- `tunnelscope fleet <directory>` — scan many captures, one aggregated view (per-baseline FAIL
  counts, never a blended score), while every per-tunnel evidence/verdict guarantee stays intact.
  The role B (auditor)/D (SOC analyst) workflow neither the CLI nor the dashboard served before.
- CI (`.github/workflows/ci.yml`): unit tests + 69-capture e2e validation + dataset integrity, on
  every push/PR.
- `build/03-USAGE-AND-OPERATIONS-PLAN.md` — per-role usage workflows, deployment model, team
  ownership, and what's deliberately not being built yet (a public API) and why.

**Fixed**
- CVE-2026-78135 detector: a responder-initiated rekey could false-positive, because IKEv2 message
  IDs are per-originator (RFC 7296 §2.1) and the detector compared them as one global sequence.
  Fixed to compare by capture/frame order instead. Found by EXP-12; re-verified 0 FP on all 69 real
  captures, both true positives still fire. (`experiments/exp12-rekey-cadence/RESULT.md`)
- Metadata-leakage TFC-padding heuristic: false-positived on naturally-uniform traffic (e.g.
  identical-size ICMP probes) with no padding configured. Now requires the uniform size to also be
  ≥1200B, grounded in RFC 4303's pad-to-MTU behaviour. (EXP-10 addendum)
- Failure-diagnosis heuristic: a genuine success with no data-plane traffic yet could be misdiagnosed
  as a rejection. Now reports the ambiguity honestly (`post-auth-outcome-ambiguous`, confidence 0.4)
  instead of asserting a specific wrong answer. (EXP-10)

**Corrected (docs, no functional change)**
- `research/09-DEFINE.md` R7: peer auth-method inference (PSK/cert/EAP) is NOT-OBSERVABLE at T0/T1
  in practice, not the "buildable" disposition originally recorded — empirically tested before
  shipping (EXP-11), same discipline as the fixes above.
- `research/09-DEFINE.md` R16: no longer claims conformal-prediction confidence scoring, which was
  never implemented (rightly superseded once 8/9 capabilities turned out deterministic).
- `research/registers/OPEN-QUESTIONS.md`: rebuilt from a confusing append-only history (closures
  appended below instead of updating rows) to one accurate status per question.

**Removed**
- `fastapi`/`uvicorn` from dependencies — declared since the project's early scaffolding, never used
  anywhere in `tunnelscope/`. A local-only API is planned but needs its own security review before
  it ships (see the usage/operations plan); these come back only alongside it.

## [0.1.0] — 2026-09-12

Initial Stage 1–3 build: evidence engine, assessment engine + baselines, score, reports, CBOM,
dashboard, leakage measurement, CVE-2026-78135 detector, Stage-3 cross-tier reconciliation.
See `TODO.md` T-030 through T-047 for full history.
