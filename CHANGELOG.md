# Changelog

Every entry cites the T-ID / EXP-ID that drove it — full detail lives in `TODO.md` and the
referenced experiment's `RESULT.md`. This file is for someone who isn't reading the task tracker.

## [0.3.0] — 2026-09-16 (T-055)

Robustness pass on the failure paths. Each item was reproduced before being fixed and is now
covered by a regression test; the suite previously only exercised captures the tool can read.

**Fixed**
- `fleet` pointed at a nonexistent directory reported a clean fleet: `rglob` yields nothing on a
  missing path, so the scan returned zero tunnels, zero errors and **exit 0**. A typo'd path in a
  scheduled job was indistinguishable from a healthy fleet. Missing / not-a-directory / no
  captures found are now errors (exit 2) — "scanned nothing" must not render as "nothing wrong".
- tshark's failure reason was swallowed: `check=True` buried stderr inside `CalledProcessError`,
  so an unreadable capture printed the whole command line but never *why*. Now reported.
- Unreadable or missing input printed a Python traceback; it now prints one line and an exit code.
- ISAKMP flags were parsed two different ways. `ike_sa_crypto()` used a decimal-tolerant reader, so
  a bare `20` (rather than `0x20`) would read as 0x14 — the responder bit would read clear, the
  function would return `{}`, and the entire IKE crypto finding would disappear silently. Not live
  on tshark 4.2.2 (which emits `0x20`), but one upstream formatting change away. Both call sites
  now share one hex reader.
- No timeout on any tshark call: a single pathological capture could hang a whole fleet scan
  indefinitely. Bounded per call by `TUNNELSCOPE_TSHARK_TIMEOUT` (default 120s).

**Added**
- `tunnelscope doctor` and an automatic preflight: verifies tshark is present and still exposes
  all 23 fields the extractors read. A renamed field does not raise — it silently produces an
  empty finding, which is absence scored as compliance. Runs once per process (~0.4s);
  `TUNNELSCOPE_SKIP_PREFLIGHT=1` opts out.
- Exit codes so automation can tell the cases apart: 0 clean, 1 findings present, 2 input error,
  3 dependency error. Findings-gating is **opt-in** via `--fail-on-findings`, so default
  behaviour and the demo script are unchanged. On `fleet` it also trips when a capture failed to
  parse — a file that was never read has not been cleared.
- `--version`.
- CI job for `fleet-dashboard` (typecheck + lint + build). The dashboard had no automated check
  at all, despite now shipping real code; every regression in it so far was caught by eye.

## [Unreleased] — fleet-dashboard only (T-051)

**Changed**
- `fleet-dashboard/` visual redesign: black/violet/silver-white base, with green/yellow/red
  used strictly as the status-indicator system (never decoratively). Replaced the earlier
  teal/graphite palette throughout `index.css` and every `dashboard/*` component.
- Removed the generic SVG header logo; the wordmark itself is now the mark ("Tunnel" in
  Geist, "Scope" in Bungee — the requested Kufica font is commercial-only with no free
  license, so it was not bundled; see `fleet-dashboard/README.md` for the swap-in path).
- All card containers now use a visibly rounded `rounded-2xl`.
- Fixed real text-overflow risks: KPI card truncation, the expanded verdict table's
  rule-id/baseline columns, and mobile-width x-axis label collisions on the signal trace.

This does not touch the Python package (`tunnelscope/`), tests, or dataset — version stays
at 0.2.0.

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
