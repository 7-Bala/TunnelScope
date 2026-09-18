# Changelog

Every entry cites the T-ID / EXP-ID that drove it — full detail lives in `TODO.md` and the
referenced experiment's `RESULT.md`. This file is for someone who isn't reading the task tracker.

## [Unreleased] — 2026-09-18 (T-054, T-055, T-057)

**Fixed**
- ESP content length is now right for UDP-encapsulated ESP (NAT-T, RFC 3948) and for IPv6. It used
  to be `ip.len − 28` for every packet: on a real UDP-encapsulated CBC tunnel that counted the 8 B
  UDP header as ciphertext and the cipher sieve **eliminated CBC, the true suite**; over IPv6 the
  records had no addresses or lengths, and a successful tunnel was reported as a failure (0.9).
  IPv4 options now use the header length, and IPv6 extension headers mark the length unknown
  instead of guessing. (T-057)
- CVE-2026-78135: when a capture has no IKE_AUTH, the detector now fires only if the
  CREATE_CHILD_SA's message ID directly follows the last pre-auth exchange (proving nothing was sent
  in between). A gap, or a responder-originated exchange, is UNKNOWN, so a capture that merely lost
  its IKE_AUTH is no longer a detection. (T-055)

**Added**
- `build/findings_diff.py` + `build/findings-allow.txt`: every finding on every capture, base vs
  head; CI fails on any change not listed with a reason. (T-054)
- Encapsulation lab `testbed/docker-compose.encap.yml` + `scripts/run_encap.sh`, and 4 real
  captures with T2 ground truth in `testbed/captures/encap/` (dataset now 82 pcaps). (T-057)

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

## Tunnel as the page background — 2026-09-18 (T-073)

**Changed**
- The tunnel is now the page background behind the top of the page, dimmed and fading out toward the
  data and on scroll. The intro hands over to it: the same corridor dims and settles instead of
  fading to black. Rings fit the window's shape.
- The upload panel is frosted, and its right half is a dashed drop zone (click to choose files)
  instead of a second tunnel.

**Fixed**
- The hand-over was timed per frame (capped), so on a device drawing 2 frames a second it would have
  taken ~19s instead of 1.9s; it now runs on wall-clock time.

## Intake tunnel — 2026-09-18 (T-072)

**Changed**
- The upload panel's tunnel is drawn with the intro's glowing tubes, adds specks of light travelling
  out of it and a pulse of light every few seconds (faster while dragging or analysing), leans toward
  the pointer, and a click sends a pulse down to the core.

**Fixed**
- The tunnel was pulled off centre whenever the pointer was elsewhere on the page (the offset was
  not clamped); it now only follows the pointer over the tunnel and eases back to centre.
- "Choose captures" had no hover colour (it still pointed at the removed teal token).

## Dashboard intro — 2026-09-18 (T-069)

**Added**
- First-visit intro: the tunnel's rings switch on one by one from the far end toward the viewer,
  each flickering before it holds, then the wordmark and a fade into the dashboard. Skippable,
  first visit only, off under reduced motion. `?intro` replays it; `?intro=hold` stops on the
  final frame.
- Plays on every load now, not just the first visit (T-071); any key or tap still skips it.
- One faulty light (T-070): ring 9 catches, dies, and catches again while the nearer rings wait for it.

## Merge — 2026-09-18 (T-068)

**Changed**
- `fleet-dashboard/`: the upload-first dashboard (intake, 3D tunnel, data-source switch, register
  panes) now uses the black/violet design system and Kufica wordmark. Evidence-tier chips: observed
  and measured in violet, inferred in silver (a meta tone, never the yellow status colour).
- `ike_sa_crypto()` keeps its per-SA filter and is now served from the capture cache.


Two histories diverged after T-050 (2026-09-14): GitHub `main` (T-051…T-056 below, 2026-09-14…16)
and this machine (T-051…T-061 above). Both used the IDs T-051…T-056 for different work. They were
merged on 2026-09-18 keeping GitHub's black/violet dashboard design (user's choice) with the
upload features rebuilt on it, and both backends combined. In `TODO.md` the GitHub-side tasks are
renumbered **T-062…T-067** (T-051→T-062, T-052→T-063, T-053→T-064, T-054→T-065, T-055→T-066,
T-056→T-067); their commit messages keep the original IDs.

## [0.3.0] — 2026-09-16 (GitHub T-055 → T-066)

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

**Performance (GitHub T-056 → T-067)**
- Capture reads are memoised on `(path, mtime, size)`. The IKE crypto read runs once per SA and
  each read re-parses the entire file, so a capture carrying 10 tunnels cost 10 tshark spawns
  (1.86s); it now costs 1 (0.19s). The single-capture CLI path drops 5 spawns to 3. A capture
  that changes on disk is re-read rather than served stale, and the cache is bounded
  (`TUNNELSCOPE_CACHE_CAPTURES`, default 8, `0` disables).
- Stated honestly: this does **not** speed up `fleet`. The original premise was that fleet scans
  would benefit, and measurement disproved it — each capture is analysed exactly once, so there
  is nothing to reuse across files (19.7s vs 19.3s over 35 captures, i.e. noise). The win is
  repeated reads of one capture, which is the multi-tunnel gateway case our corpus happens not
  to contain.

## fleet-dashboard only — 2026-09-14 (GitHub T-051 → T-062)

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
