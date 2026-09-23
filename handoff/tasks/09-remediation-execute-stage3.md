# Task 09: remediation execution — Stage 3 (the risky one: real commands, real lab)

Purpose: Stage 1 (plan) and Stage 2 (dashboard UI) are merged. This is the last piece: on
Approve, actually change the config on a LAB endpoint, reload, re-capture, and re-verify the
fix worked. Read `build/09-REMEDIATION-ROADMAP.md`'s "Stage 3: execute + verify" section fully
before writing anything.

**This task executes real commands against a real (lab) system. Treat every design constraint
below as load-bearing, not a suggestion. If anything is ambiguous, stop and ask rather than
guess toward "more capable."**

- Branch: `task/remediation-execute-stage3`
- You may create/edit: `tunnelscope/remediate/execute.py` (new), `tunnelscope/api/server.py`,
  `fleet-dashboard/src/components/dashboard/RemediationPane.tsx`,
  `fleet-dashboard/src/lib/api.ts`, `tests/test_remediate.py`, `TODO.md`
- Do NOT edit: `tunnelscope/remediate/plan.py` (Stage 1, frozen), anything under `assess/`,
  `rules/`, `risk/`, `leakage/`, `anomaly/`, `rephrase/`.
- Run checks as: `ALLOW="tunnelscope/remediate/ tunnelscope/api/server.py fleet-dashboard/src/components/dashboard/RemediationPane.tsx fleet-dashboard/src/lib/api.ts tests/test_remediate.py TODO.md" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md`, `.agents/rules/10-python-package.md`,
`.agents/rules/20-dashboard.md`, and `.agents/rules/30-experiments-and-lab.md` first. Then read
`build/09-REMEDIATION-ROADMAP.md` completely, especially "Stage 3: execute + verify" and "What
this is NOT". Create branch `task/remediation-execute-stage3` from `main`.

## The non-negotiable safety rules (violating any one of these means stop and ask, not improvise)

1. **The only valid targets are the project's own Docker lab containers.** Read
   `testbed/docker-compose.yml` for the real container names (they look like `sih26-alice-pq`,
   `sih26-bob-pq`, `sih26-router` — confirm the exact names from the file, do not guess). The
   execute function must REFUSE (return an error, do nothing) if given any target string that
   isn't one of the container names actually found in `testbed/docker-compose.yml` at runtime
   (read the file, build the allowed-target set from it — do not hardcode a list that can drift
   from the actual lab).
2. **`docker exec` only.** No SSH, no `paramiko`, no `fabric`, no raw sockets to a remote host.
   If the container named as the target isn't currently running (`docker ps` doesn't list it),
   refuse and say so — do not try to start it.
3. **Only the exact commands from Stage 1's `REMEDIATION` dict may run, verbatim, never
   string-built from user input.** `tunnelscope/remediate/plan.py` is frozen in this task
   precisely so its commands stay the audited, reviewed ones. Do NOT accept a raw shell command
   from the API caller — the caller supplies `rule_id` and `target`, nothing else; the actual
   command text comes only from `plan.py`.
4. **`auto_applicable: false` rules (`CVE-2026-78135`, `RFC4303-SEQ`) can never execute,
   structurally, not just by convention.** The apply function must check this flag and refuse
   before touching Docker at all.
5. **No apply without a prior explicit plan fetch and explicit confirmation in the SAME
   request** — the API for applying takes `{"rule_id", "target", "confirm": true}` and refuses
   (400) if `confirm` isn't literally `true`. This is the server-side backstop for the
   dashboard's Approve button; the button matters, but the server must not trust the button
   alone.
6. **Every apply attempt is logged** (which rule, which target, when, who/what called it — best
   effort, e.g. remote address) to a plain append-only file, e.g. `.tunnelscope-history/remediate.jsonl`
   (follow the existing pattern in `tunnelscope/anomaly/anomaly.py`'s `History` class for the
   append-only JSONL style). This is the audit trail — it must record attempts even if they fail
   or are refused, not just successes.

## STEP 1: `tunnelscope/remediate/execute.py`

Write `apply_remediation(rule_id: str, target: str, confirm: bool) -> dict`:
  - Validates `confirm is True`, the target is a real, currently-running container from
    `docker-compose.yml`'s actual list, and `rule_id` maps to an `auto_applicable: True` entry
    in `plan.py`'s `REMEDIATION`. Any failure here returns
    `{"ok": False, "stage": "validate", "error": "<specific reason>"}` and does NOT touch Docker.
  - On success: runs the plan's commands via `subprocess.run(["docker", "exec", target, ...])`
    (this is the one place in the whole codebase allowed to use `subprocess` for this purpose —
    say so in a module docstring, and note that `tunnelscope/rephrase/`'s and
    `tunnelscope/remediate/plan.py`'s "no subprocess" static checks must NOT be weakened or
    broadened to cover this new file; if you need to adjust `test_remediate_endpoint_is_provably_read_only`
    or the equivalent, scope it precisely to `plan.py`, not this new file — read that test first).
  - After running the commands, triggers a short re-capture (look at how `tunnelscope live` or
    the existing lab capture scripts start `tcpdump`/`dumpcap` against a `docker exec` target —
    `testbed/scripts/run_exp17.sh` has the pattern for capturing from `sih26-router`) for a few
    seconds, then runs the normal analysis pipeline (`tunnelscope.report.report.analyze`) on the
    fresh capture.
  - Finds the same `rule_id`'s verdict in the fresh analysis and reports whether it is now PASS.
  - Returns `{"ok": True, "rule_id", "target", "commands_run": [...], "verdict_before": "FAIL",
    "verdict_after": "PASS" | "FAIL" | "UNKNOWN", "confirmed_fixed": bool}` — `confirmed_fixed`
    is `True` only if `verdict_after == "PASS"`. If the commands ran but the verdict is still
    FAIL, that is a valid, honest, reportable outcome — do not retry silently, do not hide it.
  - Every code path — success, refusal, exception — appends one line to the audit log (rule 6
    above) before returning.

## STEP 2: API endpoint

`POST /api/remediate/apply` in `tunnelscope/api/server.py`, following the existing style. Body:
`{"rule_id", "target", "confirm"}`. Calls `apply_remediation`. Returns its dict as JSON, 200 on
`ok: True`, 400 on a validation refusal, 500 only for a genuine unexpected exception (caught,
logged, never leaks a stack trace to the client).

## STEP 3: dashboard wiring

In `RemediationPane.tsx`, when `decision === "approved"` AND `auto_applicable`, add an explicit
second step — do NOT auto-apply on Approve alone, that collapses the two-step human gate the
roadmap requires. Add a clearly separate "Apply in lab" button that only appears after Approve,
asks for (or has a fixed, visible, non-editable) `target` — for this task, hardcode the target
selection to a dropdown of the SAME container names the backend validates against (fetch them
from a small new read-only endpoint if needed, or hardcode the known lab pair — read
`testbed/docker-compose.yml` yourself to know what's real), calls
`/api/remediate/apply` with `confirm: true`, and while waiting shows a clear "Applying..."
state (this can take several seconds, it's a real capture+re-analysis). On response, show the
real outcome: commands run, verdict before, verdict after, and a clear PASS/FAIL/still-failing
message — never say "fixed" unless `confirmed_fixed` is literally `true` in the response.

## STEP 4: tests

Add to `tests/test_remediate.py`:
  - `apply_remediation` refuses a target not in the real docker-compose list (mock the compose
    file read or use the real one — check the real container names exist first).
  - Refuses `confirm=False` or missing.
  - Refuses an `auto_applicable: False` rule_id even with `confirm=True`.
  - The static "no execution in plan.py" check from Stage 1 still passes UNCHANGED (prove
    `execute.py`'s subprocess use didn't leak into `plan.py` or weaken that test).
  - If Docker/the lab is actually available in this environment, ONE real end-to-end test:
    force a real FAIL condition in the lab (same technique used in earlier experiment scripts —
    e.g. configure a weak DH group), call `apply_remediation` for real, confirm the verdict
    flips. If Docker isn't available here, write the test but mark it skipped with a clear
    reason (`pytest.mark.skipif`), don't fake the outcome.

## STEP 5: verification

`ALLOW="tunnelscope/remediate/ tunnelscope/api/server.py fleet-dashboard/src/components/dashboard/RemediationPane.tsx fleet-dashboard/src/lib/api.ts tests/test_remediate.py TODO.md" build/check_all.sh --fast`
must PASS. Add one `TODO.md` line. Commit: `T-096: remediation execution, Stage 3 (lab-only,
confirm-gated, re-verified)`, no Co-Authored-By line.

REPORT: the check table, test output, and — if the lab was available — the real before/after
verdict from one genuine apply, pasted in full, not summarized.

## DONE WHEN

- A target outside the real docker-compose list is provably refused (test proves it, not just
  claimed).
- An `auto_applicable: False` rule is provably refused even with `confirm: true`.
- The dashboard never displays "fixed"/"applied" language unless `confirmed_fixed` is true in a
  real API response.
- The audit log records every attempt, including refusals.
- `RESULT: PASS`.
