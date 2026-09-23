# Task 09b: fix Stage 3 — commands must actually change config, not just prose

Context: `task/remediation-execute-stage3` (branch exists, commit `414cd19`) implements the
safety scaffolding correctly (target whitelist from docker-compose.yml, confirm-gate,
auto_applicable block, audit log, re-verify) — all of that is good and stays as-is. But it has
one real bug: `execute.py` runs `plan.py`'s `commands` list verbatim through `sh -c` inside the
container. Those strings are human-readable PROSE written for Stage 1's read-only API
(e.g. `"set `proposals` to include ecp384 or modp4096, remove the weak group"`), not real shell
commands. Nothing actually gets edited. `swanctl --load-all` then reloads the UNCHANGED config.
The dashboard correctly still shows "not fixed" (verdict stays FAIL), so nothing dishonest is
claimed — but the feature cannot fix anything as built. Fix that, without breaking Stage 1's
existing read-only text.

- Branch: stay on `task/remediation-execute-stage3` (do not create a new branch)
- You may now ALSO edit: `tunnelscope/remediate/plan.py` (lifting the earlier "frozen" restriction
  for this one fix — see STEP 1, additive only)
- Everything else stays in scope as before: `tunnelscope/remediate/execute.py`,
  `tests/test_remediate.py`, `TODO.md`

## PROMPT (paste everything below this line)

Read `AGENTS.md` and `build/09-REMEDIATION-ROADMAP.md` first. Stay on branch
`task/remediation-execute-stage3`. This is a targeted fix, not a rewrite — the safety scaffolding
(target whitelist, confirm gate, auto_applicable block, audit log, re-capture+re-verify) is
already correct and must not change.

## THE BUG

`execute.py` currently runs each string in `plan.py`'s `REMEDIATION[rule_id]["commands"]`
verbatim as a shell command. Those strings are prose written for a human reading the Stage 1 API
response (e.g. `"set version = 2 in the connection's swanctl.conf"`), not real commands. So no
config file is ever edited, and `swanctl --load-all` reloads the unchanged config. Confirm this
yourself: read `tunnelscope/remediate/plan.py`'s `REMEDIATION` dict and
`tunnelscope/remediate/execute.py`'s STEP 5 (the `for cmd in commands:` loop).

## THE FIX

STEP 1. Investigate the REAL config first, do not guess paths. Start the lab
(`cd testbed && docker compose up -d router alice-pq bob-pq`, wait, or reuse whichever lab
containers `.agents/rules/30-experiments-and-lab.md` / `testbed/scripts/*.sh` bring up for the
`t-tun` connection used elsewhere in this repo — e.g. `run_exp17.sh`'s `setup_exp15` function
shows the pattern: config loaded via `swanctl --load-all --file /tmp/exp15-alice.conf`). Once a
lab connection is up, `docker exec` into `sih26-alice-pq` and:
  - `swanctl --list-conns` to see the loaded connection and its actual proposal strings.
  - Find the real on-disk config file swanctl loaded from (check `/etc/swanctl/conf.d/` and
    whatever path `--load-all --file` was pointed at) and read it, to see the real key names
    (`proposals =`, `version =`, etc.) and real syntax strongSwan's `swanctl.conf` uses.

STEP 2. Add a NEW field to each `auto_applicable: true` entry in `tunnelscope/remediate/plan.py`
called `exec_commands`: a list of REAL, literal shell commands (e.g. a `sed -i` line that edits
the actual proposal string in the actual config file path you found in STEP 1, followed by
`swanctl --load-all`). **Do not touch or reword the existing `change`, `commands`, or
`auto_applicable` fields — Stage 1's API response must not change for any existing caller.**
This is additive only. For each entry, write the `exec_commands` you can make genuinely correct
and testable; if a specific rule's real fix is too environment-specific to express safely and
generically (e.g. `RFC8247-DH-OFFER`, which the roadmap notes targets "the OTHER endpoint" — a
second container, not the one being remediated), leave `exec_commands` as an empty list `[]` for
that entry and make `execute.py` refuse to apply it (STEP 3) rather than run something wrong.
Say explicitly in your report which rules got real `exec_commands` and which were left empty and
why.

STEP 3. Update `tunnelscope/remediate/execute.py`'s command-execution step (STEP 5 of the
original implementation) to run `plan["exec_commands"]` instead of `plan["commands"]`. If
`exec_commands` is empty for a rule, `apply_remediation` must refuse with a clear
`{"ok": False, "stage": "validate", "error": "no safe automated fix exists for this rule yet"}`
— same refusal shape as the existing `auto_applicable` check, do not silently fall back to the
old prose-based behavior.

STEP 4. Verify for real, not by inspection alone: with the lab running, call `apply_remediation`
for at least one rule that now has real `exec_commands` (pick one where you can force the FAIL
condition first — check `testbed/scripts/` for how earlier experiments configured a weak DH
group, e.g. `gen_exp15_conf.py` or similar). Confirm: before the call, the rule's verdict is
FAIL; after the call, `docker exec sih26-alice-pq swanctl --list-conns` shows the NEW proposal
string (not the old one); the re-analysis in `apply_remediation`'s own return value shows
`verdict_after: "PASS"` and `confirmed_fixed: true`. Paste this whole sequence in your report —
the before state, the exact call, the after state, and the config diff (old proposal string vs
new one) — this is the proof that something real changed, not just that a function returned
`ok: true`.

STEP 5. Update `tests/test_remediate.py`: the existing safety tests (target whitelist, confirm
gate, auto_applicable block, audit log) should not need changes. Add one test asserting that a
rule with empty `exec_commands` is refused by `apply_remediation` with the new error message,
and update `test_apply_remediation_mocked_success_and_fail` / `test_lab_remediation_e2e` if they
assumed the old `commands` field was what got executed — they should now assert `exec_commands`
is what runs.

STEP 6. `ALLOW="tunnelscope/remediate/ tunnelscope/api/server.py fleet-dashboard/src/components/dashboard/RemediationPane.tsx fleet-dashboard/src/lib/api.ts tests/test_remediate.py TODO.md" build/check_all.sh --fast`
must PASS. Add one `TODO.md` line describing the bug and the fix, referencing this task. Commit:
`T-096: fix Stage 3 -- exec_commands are real config edits, not prose`, no Co-Authored-By line.

REPORT: which rules got real `exec_commands` and which were left empty (with why), the full
before/after proof from STEP 4 (real config diff, real verdict flip), the check table, and test
output.

## DONE WHEN

- At least one rule provably changes real config and flips a real verdict from FAIL to PASS —
  proven with actual `swanctl --list-conns` output before and after, not just a function's
  return value.
- A rule with no safe `exec_commands` is refused, not silently run with the old broken behavior.
- Stage 1's existing `change`/`commands`/`auto_applicable` fields are byte-identical to before —
  only `exec_commands` was added.
- `RESULT: PASS`.
