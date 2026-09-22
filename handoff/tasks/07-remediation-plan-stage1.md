# Task 07: remediation plan generator — Stage 1 only (no execution)

Purpose: judges said the tool is still just a report. `build/09-REMEDIATION-ROADMAP.md` designs
the fix: propose → human approves → apply → re-verify. This task builds ONLY Stage 1 (the plan)
and a READ-ONLY API endpoint that returns it. It does NOT touch a real or lab endpoint, does NOT
run any command against strongSwan/Docker, and does NOT build the dashboard Approve/Reject UI.
Those are separate, later tasks (Stage 2 and Stage 3), on purpose — this is the safe half.

- Branch: `task/remediation-plan-stage1`
- You may create/edit: `tunnelscope/remediate/__init__.py`, `tunnelscope/remediate/plan.py`,
  `tunnelscope/api/server.py`, `tests/test_remediate.py`, `TODO.md`
- Do NOT edit: anything under `tunnelscope/assess/`, `tunnelscope/rules/`, `tunnelscope/risk/`,
  `tunnelscope/leakage/`, `tunnelscope/anomaly/`, `tunnelscope/rephrase/` — this task only reads
  verdicts that already exist, it does not change how they're computed.
- Run checks as: `ALLOW="tunnelscope/remediate/ tunnelscope/api/server.py tests/test_remediate.py TODO.md" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md` and `.agents/rules/10-python-package.md`
first. Then read `build/09-REMEDIATION-ROADMAP.md` completely — it is the design this task
builds. Create branch `task/remediation-plan-stage1` from `main`.

STEP 1. Write `tunnelscope/remediate/plan.py` with a glossary shaped exactly like `GLOSSARY` in
`tunnelscope/explain/explain.py`, but for remediation, using this EXACT table (do not invent or
alter any entry, copy it faithfully):

```python
REMEDIATION = {
    "V-207205": {
        "change": "Move IKEv1 to IKEv2",
        "commands": ["set `version = 2` in the connection's swanctl.conf", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "V-207193": {
        "change": "Raise the DH group",
        "commands": ["set `proposals` to include ecp384 or modp4096, remove the weak group",
                      "swanctl --load-all"],
        "auto_applicable": True,
    },
    "V-207223": {
        "change": "Raise integrity to SHA-384+",
        "commands": ["set proposal integrity to sha384 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8247-DH-MUST": {
        "change": "Drop a forbidden DH group that was picked",
        "commands": ["remove the forbidden group from `proposals`", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8247-DH-OFFER": {
        "change": "Drop a forbidden DH group still offered",
        "commands": ["remove the forbidden group from the OTHER endpoint's proposal list",
                      "swanctl --load-all on that endpoint"],
        "auto_applicable": True,
    },
    "RFC8247-ENCR": {
        "change": "Handshake cipher to AES-GCM",
        "commands": ["set the IKE proposal to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "CVE-2026-78135": {
        "change": "Patch, not a config change",
        "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
        "auto_applicable": False,
    },
    "DST-PQ-KE": {
        "change": "Add hybrid PQ key exchange",
        "commands": ["set proposals to include ke1_ke2 = ke1_mlkem768 (or vendor equivalent)",
                      "swanctl --load-all"],
        "auto_applicable": True,
    },
    "DST-PQ-DOWNGRADE": {
        "change": "Stop allowing classical-only fallback",
        "commands": ["remove the classical-only proposal from the list entirely (no fallback offered)",
                      "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC4301-CONFIDENTIALITY": {
        "change": "AH to ESP",
        "commands": ["change `esp_proposals` in place of `ah_proposals`", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8221-AH-INTEG": {
        "change": "AH integrity off MD5",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8221-AH-LEGACY": {
        "change": "AH integrity off legacy 96-bit",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8221-ESP-3DES": {
        "change": "ESP cipher off 3DES",
        "commands": ["set `esp_proposals` to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC4303-SEQ": {
        "change": "Not a config fix",
        "commands": ["replay is a symptom (misconfigured anti-replay window, or an attack) -- investigate, no command"],
        "auto_applicable": False,
    },
}
```

Do not add, remove, or reword any entry. If you believe one is wrong, stop and say why instead
of changing it.

STEP 2. Write `plan_for(rule_id: str, observed=None) -> dict | None` in the same file:
  - Returns `None` if `rule_id` is not in `REMEDIATION` (unknown rule — the caller decides what
    to do with that, this function never guesses).
  - Otherwise returns `{"rule_id": rule_id, "change": ..., "commands": [...],
    "auto_applicable": bool, "observed": observed}` — a plain dict, JSON-serialisable, no
    execution of anything, no network, no subprocess. This function does not touch a live system
    at all; it only looks up and returns text.
  - Add a test-enforced invariant (in `tests/test_remediate.py`, see STEP 4) that EVERY rule ID
    that exists in any `tunnelscope/rules/*.yaml` file with `severity: high` or `medium` also has
    an entry in `REMEDIATION` — mirror the pattern of
    `tests/test_ai_layer.py::test_every_rule_has_a_plain_explanation`. If a rule is missing,
    that test should FAIL, not silently pass — this is how future rule additions get caught if
    someone forgets to add a remediation entry, the same discipline as the explain glossary.

STEP 3. Add a READ-ONLY API endpoint in `tunnelscope/api/server.py`:
  - `POST /api/remediate/plan` — read the whole existing file first, follow its exact style
    (the `_json` helper, the `do_POST` dispatch pattern). Accept a JSON body
    `{"rule_id": "...", "observed": ...}`, call `plan_for`, return the dict as JSON with status
    200, or `{"ok": false, "error": "unknown rule"}` with 404 if `plan_for` returns `None`.
  - This endpoint must be provably read-only: it does not open a socket, does not call
    `subprocess`, does not write any file, does not import anything from `docker`/`paramiko`/
    `fabric` or similar. Add a test (STEP 4) that greps this function's source for those and
    asserts none appear — the same kind of static check `test_no_outside_model_is_used` does.

STEP 4. Write `tests/test_remediate.py`:
  a. `plan_for` returns the exact expected dict for at least 3 different rule IDs from the table
     (pick ones with different `auto_applicable` values, including one `False` one).
  b. `plan_for("NOT-A-REAL-RULE")` returns `None`.
  c. The coverage invariant from STEP 2 (every high/medium rule in the YAML files has a
     `REMEDIATION` entry).
  d. The read-only static check from STEP 3 (no subprocess/socket/docker/paramiko/fabric
     anywhere in the function or file implementing the endpoint).
  e. An end-to-end test hitting the real server: start it (look at
     `tests/test_ai_layer.py::test_server_history_and_explain` for the pattern — same
     `make_server`/thread/shutdown approach), POST a known rule_id to `/api/remediate/plan`,
     assert the JSON response matches, and POST an unknown rule_id, assert 404.

STEP 5. `ALLOW="tunnelscope/remediate/ tunnelscope/api/server.py tests/test_remediate.py TODO.md" build/check_all.sh --fast`
must be `RESULT: PASS`. Add one line to `TODO.md`. Commit:
`T-094: remediation plan generator, Stage 1 only (read-only, no execution)`, with no
Co-Authored-By line.

REPORT: the check table, the full test output, and one example `curl` or Python call against the
live server showing a real plan response for a rule with `auto_applicable: true` and one for
`auto_applicable: false`.

## DONE WHEN

- `plan_for` and the new endpoint are provably read-only (the static check passes and you can
  explain why it's trustworthy, not just that the test is green).
- The coverage invariant test exists and would fail if a rule were added to a YAML file without
  a matching `REMEDIATION` entry.
- `RESULT: PASS`.
- Nothing under `assess/`, `rules/`, `risk/`, `leakage/`, `anomaly/`, `rephrase/` was touched.
