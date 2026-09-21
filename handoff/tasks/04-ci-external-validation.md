# Task 04: run the third-party capture validation in CI (non-blocking)

Purpose: `build/validate_external.py` checks our tool against other people's IPsec captures (it found a real
bug). CI should run it on every push, but it needs the network, so it must never block a merge.

- Branch: `task/ci-external`
- You may edit: `.github/workflows/ci.yml`, `TODO.md`
- Run checks as: `ALLOW=".github/workflows/ci.yml" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md` and `.agents/rules/00-golden-rules.md` first.

Goal: add ONE new job named `external` to `.github/workflows/ci.yml`. Create branch `task/ci-external`
from `main`.

Read the whole existing file first. The new job must:
  - run on `ubuntu-latest`, with `continue-on-error: true` at the JOB level (so a network problem can
    never fail the workflow);
  - check out the repo, set up Python 3.11, and install tshark exactly the way the existing `test` job does
    (copy those steps, do not invent new ones);
  - install the package the same way the `test` job does (`pip install -e ".[dev]"`);
  - run `python3 build/validate_external.py` as its only test step;
  - NOT depend on (`needs:`) any other job, and NO other job may depend on it.
Do not change any existing job. Do not change the `on:` triggers. Do not add secrets.

Verify:
  1. `.venv/bin/python -c "import yaml,sys; d=yaml.safe_load(open('.github/workflows/ci.yml')); print(sorted(d['jobs'])); print(d['jobs']['external'].get('continue-on-error'))"`
     must print the job names including `external`, then `True`.
  2. `git diff main --stat` shows only `.github/workflows/ci.yml` (and TODO.md).
  3. `git diff main -- .github/workflows/ci.yml` contains only added lines (no line starting with a single `-`
     except the file header). Paste it.
  4. `ALLOW=".github/workflows/ci.yml" build/check_all.sh --fast` is `RESULT: PASS`.

You cannot run GitHub Actions locally. Say so in your report; do not claim the job runs until CI shows it.
Add one line to `TODO.md`. Commit: `T-090: run third-party capture validation in CI (non-blocking)`, with no Co-Authored-By line.

REPORT: the verification outputs, the added lines, and the sentence "Not yet run on GitHub".

## DONE WHEN
- `external` job exists with `continue-on-error: true`, no `needs`, existing jobs byte-identical.
- The reviewer confirms after pushing that the job appears in the Actions run.
