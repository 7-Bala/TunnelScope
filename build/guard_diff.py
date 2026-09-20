#!/usr/bin/env python3
"""Guard the DIFF, not the code (T-086).

Weaker coding agents fail in predictable ways that no test catches: they edit
results files to match a claim, weaken a test so it passes, wander into files
the task never mentioned, commit a secret or a huge file. This script compares
the working tree with BASE (default: local `main`) and fails on those.

  ALLOW="README.md docs/" python3 build/guard_diff.py      # task scope (path prefixes)
  ALLOW_PROTECTED=1  ...   a human/Claude-approved edit of a protected file
  ALLOW_TEST_EDITS=1 ...   a human/Claude-approved change to existing tests
Exit 0 = clean, 1 = violations (each printed with the reason).
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys

BASE = os.environ.get("BASE", "main")
ALLOW = os.environ.get("ALLOW", "").split()
ALWAYS_OK = ("TODO.md", "build/E2E-VALIDATION.md", "logs/", "handoff/reviews/")

# any change at all is a violation: these are RESULTS, written once by the run that produced them
IMMUTABLE = ["experiments/*/results/*", "experiments/*/RESULT.md", "dataset/MANIFEST.csv",
             "testbed/captures/*/manifest.csv", "testbed/captures/*/*.groundtruth.json", "research/14-*.md"]
# may grow, never lose a line (pre-registrations, decision log, experiment register)
APPEND_ONLY = ["experiments/*/PREREG.md", "research/registers/DECISIONS.md",
               "research/registers/EXPERIMENT-REGISTER.md", "build/findings-allow.txt"]
MAX_BYTES = 5 * 1024 * 1024
SECRET = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                    r"AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}")


def git(*a: str) -> str:
    return subprocess.run(["git", *a], capture_output=True, text=True).stdout


def main() -> int:
    base = BASE if subprocess.run(["git", "rev-parse", "--verify", "-q", BASE], capture_output=True).returncode == 0 else "HEAD"
    numstat = [l.split("\t") for l in git("diff", "--numstat", base).splitlines() if l.count("\t") == 2]
    changed = {p: (0 if a == "-" else int(a), 0 if d == "-" else int(d)) for a, d, p in numstat}
    for p in git("ls-files", "--others", "--exclude-standard").splitlines():
        try:
            n = sum(1 for _ in open(p, "rb"))
        except OSError:
            n = 0
        changed.setdefault(p, (n, 0))
    bad: list[str] = []
    match = lambda p, pats: any(fnmatch.fnmatch(p, g) for g in pats)

    for p, (added, deleted) in sorted(changed.items()):
        if ALLOW and not (p.startswith(tuple(ALLOW)) or p.startswith(ALWAYS_OK)):
            bad.append(f"OUT OF SCOPE: {p} is not under the task's allowed paths {ALLOW}")
        if os.environ.get("ALLOW_PROTECTED") != "1":
            existed = subprocess.run(["git", "cat-file", "-e", f"{base}:{p}"], capture_output=True).returncode == 0
            # a results file may be CREATED by the run that produces it; once it exists on BASE it is frozen
            if match(p, IMMUTABLE) and existed and (added or deleted):
                bad.append(f"PROTECTED RESULT FILE changed: {p} (results are written by the run that produced them, never edited)")
            if match(p, APPEND_ONLY) and deleted:
                bad.append(f"APPEND-ONLY FILE lost {deleted} line(s): {p} (add a new section, never edit or delete history)")
        if os.path.exists(p) and os.path.getsize(p) > MAX_BYTES:
            bad.append(f"FILE TOO LARGE ({os.path.getsize(p) // 1024} KB): {p} (captures/datasets are hashed, not committed)")

    # weakening tests: removed assertions / removed tests / added skips
    if os.environ.get("ALLOW_TEST_EDITS") != "1":
        for line in git("diff", "-U0", base, "--", "tests/").splitlines():
            if line.startswith("-") and not line.startswith("---") and re.search(r"^\-\s*(assert\b|def test_|.*pytest\.raises)", line):
                bad.append(f"TEST WEAKENED: removed line `{line[1:].strip()[:90]}` (fix the code, not the test)")
            if line.startswith("+") and re.search(r"pytest\.mark\.(skip|xfail)|@unittest\.skip|\bpytest\.skip\(", line):
                bad.append(f"TEST SKIPPED: `{line[1:].strip()[:90]}` (a skipped test proves nothing)")

    # secrets in added lines (lab pre-shared keys under testbed/ are throwaway and excluded by pattern)
    for line in git("diff", "-U0", base).splitlines():
        if line.startswith("+") and not line.startswith("+++") and SECRET.search(line):
            bad.append(f"POSSIBLE SECRET in an added line: `{line[1:60]}...`")

    # brand-new (untracked) files are not in `git diff`, and that is exactly where a key gets pasted
    for p in git("ls-files", "--others", "--exclude-standard").splitlines():
        if os.path.getsize(p) > MAX_BYTES or p.startswith("testbed/"):
            continue
        try:
            text = open(p, errors="ignore").read()
        except OSError:
            continue
        m = SECRET.search(text)
        if m:
            bad.append(f"POSSIBLE SECRET in new file {p}: `{m.group(0)[:24]}...`")

    # findings-allow.txt: every new rule needs a reason after '#'
    for line in git("diff", "-U0", base, "--", "build/findings-allow.txt").splitlines():
        if line.startswith("+") and not line.startswith("+++") and "::" in line and not re.search(r"#\s*\S.{12,}", line):
            bad.append(f"ALLOW-LIST ENTRY WITHOUT A REASON: `{line[1:80]}` (write why this change is intended)")

    if bad:
        print(f"GUARD FAILED against {base}: {len(bad)} problem(s)")
        for b in bad:
            print("  -", b)
        return 1
    print(f"guard ok: {len(changed)} changed file(s) vs {base}, none out of scope, protected, weakened or oversized")
    return 0


if __name__ == "__main__":
    sys.exit(main())
