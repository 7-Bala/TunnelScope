# How Claude reviews an Antigravity branch

Input: the file written by `handoff/review_pack.sh` (branch, commits, diff stat, guard output, check
table, the diff or its head, TODO changes).

## Checklist (in this order; stop at the first REJECT reason)
1. **Machine checks.** `RESULT: PASS`? Any SKIP that should not be a SKIP?
2. **Scope.** Files changed = exactly the task's FILES list? Any unrelated edit is a reject.
3. **Honesty.** Every number/claim added: does it match its source file? (Claude re-runs the command.)
   Words like "guarantees", "compliant", "secure", "100% accurate", "proven" added anywhere = fix.
4. **Tests.** New tests added and meaningful (would they fail if the code were wrong)? Existing ones untouched.
5. **Behaviour.** Re-run the task's DONE WHEN commands; for dashboard tasks look at the screenshots
   (desktop + 375 px) and the console-errors line.
6. **Invariants.** UNKNOWN never carries a value; no verdict computed in the browser; no thresholds moved
   without an experiment; no new dependency; no network call added to the package.
7. **Report quality.** Did the agent paste real output, say what it did NOT do, and mention surprises?

## Verdicts
- **ACCEPT**: merge command supplied.
- **ACCEPT WITH FIXES**: a numbered list of at most 5 fixes, each written as a ready-to-paste prompt line
  naming the file and the exact change. Re-review only the fixes.
- **REJECT**: one paragraph on why, and a shorter replacement prompt (or "Claude will do this task").

## Standing suspicion list (things weaker models do)
Editing the test instead of the code; deleting a failing check; a passing number that was never computed;
copying a README claim without re-measuring; adding a helper "for convenience" outside scope; silently
catching an exception; renaming `UNKNOWN` to something friendlier; a TODO.md line that overstates.
