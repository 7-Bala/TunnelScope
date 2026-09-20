# Golden rules (always on)

1. **Evidence, not claims.** Every number, count or statement you write into docs, UI or code
   comments must come from a file or a command you ran in this session. Cannot get it? Write `TBD`.
2. **Stay in scope.** Edit only the files the task lists. If another file needs a change, stop and say why.
3. **Tests are the judge.** Never weaken, delete, skip or `xfail` a test. If a test fails, fix the code.
   If you believe the test is wrong, stop and explain; do not change it.
4. **Results are read-only.** Never edit `experiments/*/results/*`, `RESULT.md`, `dataset/MANIFEST.csv`.
   Pre-registrations, the decision log and the experiment register are append-only.
5. **Check before you commit.** `build/check_all.sh --fast` before each commit; full run before "done".
   Paste the PASS/FAIL table into your report. A FAIL means you are not done.
6. **Honest failure beats fake success.** If you could not finish, say exactly what is missing.
   Do not hide a failure, rename it, or make it quiet.
7. **No new dependencies, no network calls in the package, no AI libraries, no big files.**
8. **One task, one branch** (`task/<name>`). Never commit or push to `main`. Never force-push.
9. **Unsure means stop and ask.**

Report format at the end of every task: what changed (file list), the check table, anything that
surprised you, anything you did not do and why.
