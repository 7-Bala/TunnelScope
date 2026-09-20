# Working with Antigravity: how this handoff works

Antigravity's models are weaker than the ones that built this project, so the setup does not rely on
the model being careful. It relies on **small tasks, exact instructions, and a script that checks the work**.

## One-time setup (5 minutes)
1. Open this repository folder in Antigravity. Confirm it sees `AGENTS.md` and `.agents/rules/`.
2. In the Rules panel set activation once: `00-golden-rules` = **Always on**; `10-python-package` =
   glob `tunnelscope/**, tests/**`; `20-dashboard` = glob `fleet-dashboard/**`;
   `30-experiments-and-lab` = glob `experiments/**, testbed/**`. (I could not confirm from the docs how
   activation is written inside the file, so it is set in the UI, not in the files.)
3. Pick the strongest model it offers. If it has a planning mode, use it for every task below.
4. Terminal check: `cd "<repo>" && build/check_all.sh --fast` should print `RESULT: PASS`. If not, stop
   and fix the environment before starting any task.

## For every task (the loop)
1. **Fresh conversation per task.** Weaker models get confused by long history.
2. Paste the **PROMPT block** from the task file. Nothing else. Do not paraphrase it.
3. Let it work. If it asks a question, answer briefly; if it wanders, say: "Stop. Re-read AGENTS.md and
   the task's FILES section, and only do what the task lists."
4. **Do not trust its "done".** In your own terminal, on its branch, run the full check yourself:
   ```bash
   ALLOW="<the task's allowed paths>" build/check_all.sh
   ```
   Only `RESULT: PASS` counts. The agent's summary does not.
5. Make the review pack and give it to Claude (small on purpose, cheap to review):
   ```bash
   handoff/review_pack.sh          # writes handoff/reviews/<branch>.md and prints its path
   ```
   Paste the file's contents with: "Review this per handoff/REVIEW.md".
6. On ACCEPT: `git checkout main && git merge --no-ff task/<name> && git push`.
   On fixes needed: Claude returns a short **fix prompt**; paste it into the same Antigravity conversation.

## Order
1. `01` (canary: a docs-only task, to see how this model behaves before trusting it with code)
2. `02`, `03`, `04` (independent; any order)
3. `05` only after 01-04 went well. It runs the Docker lab for about an hour.
Remaining work and who should do it: `BACKLOG.md`.

## Things to give the model, never
Your passwords, API keys, or logins. If a task needs a download that needs an account, you fetch it and
tell the agent the file path.
