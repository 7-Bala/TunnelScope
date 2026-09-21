# TunnelScope: instructions for coding agents

Read this file fully before doing anything. Then read the task you were given.

## What this project is
TunnelScope analyses IPsec VPN captures (pcap files). It reads the IKE handshake and ESP/AH packets
with tshark, produces *findings* (each labelled OBSERVED, INFERRED, MEASURED, UNKNOWN or
NOT_OBSERVABLE), judges them against written rules (DISA, RFC 8247, RFC 8221/4303, post-quantum),
and builds a threat matrix, a risk score and reports. Two small models we trained ourselves
(Random Forests) predict the traffic type and detect mixed traffic. A React dashboard shows it all.
Problem statement: Smart India Hackathon 2026, PS SIH26160, NTRO.

**The one rule the whole project rests on: never claim more than the evidence shows.**
"UNKNOWN" and "NOT_OBSERVABLE" are correct answers. Absence of evidence is never a pass.

## Where things are
| Path | What |
|---|---|
| `tunnelscope/ingest/tshark.py` | reads pcaps (only place that runs tshark) |
| `tunnelscope/evidence/` | turns packets into findings (`extract.py`, `protocol.py`, `record.py`) |
| `tunnelscope/rules/*.yaml` | the rules; `assess/engine.py` runs them |
| `tunnelscope/risk/`, `explain/`, `anomaly/`, `live/`, `leakage/` | risk score, plain-English text, change detection, live mode, our two models |
| `tunnelscope/api/server.py`, `cli.py` | the local server (127.0.0.1 only) and the command line |
| `fleet-dashboard/` | React + TypeScript dashboard |
| `testbed/` | Docker lab, capture scripts, all captures (`testbed/captures/`) |
| `experiments/` | one folder per experiment: `PREREG.md` (written BEFORE capture), `analyze.py`, `RESULT.md` |
| `research/registers/` | `DECISIONS.md` (decision log), `EXPERIMENT-REGISTER.md` |
| `TODO.md` | the live task list. Add a line for every task you finish |
| `handoff/` | task prompts for you, and the review process |

## Commands (use these exactly)
```bash
.venv/bin/python -m pytest -q                       # unit tests (must stay all-pass)
build/check_all.sh --fast                           # run this before EVERY commit (about 1 minute)
build/check_all.sh                                  # run this before you say "done" (5-8 minutes)
ALLOW="path1 path2/" build/check_all.sh --fast      # same, and fails if you touched anything outside those paths
.venv/bin/tunnelscope --help                        # the CLI
./start.sh                                          # start the app (dashboard at http://127.0.0.1:8765)
cd fleet-dashboard && npx tsc -b && npm run lint && npm run build     # dashboard checks
```
If `.venv` is missing, run `./start.sh` once (it creates it).

## How to work
1. `git checkout -b task/<short-name>` from `main`. Never commit to `main`. Never push to `main`.
2. Do ONLY what the task says, in ONLY the files it lists. Need another file? Stop and say why.
3. Small commits. Message: `T-XXX: what and why`. Do NOT add any Co-Authored-By, "Generated with" or tool/model
   name to commits or files: the repo owner is the only contributor.
4. Run `build/check_all.sh --fast` before each commit. Run the full `build/check_all.sh` at the end.
5. Add one line to `TODO.md` (changelog at the bottom) saying what you did and the evidence.
6. Finish with the REPORT in the task file, pasting real command output. Not summaries of it.

## Never do these (a script checks most of them)
- Never edit a test to make it pass. Fix the code, or stop and report.
- Never edit files under `experiments/*/results/`, any `RESULT.md`, `dataset/MANIFEST.csv`, or delete a
  line from a `PREREG.md`, `DECISIONS.md` or `EXPERIMENT-REGISTER.md`.
- Never invent a number, a capture, an RFC quote or a citation. If you did not get it from a file or a
  command you ran, write `TBD` and say so in your report.
- Never add an AI/LLM library, a model download or a network call to the `tunnelscope` package
  (a test enforces this; every model here is trained by us).
- Never add a dependency (pip or npm) without asking.
- Never commit captures (`*.pcap`), model files you trained by hand, or anything over 5 MB.
- Never paste keys or passwords. Lab throwaway keys under `testbed/` are the only exception.
- Never use `git push --force`, `git reset --hard` on shared work, or `--no-verify`.

## When you are unsure
Stop and ask. A question costs a minute. A confident wrong guess costs a day.
More rules: `.agents/rules/`. Task prompts: `handoff/tasks/`. How your work is reviewed: `handoff/REVIEW.md`.
