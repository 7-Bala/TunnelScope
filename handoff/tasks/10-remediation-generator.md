# Task 10: the remediation generator and the rest of DEC-033 (T-100 to T-107)

The full plan, with every step, test, failure mode and done-when, is
`build/13-GENERATOR-BUILD-PLAN.md`. This file is only the entry point: which task to run next and
the prompt to start it.

**Gate: do not start any task until the owner has answered decisions D-A to D-F in section 3 of the
plan and they are recorded as DEC-034 in `research/registers/DECISIONS.md`.**

## Order

| Task | Branch | Depends on | Needs lab | Needs Mac model |
|---|---|---|---|---|
| T-100 vocabulary + clone load check | `task/t100-vocab-clone` | gate | yes | no |
| T-101 model runtime + live-check rows | `task/t101-runtime` | gate | no | yes |
| T-102 generator + checks V1-V8 | `task/t102-generator` | T-100, T-101 | yes (smoke) | yes (smoke) |
| T-103 self-critique | `task/t103-critique` | T-102 | no | yes (smoke) |
| T-104 plan store, API, preview digest | `task/t104-digest` | T-103 | yes | no |
| T-105 dashboard + browser tests | `task/t105-dashboard` | T-104 | yes (B2/B3) | yes (B2/B3) |
| T-106 EXP-18 | `task/t106-exp18` | PREREG after T-102; test run after T-105 | yes | yes |
| T-107 rekey verification (optional) | `task/t107-rekey` | gate | yes | no |

## Prompt (paste below this line, replacing T-10X)

Read `AGENTS.md`, `.agents/rules/` (all files), `build/12-GENERATIVE-REMEDIATION-SAFETY.md` and
`build/13-GENERATOR-BUILD-PLAN.md` completely. Then do task **T-10X** from section 6 of
`build/13-GENERATOR-BUILD-PLAN.md`, exactly as written: only its files, its steps in order, every
test and every mutation it lists, and its live proof. Follow section 5 ("Rules every task
follows") without exception. If a step is impossible or seems wrong, or you need a file that is
not listed, stop and say why; do not work around it. Before saying done, run the full
`build/check_all.sh`, and give the report the task asks for: real command output, the mutation
results (each named test that failed), the live proof output, anything you did not do, and
anything that surprised you. No Co-Authored-By or tool name in commits.
