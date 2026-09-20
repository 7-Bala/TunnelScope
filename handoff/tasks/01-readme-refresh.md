# Task 01: refresh README.md (canary task, docs only)

Purpose: `README.md` still says "planning is complete, next phase is building". It is months out of date.
This is a low-risk task, used to see how reliably this model follows instructions before trusting it with code.

- Branch: `task/readme-refresh`
- You may edit: `README.md`, `TODO.md` (one changelog line). **Nothing else.**
- Run checks as: `ALLOW="README.md" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md` and `.agents/rules/00-golden-rules.md` first. Then do this task exactly.

Goal: bring `README.md` up to date with what the repository actually contains today.
Create branch `task/readme-refresh` from `main`. Edit only `README.md` (and add one line to the bottom
of `TODO.md`).

STEP 1. Collect facts by running these commands and saving the output. Every number you write into the
README must come from one of them. Do not use numbers from memory.
  a. `.venv/bin/python -m pytest -q 2>&1 | tail -1`                     (the unit test count)
  b. `ls tunnelscope/rules/*.yaml`                                        (the baselines; list their names)
  c. `.venv/bin/tunnelscope --help`                                       (the commands)
  d. `.venv/bin/python dataset/validate.py | tail -1`                     (tracked captures)
  e. `ls experiments/`                                                    (the experiments)
  f. `sed -n 1,40p experiments/exp16-real-apps-cross-impl/RESULT.md`     (results to link to)

STEP 2. Rewrite these parts of README.md. Keep the "Repository map" table but add any missing top-level
folders (`handoff/`, `tunnelscope/`, `fleet-dashboard/`, `dataset/`, `build/`). Keep "Why TunnelScope".
  1. Replace the "Current phase" section with a section titled "Status" that says the tool is built and
     working, lists what it does in 8-10 bullets (see WHAT IT DOES below), and links to `TODO.md`.
  2. In "Quick start" keep the existing `./start.sh` lines and add one line for the CLI:
     `tunnelscope report <capture.pcap>`.
  3. Add a section "Honest limits" containing EXACTLY the text under HONEST LIMITS below.
  4. Add a section "How it was validated" with a bullet per experiment folder in `experiments/`
     (name plus one line taken from that folder's `RESULT.md` heading or first paragraph, copied, not
     invented), each linking to the `RESULT.md`. Experiments with no `RESULT.md`: write "no result yet".

WHAT IT DOES (rewrite in your own words, keep the meaning):
- Reads IKE handshakes and ESP/AH packets from a pcap (or a live stream) with tshark.
- Labels every fact OBSERVED, INFERRED, MEASURED, UNKNOWN or NOT_OBSERVABLE; unknowns are never scored as safe.
- Judges the facts against written baselines (DISA VPN SRG, RFC 8247, RFC 8221/4303, post-quantum, a CVE pattern).
- Builds a threat matrix, a 0-100 risk score and an evidence-confidence figure.
- Predicts the traffic type inside the encrypted tunnel with a model trained by us, with its confidence.
- Detects when a tunnel changes from its usual behaviour (for example a downgrade).
- Writes executive and technical reports, a CBOM, a local dashboard, and works offline (air-gapped).

HONEST LIMITS (copy exactly):
- The traffic-type model was trained on lab traffic. A model trained on synthetic traffic only scored
  0.461 on real applications; the shipped model is trained on synthetic, real-application and
  Libreswan traffic. Traffic unlike its training data can be misread.
- Tunnel/transport mode, the ESP key length, and how the peers authenticated cannot always be read from
  a capture. The tool says "unknown" when it cannot tell.
- Whether a receiver drops replayed packets is not visible from a capture.
- Everything was measured on one lab, two IPsec implementations (strongSwan, Libreswan), no real WAN.

STEP 3. Check your own work:
  - `grep -n -i -E "100% accurate|guarantee|complian|fully secure|proven" README.md`  must print nothing.
  - Every number in your README appears in STEP 1 output. In your report, list each number and which
    command gave it.
  - All relative links point at files that exist: `grep -o "](\([^)]*\))" README.md` and check each one.

STEP 4. `ALLOW="README.md" build/check_all.sh --fast` must end with `RESULT: PASS`.
Add one line to the bottom of `TODO.md`: `- **<today>** README refreshed (T-087 canary task); evidence: check table.`
Commit: `T-087: refresh README to the current state` plus the Co-Authored-By line. Do not push to main.

REPORT (paste real output, not a summary): the check table; the list of numbers with their source
commands; the list of links you verified; anything you were unsure about.

## DONE WHEN
- `RESULT: PASS` from the scoped check; only `README.md` and `TODO.md` changed.
- The grep above prints nothing; the honest-limits text is verbatim.
