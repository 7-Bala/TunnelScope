# Task 05: run EXP-17 (network conditions) and analyse it

Purpose: every capture so far was on a lab LAN with no delay or loss. This measures what packet loss and
delay do to the classifier, and whether the safety properties survive. **Claude wrote the pre-registration
and the run script; you run them and analyse the results.** Do not edit either.

Do this task only after tasks 01-04 went well. It runs Docker for about an hour.

- Branch: `task/exp17`
- Already committed on `main` (read-only for you): `experiments/exp17-network-conditions/PREREG.md`, `testbed/scripts/run_exp17.sh`
- You may create/edit: `experiments/exp17-network-conditions/analyze.py`, `experiments/exp17-network-conditions/results/`,
  `experiments/exp17-network-conditions/RESULT.md`, `testbed/captures/exp17/`,
  `research/registers/EXPERIMENT-REGISTER.md` (APPEND one section), `TODO.md`
- Run checks as: `ALLOW="experiments/exp17-network-conditions/ testbed/captures/exp17/ research/registers/EXPERIMENT-REGISTER.md" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md` and `.agents/rules/30-experiments-and-lab.md` first.
Then read `experiments/exp17-network-conditions/PREREG.md` completely. It contains six numbered predictions.
You are not allowed to change it, the run script, or any threshold. Whatever the numbers say is the result.

STEP 1. Environment. Create branch `task/exp17` from `main`. Docker Desktop must be running. Run
`cd testbed && docker compose up -d router alice-pq bob-pq apps-a apps-b` and wait 10 seconds.
Check `docker ps --format '{{.Names}}' | grep sih26` lists router, alice-pq, bob-pq, apps-a, apps-b.

STEP 2. Capture (about 50 minutes; do not interrupt it; do not run other Docker work at the same time):
  `mkdir -p logs && testbed/scripts/run_exp17.sh 3 20 2>&1 | tee logs/exp17_run.log`
  - If the output contains `FATAL`, stop and report the exact line. Do not try to repair the lab yourself.
  - If it prints `WARNING:` lines, keep them and report them. Do not delete or re-run sessions.
  - When it ends it prints `done: 96 sessions, 10 IKE bring-ups`. Any other numbers: report and stop.
  - Afterwards confirm impairment is removed: `docker exec sih26-router tc qdisc show dev eth0` must NOT mention netem.

STEP 3. Write `experiments/exp17-network-conditions/analyze.py`. Copy the structure of
`experiments/exp16-real-apps-cross-impl/analyze.py`. It must compute exactly the following and write
`experiments/exp17-network-conditions/results/exp17_results.json` (create the folder):

  DATA. `testbed/captures/exp17/manifest.csv` has NO header; columns `tag,arm,class,rep,seed,packets,sha256`;
  `arm` is one of `wan-syn`, `lossy-syn`, `wan-real`, `lossy-real`. Each session's packets are in
  `testbed/captures/exp17/<tag>.pkts.csv.gz` with a header row `t,dir,len` (dir is `out` or `in`).
  Turn a session into windows with `from tunnelscope.leakage.attacker import window_features` called on a list of
  `(float(t), dir, int(len))` tuples.
  The profile is the arm text before the dash (`wan` or `lossy`).

  P17-1 and P17-2. Load the SHIPPED model with `from tunnelscope.leakage.attacker import _model` and
  `rf = _model()[0]`. For each profile, pool the windows of both parts (`-syn` and `-real`), predict with
  `rf.predict(X)`, and compute macro-F1 with `sklearn.metrics.f1_score(y_true, y_pred, average="macro", zero_division=0)`.
  Also report macro-F1 per part and the F1 per class.

  P17-3. Leave-one-repetition-out over the three impaired repetitions. For each k in 1,2,3 and each profile:
  train `RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1, min_samples_leaf=2)` on
  (all windows returned by `load()` in `build/models/make_traffic_data.py`, which is the existing data) PLUS
  (the exp17 windows of that profile whose rep != k); test on the exp17 windows of that profile with rep == k.
  Report the macro-F1 for each k and the mean per profile. (`load()` returns `X, y, arm, rep, sess, src`;
  import it with `sys.path.insert(0, "build/models")` as the exp16 script does.)

  P17-4. For every exp17 session build a record: `from tunnelscope.evidence.record import EvidenceRecord`;
  `rec = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="x")`; set
  `rec._esp = [{"t": t, "src": "10.0.0.1" if d == "out" else "10.0.0.2", "dst": "10.0.0.2" if d == "out" else "10.0.0.1",
  "ip_len": n, "esp_content": n - 28, "esp_content_known": True, "frame": i + 1} for i, (t, d, n) in enumerate(pkts)]`.
  Call `from tunnelscope.leakage.mode_model import infer_mode` as `infer_mode(rec, ["AES-GCM-16"])`.
  It returns None (abstained) or a Finding. Count: sessions answered "tunnel", answered "transport", abstained,
  per profile and part. The prediction concerns the number answered "transport" (all sessions are tunnel mode).

  P17-5. For every SINGLE-class exp17 session (all of them are) call `from tunnelscope.leakage.attacker import extract_attacker`
  as `extract_attacker(rec)` on a record built as in P17-4, then read `rec.findings["traffic_type"]`.
  It is "flagged mixed" when `finding.value is None and "mixed" in finding.note`. Report the flagged share per
  profile. Also report answered-correct, answered-wrong and abstained-for-other-reasons counts
  (correct means `finding.value["class"] == session class`).

  P17-6. For each `testbed/captures/exp17/ike/ike-*.pcap` read `<name>.groundtruth.json`. If its `initiate_result`
  does not contain the word `successfully`, count it as "not established" and skip it. Otherwise:
  (a) load `build/validate_e2e.py` with `importlib.util.spec_from_file_location` and call its `check_exp15`
  function with `{"path": "exp17/ike/<name>.pcap"}`. It returns a list of problems; an empty list means
  TunnelScope's IKE encryption, DH group and integrity equal swanctl's. (b) `from tunnelscope.evidence.extract
  import build_records`, `from tunnelscope.assess.engine import assess_record`; take the record with the most
  `_ike` messages and read the verdict whose `rule_id == "CVE-2026-78135"`; count PASS / UNKNOWN / FAIL.
  Report per profile: established, not established, IKE mismatches (with the problem text), CVE verdict counts.

  VERDICTS. In the results JSON add a `verdicts` object with one true/false per prediction using ONLY the
  thresholds written in `PREREG.md`: P17-1 >= 0.70 on wan; P17-2 >= 0.50 on lossy; P17-3 >= 0.90 on both
  profiles (mean); P17-4 zero "transport" answers; P17-5 flagged share <= 0.15 on both profiles;
  P17-6 zero mismatches and zero CVE FAIL. Do not tune anything to make a verdict true.

STEP 4. Run `.venv/bin/python experiments/exp17-network-conditions/analyze.py` and paste its full output.

STEP 5. Write `experiments/exp17-network-conditions/RESULT.md` containing ONLY: (1) the pre-registration
reference, (2) a table with columns `# | Prediction | Result | Held or FAILED` copied from the JSON with the
real numbers, (3) the counts of sessions and IKE bring-ups, (4) any WARNING lines from the run, (5) a heading
"Not concluded" followed by the single sentence "Interpretation is written by the reviewer." Do NOT explain or
interpret the results, do not soften a failure, do not add a claim not in the JSON.
APPEND (do not edit existing lines) a section `### EXP-17 — RESULT (<today>)` to
`research/registers/EXPERIMENT-REGISTER.md` with one sentence per prediction, numbers copied from the JSON.

STEP 6. `ALLOW="experiments/exp17-network-conditions/ testbed/captures/exp17/ research/registers/EXPERIMENT-REGISTER.md" build/check_all.sh --fast`
must be `RESULT: PASS`. Add one line to `TODO.md`. `git add` the per-packet tables, `manifest.csv`, the `ike/`
folder, results, RESULT.md (the `.pcap` session files are git-ignored; do not force-add them).
Commit: `T-091: EXP-17 network conditions, results` plus Co-Authored-By.

REPORT: the run log tail (`tail -5 logs/exp17_run.log`), any FATAL/WARNING lines, the analyze output,
the verdict table, the check table.

## DONE WHEN
- 96 session tables, 10 IKE bring-ups, `results/exp17_results.json` with all six verdicts.
- RESULT.md contains no interpretation and no softened failure; PREREG.md and the run script are untouched.
- `RESULT: PASS`.
