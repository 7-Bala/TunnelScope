# TODO — SIH26160 working task tracker

> **This file is Claude's own working tracker.** It is updated at the end of **every** turn,
> without being asked. Its job is to answer, at any moment: *what is done, what is in progress,
> what is next, what is blocked, and what is the evidence.*

## Operating rules (for me)

1. **Update every turn.** Before ending any response, update statuses, move finished items to
   Done with an evidence link, and append a line to the Changelog.
2. **Never mark DONE without evidence** — a file path, commit hash, or result file. "I think it
   works" is not evidence.
3. **User requests become tasks automatically.** Anything the user asks for gets an ID here, even
   if they never say "add this to the todo."
4. **Split anything bigger than one sitting** into subtasks with their own acceptance criteria.
5. **Statuses:** `TODO` · `DOING` · `BLOCKED` (say on what) · `DONE` · `DROPPED` (say why).
6. **Priority:** `P0` blocks everything else · `P1` current phase · `P2` next phase · `P3` nice-to-have.
7. The research **freeze** (10-RESEARCH-EXIT-REVIEW.md) still applies. Targeted research is allowed
   when the user asks for it or an experiment raises a concrete question — and gets logged here.

---

## Current focus

**T-043 (user, 2026-09-11): finish every pre-build item completely before any building.**
Order: ~~T-016/T-021~~ → ~~T-010~~ → **T-012 (running)** → T-011 → ~~T-017~~ → T-014 (partly done) → **T-015 last** (it
consumes all the evidence). Nothing in the Roadmap (T-030+) starts until T-043 is DONE.

**Readiness check (2026-09-11): planning is NOT complete.** One hard gate is unfinished.

**GATE TO BUILDING — must clear first:**
1. **T-015 DEVELOP** (GATE-5) — ≥5 concepts, weighted matrix, red team. Never run. This is the
   blocker: the direction is currently de facto, not selected on the record.
2. **T-014** — `09-DEFINE.md` still states the stronger EXP-01 claim that EXP-01 disproved.
3. ~~T-021~~ — done, see Done table.

**Then:** T-030 architecture, written as the first act of building, not as more planning.

**Parallel with early build** (constrain only the ML components + generalization claims, not the
deterministic core): T-012 (EXP-05 leakage), T-010 (EXP-06 r2), T-011 (EXP-07 Libreswan).
Rule: ship no ML claim before its experiment lands.

---

## Active and queued tasks

| ID | P | Status | Task | Acceptance criteria | Evidence |
|---|---|---|---|---|---|
| T-022 | P1 | TODO | EXP-09 (new) — is the CVE-2026-78135 pattern (CREATE_CHILD_SA on an IKE SA that never authenticated) passively detectable? Closes OQ-31 | Hypothesis, ground truth and falsification criterion added to the register; pattern reproduced on the vulnerable 5.9.8 image; detector result written up | — |
| T-023 | P2 | TODO | Adopt dataset-hygiene practices seen in `naman9271/ipsec-pcap-lab`: per-file SHA-256, a locked test set, an OOD set, a strict validator (credited) | Dataset manifest with hashes; validator script exits non-zero on violations | — |
| T-024 | P2 | TODO | Cross-check EXP-04 against Wireshark master's ADDKE/ML-KEM output (build or container) as an independent oracle | Master's tshark names ML-KEM-768 on our capture; recorded in EXP-04 results | — |
| T-025 | P3 | TODO | Resolve OQ-30 — does Palo Alto's Quantum Readiness view assess third-party IPsec transiting the firewall? | Cited answer, or recorded as UNKNOWN with the reason | — |
| T-011 | P0 | DOING | EXP-07 — Libreswan cross-implementation check of EXP-01/03/04 (+EXP-06 relations). Use Fedora rawhide: libreswan **5.4**-5.fc46 + NSS 3.127 (first Libreswan with ML-KEM/RFC 9370); pin package version + image digest | Libreswan image; the same arms rerun; per-signal verdict: holds / implementation-dependent | Pre-registered (P7-1..P7-4d); image + harness + analysis committed `6425af2`; captures queued to start automatically when EXP-05 frees the router |
| T-012 | P0 | DOING | EXP-05 — metadata leakage (MI / Bayes error / RF as instrument). **IP-TFS arm dropped: Docker kernel lacks CONFIG_XFRM_IPTFS** (NOTES.md #13) | Pre-registered P5-1..P5-5 tested; MI and BER for base vs `tfc_padding=mtu`; mux arm; null control | Pre-registration in EXPERIMENT-REGISTER; captures running |
| T-013 | P2 | TODO | EXP-04 follow-up — reassemble IKE fragments for a clean KE-length asymmetry number | Asymmetry measured on reassembled messages | — |
| T-014 | **P0** | DOING | Update 09-DEFINE.md with experiment outcomes | R5/R8/R14 + matrix rows for sieve/PQ/PFS/failure-diagnosis done; **remaining:** summary-judgment line + EXP-05 row after T-012 | `research/09-DEFINE.md` |
| T-015 | **P0** | DOING | **[GATE-5 — blocks building]** DEVELOP — generate ≥5 concepts, weighted matrix, red team | Doc with matrix and selection rationale | `research/12-DEVELOP.md`: 8 concepts + criteria/weights **committed before scoring** (`6425af2`); scoring waits on EXP-05/07 |

## Roadmap to submission (not yet started)

These map to the PS's deliverables: working prototype, AI engine, dashboard, assessment report,
demo video, technical documentation, dataset. None has started; each waits on DEVELOP (T-015).

| ID | P | Status | Task | Depends on | Acceptance criteria |
|---|---|---|---|---|---|
| T-030 | P2 | TODO | System architecture (DELIVER) — components, data flow, evidence tiers T0–T4, APIs, storage | T-015 | Architecture doc + ADRs; every component traced to a requirement in 09-DEFINE |
| T-031 | P2 | TODO | Evidence extraction layer — tshark/pcap ingestion → per-SA evidence records (reusing parsers, not rebuilding them) | T-030 | Runs on all testbed captures; output validated against the `swanctl` ground truth |
| T-032 | P2 | TODO | Deterministic assessment engine — rules as versioned data (DEC-011), named baselines (RFC 8221/8247/9395, NIST SP 800-77r1, DISA SRG, DST), PASS/FAIL/UNKNOWN/NOT-OBSERVABLE/CONTRADICTORY | T-031 | Every verdict cites its rule and its evidence; zero false PASS on the misconfiguration arms |
| T-033 | P2 | TODO | PQ posture + downgrade assessor (CS-05, DEC-017) | T-031, T-021 | Detects offered-vs-selected downgrade on a dedicated testbed arm |
| T-034 | P2 | TODO | ML components, only where the AI Necessity Matrix justifies them (leakage measurement CS-01, failure diagnosis CS-02) | T-012, T-010 | Each beats a stated simple baseline under a session-level split; calibrated confidence |
| T-035 | P2 | TODO | Security score — a defensible, cited, sensitivity-tested construction (not an invented 0–100) | T-032 | Written methodology; sensitivity analysis |
| T-036 | P2 | TODO | Reports — executive + technical, generated from the evidence graph | T-032 | Both reports produced for ≥3 captures; observed / inferred / unknown kept separate |
| T-037 | P2 | TODO | Analyst dashboard — built after the engine exists; every panel justified by a job-to-be-done | T-032, T-036 | Walkthrough of one capture end to end |
| T-038 | P2 | TODO | Dataset release — the covering-array matrix, provenance, hashes, locked test set | T-023, T-010 | Published dataset + datasheet |
| T-039 | P2 | TODO | End-to-end validation — capture → verdict against ground truth across all arms, including stress cases (truncated, mid-SA start, loss, NAT) | T-032–T-036 | Validation report with per-capability metrics from 09-DEFINE §4 |
| T-040 | P3 | TODO | Demo video + SIH pitch deck + jury Q&A prep | T-039 | Recorded demo; deck; Q&A sheet covering the known weak spots |
| T-041 | P3 | TODO | Technical documentation (install, usage, architecture, limitations) | T-037 | Docs a new user can follow cold |

## Blocked

- **SIH deadline / internal milestones unknown** — needed to schedule T-030+ realistically. Asked the user 2026-09-11.

---

## Done

| ID | Task | Evidence |
|---|---|---|
| T-001 | Research plan and methodology | `research/00-RESEARCH-PLAN.md` |
| T-002 | Discover phase D1–D8 | `research/01`–`08-*.md` |
| T-003 | Define phase | `research/09-DEFINE.md` |
| T-004 | Research exit review → freeze | `research/10-RESEARCH-EXIT-REVIEW.md` |
| T-005 | Docker testbed (classical + PQ strongSwan 6.0.2, keyless router vantage) | `testbed/`, commit `6c41332` |
| T-006 | EXP-02 negative control — PASS | `experiments/exp02-negative-control/results/` |
| T-007 | EXP-01 cipher sieve — partially falsified, corrected | `experiments/exp01-cipher-sieve/results/`, DEC-013 |
| T-008 | EXP-03 PFS signature — confirmed | `experiments/exp03-pfs-signature/results/` |
| T-009 | EXP-04 PQ observability — confirmed, 4 signals | `experiments/exp04-pq-length-asymmetry/results/` |
| T-020 | Existing-solutions deep dive: problem restated, 20+ solutions (mechanism, build, maintenance, PS coverage, gap), competing SIH repos, synthesis | `research/11-EXISTING-SOLUTIONS-DEEP-DIVE.md` |
| T-020a | Live maintenance metrics for 18 repos | `research/data/solutions-maintenance-2026-09-11.json` |
| T-020b | Source-level RFC 9370 check → Wireshark YES (fixed 2026-03-14); Zeek, Suricata, nDPI NO; Arkime no ADDKE found. Closes OQ-26/27 | Doc 11 §3.A, RL-029/030 |
| T-020c | Commercial survey → AQtive Guard TLS/SSH only; Palo Alto own tunnels only (third-party UNK); Greenbone IKEv1-only (checked on the local feed) | Doc 11 §3.B/3.D, RL-031/032 |
| T-020d | Competing projects → a PS-26160 repo with synthetic-Gaussian ML and fabricated defaults; a strong but confounded dataset lab | Doc 11 §3.F, RL-034 |
| T-020e | PS A–E coverage matrix | Doc 11 §5 |
| T-020f | Synthesis + corrections (DEC-016, DEC-017) | Doc 11 §6–7 |
| T-020g | Registers updated; correction banner on doc 07; README fixed; committed and pushed | `research/registers/*`, doc 07, commit `c39dc60` |
| T-016 | Fixed `datetime.utcnow()` deprecation in `run_arm.sh` (already correct in `run_pq_arm.sh`); confirmed no other occurrences in testbed/ or experiments/ | `testbed/scripts/run_arm.sh` |
| T-021 | Upgraded PQ lab image 6.0.2 → 6.1.0 (fixes CVE-2026-78133, potential RCE). Clean rebuild, no plugin regressions. Reran EXP-04: all 4 signals byte-for-byte identical to 6.0.2 | `testbed/images/strongswan-pq/Dockerfile`, `testbed/NOTES.md` #12, `experiments/exp04-pq-length-asymmetry/results/exp04_6.1.0_confirmation.md` |
| T-010 | EXP-06 round 2 — all 6 pre-registered predictions held; rules = decision tree (macro-F1 1.000 with F2/F3 merged); F2 vs F3 provably inseparable passively; **CS-02 needs no ML** (DEC-018) | `experiments/exp06-failure-diagnosis/RESULT_R2.md`, `results/exp06r2_results.json`, 35 captures in `testbed/captures/exp06r2/` |
| T-017 | PS ID confirmed **SIH26160** (NTRO, "AI-Powered IPsec VPN Protocol Analyzer…"); SIH26161 is an unrelated NTRO dam-break statement. Earlier doubt came from a search-engine summary | Raw dataset `NoBugNinja/Smart-India-Hackathon-SIH-2026-Problem-Statements/data/sih2026_ps_20260822_211225.json` |
| T-009b | EXP-06 round 1 — inconclusive, root cause documented | `experiments/exp06-failure-diagnosis/RESULT.md`, commit `27a136d` |
| T-042 | Project named **TunnelScope** (user choice, 2026-09-11); GitHub repo renamed `7-Bala/SIH26` → `7-Bala/TunnelScope`, local remote updated, top-level README added | `README.md`, `gh repo view 7-Bala/TunnelScope`, this commit |

---

## Changelog

- **2026-09-11** — Created this file (user request). Backfilled done work from commits `e92defe`,
  `6c41332`, `27a136d`. Opened T-020 (existing-solutions deep dive) as current focus.
- **2026-09-11** — T-020 done. Main outcomes: (1) **our claim "Wireshark can't decode PQ IKE" was
  wrong** — the issue was fixed 2026-03-14 — withdrawn, and CS-05 restated (DEC-017); (2) the gap is
  confirmed in *assessment* (PS columns D/E), not parsing; (3) an actual competing PS-26160 repo was
  found and read. New: T-021–T-025. Still carried over: T-010–T-017.
- **2026-09-11** — User asked "what's left". Added the roadmap to submission (T-030–T-041), covering
  every PS deliverable not yet started. Recorded the unknown SIH deadline under Blocked.
- **2026-09-11** — Project named **TunnelScope** (user's choice, from a list of Tunnel-themed
  options). GitHub repo renamed `SIH26` → `TunnelScope`; local remote updated; top-level
  `README.md` added.
- **2026-09-11** — User asked directly whether planning is over. Honest answer: **no**. T-015
  (DEVELOP/GATE-5) never ran, so no concept was ever formally selected; 3 of 8 experiments are
  unstarted and EXP-06 is inconclusive, leaving 2 of 3 candidate ML components unvalidated and all
  findings strongSwan-only. Raised T-014 and T-015 to P0 and marked the gate to building above.
  Counter-risk noted: over-planning is now the bigger danger than under-planning.
- **2026-09-11** — User: finish everything pre-build before building. Opened T-043 (umbrella). Raised
  T-010/T-011/T-012/T-016/T-017/T-021 to P0 alongside T-014/T-015. Started T-021 + T-016.
- **2026-09-12** — T-016 and T-021 done (evidence above). EXP-04 reconfirmed on strongSwan 6.1.0,
  identical signals — the finding was not a build artifact. Moving to T-010 (EXP-06 round 2).
- **2026-09-12** — T-010 done: EXP-06 r2 matched all six pre-registered predictions; failure
  diagnosis is deterministic (DEC-018). T-017 done: SIH26160 confirmed. T-014 mostly done (PFS and
  failure diagnosis both moved from "ML" to deterministic, DEC-019). Found that Docker's kernel lacks
  IP-TFS (NOTES.md #13) — EXP-05's IP-TFS arm dropped; EXP-05 now running. Libreswan 5.4 (PQ-capable)
  located in Fedora rawhide for EXP-07.
- **2026-09-12** — EXP-05 captures running (27/52); a dry run caught an analysis bug (direction
  leaking into the "size" MI) — fixed before the final analysis, and logged in the code. Added a
  depth-2 tree baseline for the AI-necessity question. EXP-07 queued behind EXP-05. DEVELOP weights
  committed before scoring.
