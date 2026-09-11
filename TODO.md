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

**T-020 done** (existing-solutions deep dive). **Next up: T-021** (patch the lab's PQ image for
CVE-2026-78133), then **T-010 / T-022** (EXP-06 round 2 and the CVE-2026-78135 detection
experiment, which share a testbed change).

---

## Active and queued tasks

| ID | P | Status | Task | Acceptance criteria | Evidence |
|---|---|---|---|---|---|
| T-021 | P1 | TODO | Upgrade the lab's PQ strongSwan image 6.0.2 → 6.1.0 (CVE-2026-78133: rekey-collision use-after-free, potential RCE, affects 6.0.0+) and rerun EXP-04 to confirm the signals survive | Image rebuilt on tag 6.1.0; EXP-04 rerun, same 4 signals; MANIFEST.md updated | — |
| T-022 | P1 | TODO | EXP-09 (new) — is the CVE-2026-78135 pattern (CREATE_CHILD_SA on an IKE SA that never authenticated) passively detectable? Closes OQ-31 | Hypothesis, ground truth and falsification criterion added to the register; pattern reproduced on the vulnerable 5.9.8 image; detector result written up | — |
| T-023 | P2 | TODO | Adopt dataset-hygiene practices seen in `naman9271/ipsec-pcap-lab`: per-file SHA-256, a locked test set, an OOD set, a strict validator (credited) | Dataset manifest with hashes; validator script exits non-zero on violations | — |
| T-024 | P2 | TODO | Cross-check EXP-04 against Wireshark master's ADDKE/ML-KEM output (build or container) as an independent oracle | Master's tshark names ML-KEM-768 on our capture; recorded in EXP-04 results | — |
| T-025 | P3 | TODO | Resolve OQ-30 — does Palo Alto's Quantum Readiness view assess third-party IPsec transiting the firewall? | Cited answer, or recorded as UNKNOWN with the reason | — |
| T-010 | P1 | TODO | EXP-06 round 2 — fix shared-traffic-selector contamination, then rerun failure diagnosis | Distinct traffic selector per arm; all other SAs terminated before each capture; clean captures; result written up | `experiments/exp06-failure-diagnosis/` |
| T-011 | P1 | TODO | EXP-07 — Libreswan cross-implementation check of EXP-01/03/04 | Libreswan image; the same arms rerun; per-signal verdict: holds / implementation-dependent | — |
| T-012 | P2 | TODO | EXP-05 — metadata leakage with TFC padding / IP-TFS (mutual information / Bayes error) | MI and BER before/after for `tfc_padding=0/mtu` and `mode=iptfs` | — |
| T-013 | P2 | TODO | EXP-04 follow-up — reassemble IKE fragments for a clean KE-length asymmetry number | Asymmetry measured on reassembled messages | — |
| T-014 | P2 | TODO | Update 09-DEFINE.md R5 and the AI Necessity Matrix with EXP-01's narrower claim | Edited rows cite EXP-01 | — |
| T-015 | P2 | TODO | DEVELOP — generate ≥5 concepts, weighted matrix, red team | Doc with matrix and selection rationale | — |
| T-016 | P3 | TODO | Fix the `utcnow()` deprecation warning in `run_arm.sh` | Warning gone | — |
| T-017 | P3 | TODO | Confirm the PS ID (SIH26160 vs SIH26161) — OQ-16 | Official portal checked | — |

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
| T-009b | EXP-06 round 1 — inconclusive, root cause documented | `experiments/exp06-failure-diagnosis/RESULT.md`, commit `27a136d` |

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
