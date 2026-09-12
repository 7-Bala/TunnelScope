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

**T-043 DONE (2026-09-12): every pre-build item is complete.** GATE-5 cleared: the design is
selected on the record in `research/12-DEVELOP.md` (DEC-023).

**Next: the build phase, starting with T-030 (system architecture).** Build order from DEC-023:
Stage 1 = C3 posture engine + C6 PQ/downgrade assessor (deterministic, fully validated) →
Stage 2 = C8 leakage module → Stage 3 (optional) = C5 endpoint cross-check.

**Build complete through Stage 3 (2026-09-12).** All stages built and validated, including the
optional Stage-3 C5 cross-tier module (T-045) and the CVE detector now shipped in the package with
its sensitivity validated (T-022). The ONLY remaining item is the demo *video*, which is the user's
to record (`build/sih/DEMO-SCRIPT.md`). The single stated out-of-scope gap is a *live cryptographic*
CVE-2026-78135 exploit capture (needs a malicious IKE stack); the plaintext-structural pattern the
detector reads is validated. See `experiments/exp09-.../RESULT.md`.

---

## Active and queued tasks

| ID | P | Status | Task | Acceptance criteria | Evidence |
|---|---|---|---|---|---|
| T-046 | **P1** | DOING (near-done) | Kumaraguru internal ideathon deck (pptx) filled from real project evidence, all layout defects found+fixed; official SIH portal submission (sih.iqubekct.ac.in/submissions/63) — all 6 sections filled+saved, 100% readiness, every section "Strong". User has attached the PPT (2026-09-12). Demo video still to record (user's task) | Deck delivered; portal draft saved; PPT attached ✅; video recorded; user clicks Submit for review when ready | `/Users/bala/Downloads/TunnelScope_SIH26160_Double_Diamond_Deck.pptx`; portal shows "Draft saved – readiness 100%" |

## Roadmap to submission (not yet started)

These map to the PS's deliverables: working prototype, AI engine, dashboard, assessment report,
demo video, technical documentation, dataset. DEVELOP is done (DEC-023); T-030 is next.

| ID | P | Status | Task | Depends on | Acceptance criteria |
|---|---|---|---|---|---|


 Each beats a stated simple baseline under a session-level split; calibrated confidence |



| T-038 | **P1** | DONE | Dataset release packaging | T-023 ✅ | `dataset/README.md` + `DATASHEET.md` + `build_manifest.py` (71 pcaps, hash-verified); `python3 dataset/validate.py` → PASS |

| T-040 | **P1** | DONE | SIH pitch deck + jury Q&A + demo script (video is the user's to record) | T-039 ✅ | `build/sih/PITCH-DECK.md` (11 slides), `JURY-QA.md`, `DEMO-SCRIPT.md` (6 steps, commands verified against real captures) |


## Blocked

_None._ (2026-09-12: user confirmed **no deadline** → build the full staged system per DEC-023,
not a compressed version.)

---

## Done

| ID | Task | Evidence |
|---|---|---|
| T-047 | EXP-10 vendor-diversity via free/open-source alternative (user request). OpenIKED/OpenIKEv2/racoon2 each ruled out with evidence (dead/archived/unstable). Built a real OpenBSD 7.9 arm64 VM (Parallels, native, isolated network) running genuine `iked`; strongSwan 6.1.0 (macOS host) negotiated against it — a real, architecturally independent third codebase. `ike_meta`/`ike_crypto`/PQ-posture and EXP-06 failure-diagnosis all generalized correctly on a real auth failure (byte-exact to `iked`'s own log); **also found a genuine gap**: the same heuristic misdiagnosed a real success as rejected (no ESP sent) — reported honestly, not hidden. Also surfaced OpenBSD's own PQ mechanism (`sntrup761x25519`) our detector doesn't recognize (scoped follow-up). 74 pcaps, dataset validator PASS, e2e still 69/69 | `experiments/exp10-openbsd-iked-generalization/RESULT.md`, `testbed/captures/exp10/` (pcap + groundtruth.json), `research/registers/EXPERIMENT-REGISTER.md` |
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
| T-012 | EXP-05 metadata leakage — all 5 pre-registered predictions held; TFC padding zeroes size leakage (+54% bytes) yet class inference stays at F1 0.995; ML justified only as a measuring instrument; 2 analysis bugs caught | `experiments/exp05-metadata-leakage/RESULT.md` |
| T-011 | EXP-07 Libreswan 5.4 — 7/7 predictions held; protocol facts generalise; notify + fragmentation implementation-dependent (DEC-020) | `experiments/exp07-libreswan-generalization/RESULT.md` |
| T-014 | 09-DEFINE updated with EXP-01/03/04/05/06/07 outcomes; 8 of 13 capability rows now deterministic | `research/09-DEFINE.md` |
| T-015 | **DEVELOP / GATE-5** — 8 concepts + 2 composites; weights committed before scoring; K1 selected (wins 22/23 weighting scenarios); red team; staged build order (DEC-023) | `research/12-DEVELOP.md`, `research/data/develop_*.json` |
| T-043 | User request: finish every pre-build item before building — all done | commits `982da43` → `32ca480` |
| T-044 | EXP-08 mode inference — **NOT-OBSERVABLE at T0**: fixed +20 B offset only with a paired baseline; without one every ESP length is valid in both modes. Resolves the last candidate-ML row → only CS-01 leakage remains ML (DEC-024) | `experiments/exp08-mode-inference/RESULT.md` |
| T-013 | EXP-04 follow-up — reassembled the fragmented IKE_INTERMEDIATE: initiator KE plaintext 1216 B vs responder 1112 B = **104 B asymmetry**, matching ML-KEM-768 ek(1184)−ct(1088)=96 B. PQ-6 confirmed as secondary signal | `experiments/exp04-pq-length-asymmetry/reassemble_ke.py` + `results/t013_ke_asymmetry.json` |
| T-024 | EXP-04 oracle — **four independent sources** agree ADDKE1 ID 36 = ML-KEM-768: IANA registry (RFC-ietf-ipsecme-ikev2-mlkem-09), Wireshark master `packet-ike.c`, tshark 4.6.4/4.6.8 parsing our capture, strongSwan T2 log | this table; IANA + Wireshark master verified |
| T-022 | EXP-09 CVE-2026-78135 detector — **shipped in the package** (`extract_early_childsa_cve` + `rules/cve-2026-78135.yaml`), deterministic + vantage-aware. Three validation layers: specificity 0 FP/69, sensitivity 1/1 on a synthetic plaintext-structural positive, AND sensitivity confirmed on a **genuine live fault-injected exploit** (real strongSwan 6.1.0 traffic, two one-line build-asserted patches, isolated Docker lab, root-cause gate bypass independently confirmed via the daemon's own debug log). OQ-31 closed | `experiments/exp09-early-childsa-cve/RESULT.md`, `tests/test_cve.py` (7), `testbed/captures/{synthetic,exploitlab}/`, `testbed/images/strongswan-exploitlab/`, `testbed/docker-compose.exploitlab.yml` |
| T-045 | Stage-3 C5 cross-tier consistency — `tunnelscope/crosstier/` reconciles T2 endpoint telemetry vs T0/T1 findings: escalation (resolves NOT-OBSERVABLE mode), confirmation/refinement (ESP cipher family→exact), CONTRADICTORY (the real NOTES #13 IP-TFS case). CLI `crosstier`. Trust stays causal (T2 is ground truth). 8 tests | `tunnelscope/crosstier/crosstier.py`, `build/02-CROSSTIER.md`, `tests/test_crosstier.py`, `testbed/telemetry/` |
| T-023 | Dataset hygiene — `dataset/build_manifest.py` (69 pcaps, per-file SHA-256, causal T2 ground truth, vantage, train/val/locked-test split by session/config) + `dataset/DATASHEET.md` + strict `dataset/validate.py` (exits non-zero on hash/provenance/leakage violations; **PASS**). Credits `naman9271/ipsec-pcap-lab` | `dataset/` |
| T-025 | OQ-30 closed — Palo Alto Quantum Readiness inventories TLS/SSH via decryption logs + its OWN VPN tunnels; third-party IPsec merely transiting is NOT inventoried. The doc-11 assessment gap stands | `research/11-...md`, OQ-30 |
| T-030 | System architecture — `build/00-ARCHITECTURE.md`: components, data flow, 9 design invariants, requirement traceability, 6 ADRs, staged build order, testing strategy | `build/00-ARCHITECTURE.md` |
| T-031 | Evidence extraction layer — `tunnelscope/` package: tshark ingest (reuse, ADR-001), Finding/EvidenceRecord core with mandatory status (ADR-002), 5 extractors (ike_meta, pq_addke, pfs, mode, failure) + CLI. Reproduces EXP-03/04/06/08 on BOTH implementations; 9 tests vs ground truth pass | `tunnelscope/`, `tests/test_extract.py` |
| T-032 | Deterministic assessment engine — `tunnelscope/assess/engine.py` + 3 versioned baseline files (`rules/`: DISA VPN SRG, RFC 8247, DST/NQM). Verdicts PASS/FAIL/UNKNOWN/NOT-OBSERVABLE/CONTRADICTORY, each citing authority+rule+evidence. Demonstrates the MODP-2048 multi-baseline split (PASS RFC 8247 / FAIL DISA). 4 tests incl. zero-false-PASS pass. Added `ike_crypto` + `cipher_sieve` extractors | `tunnelscope/assess/`, `rules/`, `tests/test_assess.py` |
| T-033 | PQ posture + downgrade assessor + CBOM (CS-05, DEC-017) — `tunnelscope/pq/cbom.py` emits CycloneDX 1.6. Full chain proven on a dedicated **downgrade arm** (`pq-downgrade.pcap`: ML-KEM offered, MODP-2048 selected, 0 IKE_INTERMEDIATE): extractor→`offered-but-not-used`, DST-PQ-DOWNGRADE→FAIL, CBOM posture→DOWNGRADED. CBOM never overstates (gaps recorded). 4 tests | `tunnelscope/pq/cbom.py`, `tests/test_pq_cbom.py`, `testbed/captures/pq-downgrade.pcap` |
| T-035 | Security score — `tunnelscope/score/score.py` + `build/01-SCORING-METHODOLOGY.md`. Per-baseline (never one number), severity-weighted pass rate over ASSESSABLE rules, coverage reported alongside, sensitivity-tested (stable/fragile). Returns None (not a fake score) when nothing is assessable. 3 tests | `tunnelscope/score/`, `build/01-SCORING-METHODOLOGY.md` |
| T-036 | Reports — `tunnelscope/report/report.py`: executive + technical from the evidence graph (I8). Every finding tagged observed/inferred/not-observable; every verdict cites its authority; multi-baseline scores + fragility note; downgrade + high-severity surfaced. CLI `report`. 2 tests | `tunnelscope/report/`, `tests/test_report.py` |
| T-034 | Leakage-measurement module (CS-01, Stage 2) — `tunnelscope/leakage/leakage.py`: per-capture size/timing entropy in bits + TFC-padding detection, wired into the pipeline. Verified: unpadded leaks size+timing; TFC-padded → size 0 bits, timing remains (EXP-05). Reports bits, never a traffic label (DEC-021). Also fixed ESP-only flow handling (T0 forensic). 3 tests | `tunnelscope/leakage/`, `tests/test_leakage.py` |
| T-039 | End-to-end validation — `build/validate_e2e.py`: runs the full pipeline over all 69 dataset captures, checks every finding vs causal ground truth. **69/69 pass, 0 mismatches**, both implementations; standing anti-overclaim checks (mode never valued at T0; no ESP key length) enforced. Exits non-zero on any mismatch | `build/validate_e2e.py`, `build/E2E-VALIDATION.md` |
| T-041 | Technical documentation — `tunnelscope/README.md` (install, usage, design, the one ML component, trust/limits, tests) | `tunnelscope/README.md` |
| T-037 | Analyst dashboard — `tunnelscope/report/dashboard.py`: self-contained, offline HTML (ADR-006), theme-aware, status-colour-coded (observed/inferred/not-observable/contradictory distinct, DEC-008). Per-SA posture badge, per-baseline scores+coverage, fragility note, verdict + evidence tables, "not observable" section. CLI `dashboard`. Rendered + verified | `tunnelscope/report/dashboard.py`, `build/demo/` |
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
- **2026-09-12** — **T-043 complete: planning finished.** EXP-05 and EXP-07 done; T-014 done;
  T-015 DEVELOP done: K1 selected (DEC-023). Only non-gating items remain (T-013, T-022–T-025,
  T-044). Next: T-030 architecture. Still blocked on the user: the SIH deadline.
- **2026-09-12** — User: finish all processes before building. Closed T-044 (mode NOT-OBSERVABLE at
  T0 — last ML row resolved), T-013 (KE asymmetry 104 B ≈ 96 B theoretical), T-024 (4-source ML-KEM
  oracle), T-022/EXP-09 (CVE detector, 0 FP, vantage-aware). Remaining: T-023, T-025.
- **2026-09-12** — T-023 (dataset manifest + datasheet + strict validator, PASS) and T-025 (Palo
  Alto does NOT assess transiting third-party IPsec) done. **All pre-build processes finished.**
  Next: T-030 architecture.
- **2026-09-12** — User: no deadline → full staged build (DEC-023). Blocker cleared. Starting the
  build phase with T-030 (system architecture) as the first act of building.
- **2026-09-12** — BUILD started. T-030 architecture (9 invariants, 6 ADRs, traceability). T-031
  evidence extraction: tunnelscope package works end-to-end, reproduces every experiment finding on
  strongSwan AND Libreswan captures, 9 ground-truth tests pass. Next: T-032 assessment engine.
- **2026-09-12** — T-032 assessment engine done: rules as versioned YAML, multi-baseline verdicts
  with citations, zero-false-PASS validated, the MODP-2048 RFC-vs-DISA contradiction shown live.
  13 tests pass. Building T-033 (PQ assessor + CBOM) next.
- **2026-09-12** — T-033 done: PQ downgrade detection + CycloneDX CBOM export, proven end-to-end on
  a dedicated downgrade arm. 16 tests pass; dataset validator still PASS. Next: T-035 score, T-036 reports.
- **2026-09-12** — T-035 score (per-baseline, coverage-aware, sensitivity-tested) and T-036 reports
  (exec + technical from evidence graph) done. 21 tests pass. Stage 1 MVP is essentially complete
  (ingest→evidence→assess→score→report→CBOM, all deterministic). Next: T-034 leakage module (Stage 2).
- **2026-09-12** — T-034 leakage module done (Stage 2): size/timing bits + padding detection wired
  into the pipeline; ESP-only forensic captures now produce records. 24 tests pass. Next: T-037
  dashboard (Stage 3), T-039 validation, T-041 docs.
- **2026-09-12** — T-039 end-to-end validation: 69/69 captures match ground truth, zero overclaims.
  T-041 tool README. Next: T-037 dashboard, T-038 dataset release packaging, T-040 pitch/Q&A.
- **2026-09-12** — T-037 dashboard: offline self-contained HTML, rendered and sent. All build
  components now exist (ingest→evidence→assess→score→report→CBOM→dashboard). Remaining: T-038
  dataset packaging, T-040 pitch/Q&A prep (demo video needs the user to record).
- **2026-09-12** — T-038 dataset release (README + datasheet + hash-verified manifest, validator
  PASS) and T-040 SIH materials (pitch deck, jury Q&A, demo script — commands verified against real
  captures) both DONE. **Build roadmap T-030–T-041 complete.** Remaining are the documented
  deferrals only: T-022 true-positive CVE arm (needs a malicious IKE stack) and the optional Stage-3
  C5 endpoint cross-check. The demo *video* is the user's to record from `build/sih/DEMO-SCRIPT.md`.
- **2026-09-12** — User: "complete everything left behind except the demo video." Closed both:
  **T-022** — wired the CVE-2026-78135 detector into the package as a real extractor + `CVE-WATCH`
  rule, and validated SENSITIVITY with a synthetic plaintext-structural positive (0 FP/69, 1/1 TP).
  **T-045** — built the optional Stage-3 C5 cross-tier module (T2-vs-wire reconciliation, incl. the
  NOTES #13 IP-TFS CONTRADICTORY). 38 tests pass (was 24), e2e still 69/69, dataset validator PASS
  (72 pcaps, synthetic fixture excluded from all ML splits). **Only the demo video now remains, and
  it is the user's to record.** The one stated out-of-scope gap is a live-crypto CVE exploit capture.
- **2026-09-12** — User: attempt both remaining stretch items (live CVE exploit, vendor-appliance
  validation). **live CVE exploit** — first pass cited the root-cause gate but stopped short
  (commit `fe52c31`); user pushed to finish it, so continued: mapped `initiate_tasks()`'s
  exchange-selection (picks exchange from the first recognized queued task type, independent of
  IKE_SA state), wrote two one-line, build-asserted patches (`testbed/images/strongswan-exploitlab/`:
  attacker skips activating `TASK_IKE_AUTH`; vulnerable relaxes the `reject_request()` gate), built
  an isolated Docker lab (`testbed/docker-compose.exploitlab.yml`, separate network from the
  validated testbed), and captured a **genuine live exchange**: real strongSwan 6.1.0 traffic
  showing `IKE_SA_INIT → CREATE_CHILD_SA` with zero `IKE_AUTH`. TunnelScope's detector fires FAIL
  (high) on it — same result as the synthetic positive, now on real traffic. Gate bypass
  independently confirmed via the responder's own cfg-debug log (reached TS evaluation, past the
  state check). Honestly documented what did NOT happen too: no Child SA installed (T2: empty on
  both sides), root cause diagnosed (responder has no linked child_cfg without IKE_AUTH's identity
  selection) rather than left unexplained. **T-022 now genuinely complete at the wire-detection
  level** (`experiments/exp09-.../RESULT.md`, `tests/test_cve.py` — 7 tests). **Vendor-appliance
  validation (Cisco/Palo Alto/Fortinet)** — still genuinely blocked: needs licensed vendor VM images
  or hardware I have no way to obtain; not attempted because there is no legitimate path to do so
  without the user supplying access.
- **2026-09-13** — User: for vendor-diversity, "see for any other free or open source alternative
  and use it." Researched real alternatives (not assumed): OpenIKED's Linux port explicitly dropped
  (confirmed from its own commit history), OpenIKEv2 archived since 2020, racoon2 self-described
  unstable/abandoned ~15y — all ruled out with evidence, none faked as viable. Built a genuine
  OpenBSD 7.9 arm64 VM (Parallels Desktop, native — no emulation, this Mac is Apple Silicon) running
  real `iked`, on an isolated Host-Only network never touching the validated Docker testbed.
  strongSwan 6.1.0 (installed via Homebrew on the macOS host) negotiated against it — first real
  cross-check against a codebase outside the strongSwan/Libreswan lineage. User ran the one
  root-requiring step themselves (tcpdump capture) since I do not enter sudo passwords. Result
  (T-047/EXP-10): core deterministic extractors generalized correctly, including a byte-exact
  failure diagnosis on a real auth error — but also caught a genuine false negative (a real success
  misdiagnosed as rejected, because no ESP traffic had been sent) and a real generalization limit
  (OpenBSD's own PQ mechanism, `sntrup761x25519`, isn't recognized by our ADDKE-based detector).
  Both reported honestly, neither hidden. 74 pcaps, e2e still 69/69, dataset validator PASS.
