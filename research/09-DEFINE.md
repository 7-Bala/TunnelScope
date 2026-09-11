> **Updated 2026-09-12 (T-014):** rows R5, R8, R14 and the matching AI-Necessity rows now reflect
> EXP-01 (narrowed), EXP-03 (confirmed) and EXP-04 (confirmed); the failure-diagnosis row reflects
> EXP-06 round 2. Original wording preserved in git history.

# Define — Refined Problem, Requirements, AI Necessity, Success Metrics, Rejected Scope

**Status:** DEFINE phase output, built directly on Discover (docs 00–08, registers/). This is the
last document before the Research Exit Review and the go/no-go on entering DEVELOP.

---

## 1. Refined problem statement

**Original PS (compressed):** build an AI-driven platform that inspects IPsec traffic/streams,
identifies protocol/mode/algorithm/SA characteristics and inner traffic type, assesses security,
and produces reports — validated against a self-built testbed.

**Refined problem statement, built on the Discover evidence:**

> Build an **evidence-tiered IPsec/IKE posture-assessment framework** that (a) deterministically
> extracts everything observable at each of five defined vantage points (T0 passive-ESP through T4
> authorized active probe), (b) **measures** — rather than assumes — deployment behaviour that
> protocols do not expose declaratively (effective SA lifetime, rekey cadence, metadata leakage in
> bits), (c) evaluates findings against **explicitly named, versioned standards baselines**
> (RFC 8221/8247/9395, NIST SP 800-77r1, DISA VPN SRG), with every verdict tagged `PASS` / `FAIL` /
> `UNKNOWN` / `NOT-OBSERVABLE` / `CONTRADICTORY`, and (d) uses a narrow, justified statistical layer
> only where deterministic methods provably cannot resolve the question — with the layer's own
> performance reported as a security measurement in its own right, not as a claimed truth oracle.

This is a **relocation of the gap**, not a rejection of the PS. The PS's own five deliverable
groups (A–E) are all still addressed; several are re-scoped per the Observability Matrix
(01-DISCOVER §5), and one (inner-traffic ID) is reframed from a classification claim into a
leakage-measurement claim (CS-01), which is the only version of that requirement that survives
contact with the evidence in 04-DISCOVER.

---

## 2. Requirement disposition table

Every PS-derived requirement gets one of: **ACCEPT** (as stated) / **RE-SCOPE** (accepted, redefined)
/ **DECLINE** (explicitly, with reason and the nearest legitimate substitute).

| # | PS requirement | Disposition | Basis |
|---|---|---|---|
| R1 | Testbed: tunnel/transport, AES variants, DH groups, PFS, IPv4/IPv6, traffic types | **RE-SCOPE** — covering-array design, not full cross-product | DEC-004, 05-DISCOVER §5 |
| R2 | Capture IKE, ESP, AH, normal traffic | **ACCEPT** | Standard; parsers exist to reuse (D2) |
| R3 | Identify IPsec protocol / IKE version | **ACCEPT** — O at T1 | Observability Matrix A1–A2 |
| R4 | Identify tunnel vs transport mode | **RE-SCOPE** — I at T0/T1 (inferred, confidence-tagged), O at T2 | A7 |
| R5 | Identify encryption algorithm (ESP) | **RE-SCOPE, narrowed by EXP-01** — at T0/T1 the sieve reliably answers one question: *block-cipher (CBC) mode vs AEAD/counter/stream* (and only in that direction; AEAD evidence rules out CBC, CBC evidence cannot rule out AEAD). It **cannot** separate AES-GCM / AES-CCM / ChaCha20-Poly1305 / AES-CTR+HMAC (a 5-way ambiguity class). Exact suite at T2 | A5, EXP-01, DEC-013 |
| R6 | Identify AES-128 vs AES-256 | **DECLINE at T0/T1** (information-theoretically impossible, F-05); **ACCEPT at T1 for IKE SA / T2 for ESP SA** | F-05, headline negative result |
| R7 | Identify authentication algorithm | **RE-SCOPE** — disambiguate ESP integrity alg. (I at T0/T1) vs IKE peer-auth method (I at T1 via CERTREQ/SIGHASH presence) | A8 |
| R8 | Identify key exchange method | **ACCEPT, validated by EXP-04** — O at T1 (plaintext IKE SA transform). RFC 9370 ADDKE/PQ use is **deterministically detectable by four plaintext signals** (INTERMEDIATE_EXCHANGE_SUPPORTED notify, +16 B IKE_SA_INIT, presence of IKE_INTERMEDIATE, fragmentation), reproduced on strongSwan 6.0.2 and 6.1.0. Dissection itself is solved in Wireshark master (DEC-017); our capability is PQ **posture + downgrade assessment** | A9, EXP-04, DEC-017 |
| R9 | Identify SA characteristics | **RE-SCOPE** — split into O items (SPI, proposals) and **measured** items (lifecycle, rekey cadence) | A11, CS-03 |
| R10 | Predict traffic type inside ESP | **RE-SCOPE, substantially** — replace "predict identity" with "measure adversary inference capability / metadata leakage in bits" (CS-01); retain a capped, caveated classifier only as a secondary, explicitly-labelled-uncertain output | 04-DISCOVER §6, G-12 |
| R11 | Cryptographic strength / compliance | **ACCEPT, RE-SCOPED** — verdict always names its baseline (DEC-007); never an unqualified "compliant" | S-02, DEC-007 |
| R12 | Key lifetime | **RE-SCOPE** — IKEv2 negotiates none (F-02); report **measured** effective rekey behaviour, not a "compliant/non-compliant" lifetime check, except for IKEv1 Main Mode where it is genuinely observable | F-02, RL-003 |
| R13 | Replay protection | **RE-SCOPE** — passive: sequence-hygiene only (O); enforcement is **NOT-OBSERVABLE** below T2/T4 despite being a named DISA control (V-207212) | A12/A13, DEC-008 |
| R14 | PFS configuration | **ACCEPT at T0/T1 when a rekey is observed, validated by EXP-03** — PFS-on CREATE_CHILD_SA messages are larger by a fixed 256-byte gap (the KE payload), cleanly separable by one threshold, reproduced across runs. Before any rekey is observed: NOT-OBSERVABLE. O at T2 | A10, EXP-03 |
| R15 | Metadata exposure | **ACCEPT, this is CS-01's home** — the strongest, best-evidenced deliverable in the whole set | G-04, E-06/E-07 |
| R16 | Executive + technical reports, risk score, threat matrix, AI confidence score | **ACCEPT, RE-SCOPED** — score is a weighted, cited, sensitivity-tested construction (not invented); confidence score is calibrated/conformal, not raw softmax | DL-03, §4.4 |
| R17 | "AI-driven" framing (title) | **RE-SCOPE** — AI used only where the AI Necessity Matrix (§3) justifies it; framed publicly as "evidence-driven, AI-assisted" | E-01–E-05, DEC-006 |

**Net effect:** nothing from the PS is silently dropped. Six items are declined *in one specific
regime* (passive, no endpoint access) while remaining fully deliverable in another (endpoint
telemetry, or IKE-SA-level rather than ESP-SA-level). This is defensible because the regime
boundary is not our invention — it is dictated by RFC 7296's encryption boundary and confirmed
independently by practitioner behaviour (PE-01).

---

## 3. AI Necessity Matrix

| Capability | Rule-based possible? | AI required? | ML suitable? | LLM useful? | Recommended approach | Reason |
|---|---|---|---|---|---|---|
| IKE/ESP field parsing | Yes | No | No | No | Deterministic parser (reuse tshark/Zeek grammar as reference) | Solved problem; D2 |
| Standards compliance verdicts | Yes | No | No | No | Rule engine over versioned, cited registries (DEC-011) | Deterministic mapping to RFC/NIST/DISA clauses |
| ESP cipher-suite family (T0/T1) | **Partially** | No | No | No | Constraint sieve on IV/ICV/alignment (F-04) — **narrowed by EXP-01** to a one-directional CBC-vs-AEAD/stream test | Deterministic and converges at packet 1; ML cannot help because the ambiguity is structural (identical IV/ICV/alignment), not noisy |
| AES-128 vs 256 at T0/T1 | No — provably impossible | N/A | N/A | No | **Explicitly decline**; report NOT-OBSERVABLE | F-05 |
| SA lifecycle / effective lifetime | Yes | No | No | No | Time-series change-point detection on SPI transitions | Not a learning problem |
| PQ key-exchange / downgrade detection | Yes | No | No | No | Deterministic: transform ID where the parser supports ADDKE (Wireshark master); EXP-04's plaintext structural signals where it doesn't (Suricata, Zeek, nDPI, Arkime) | Zero AI needed; **validated by EXP-04** on two strongSwan versions |
| Tunnel vs transport (no endpoint) | Weakly | Possibly | **Yes, narrow** | No | Calibrated statistical classifier w/ conformal confidence over a small feature set (header length shift, MTU behaviour) | Genuine residual uncertainty after deterministic methods exhausted |
| PFS at rekey (no keys) | **Yes** | **No** | No | No | Single length threshold on CREATE_CHILD_SA (**EXP-03**: 256-byte gap) | **Changed from 'ML, narrow' to deterministic** — the signal is a fixed structural gap, not a distribution |
| Failure-mode diagnosis (CS-02) | **Yes** | **No** | No | No | Rules over plaintext structure with thresholds derived from protocol arithmetic (**EXP-06 r2**: 6-way separation at macro-F1 1.000; a fitted tree does no better). Proposal- vs TS-mismatch reported as one class — *provably* inseparable at T0/T1 | **Changed from 'genuine ML need' to deterministic** — zero-variance structural signatures, nothing to learn |
| Metadata-leakage quantification (CS-01) | No | **Yes, as instrument not oracle** | **Yes — the strongest ML justification in the project** | No | Classifier used to *estimate* Bayes error rate / mutual information (WeFDE/Cherubin methodology) | Low classifier accuracy = good security finding; immune to the accuracy-inflation crisis |
| Implementation/vendor fingerprinting | Partially (VID lookup) | Possibly | **Yes, narrow** | No | Shallow similarity match over VID + backoff timing + payload ordering | Small, interpretable feature space |
| Report narrative generation | No | **Yes, strictly bounded** | No | **Yes** | LLM templated **exclusively** from the evidence graph; never a source of facts, only phrasing | DL-03; explainability requires the evidence graph to already be correct before the LLM touches it |
| Inner-traffic *identity* classification (literal PS R10) | No | N/A | **Rejected as core claim** | No | Not built as a truth oracle; subsumed into CS-01 | E-01–E-05, DEC-006, G-12 |

**Summary judgment:** of thirteen capability rows, **six are purely deterministic**, **one is
explicitly declined**, **four use ML as a narrow, justified, calibrated instrument** (two of which —
CS-01, CS-02 — are the project's actual technical contributions), and **one uses an LLM strictly for
templated narrative, never for facts.** No component uses AI merely because the PS says "AI-driven."

---

## 4. Success metrics (not accuracy alone)

Per capability class, tied to the FP/FN asymmetry established in 03-DISCOVER §4:

| Capability class | Primary metric | Why not accuracy alone |
|---|---|---|
| Deterministic extraction | Exact-match rate against T2/T3 ground truth, per attribute | Binary correctness; accuracy is fine here because ground truth is authoritative |
| Compliance verdicts | Traceability rate (verdict → cited clause) = 100% mandatory; false-"PASS" rate on held-out misconfigurations | False assurance (R14 in RISKS.md) is the worst failure mode — must be driven toward zero, not traded off |
| Statistical inference (tunnel/transport, PFS) | Calibration error (ECE), conformal coverage at stated confidence, abstention rate | A confident wrong answer is worse than a correctly-uncertain one (DL-05) |
| Failure-mode diagnosis (CS-02) | Macro-F1 **plus** confusion-matrix cost-weighted by remediation cost (a wrong "PFS mismatch" diagnosis triggers a different fix than a wrong "TS mismatch" one) | Class costs are not symmetric (PE-02) |
| Metadata leakage (CS-01) | **Bits of mutual information**, Bayes-error-rate estimate, before/after TFC-padding delta | This *is* the security metric; not a classification accuracy at all (E-07) |
| Cross-tier consistency | Agreement rate between T0/T1 inference and T2/T3 ground truth, contradiction rate flagged | Validates the whole architecture continuously, not just at deployment |
| Dataset integrity (leakage control) | AES-128/256 negative-control experiment must show **near-chance** performance | A built-in contamination detector (05-DISCOVER §6) |

---

## 5. Explicitly rejected scope

- **Literal inner-traffic application identification as a truth claim.** Rejected on evidence
  (04-DISCOVER, G-12); replaced by CS-01.
- **Full combinatorial testbed matrix.** Rejected as wasteful; replaced by covering array + targeted
  microscopes (DEC-004).
- **Pretrained traffic transformers (ET-BERT/YaTC/NetMamba class) as core engine.** Rejected
  (DEC-006); permitted only as a documented, discredited-baseline comparison.
- **Unauthorized/unscoped active probing.** Rejected outright; T4 requires a logged scope assertion
  and refuses out-of-scope targets (03-DISCOVER §5).
- **Any unqualified "compliant" verdict.** Rejected (DEC-007) — every verdict names its baseline.
- **Solving tunnel-mode multiplexed source separation.** Rejected as a hackathon-scale goal (R-11 in
  RISKS.md); replaced by naming, measuring and bounding the degradation curve (G-12 revised).

---

## 6. What DEFINE resolved that DEVELOP now depends on

- A **relocated, defensible problem statement** that keeps every PS deliverable group but changes
  what "solving" each one means.
- A **requirement disposition table** that can be read aloud to a jury without contradiction.
- An **AI Necessity Matrix** with a specific, evidence-cited technique per row — this is the direct
  input to concept generation; no concept in DEVELOP may deviate from a row's disposition without a
  new decision entry explaining why.
- **Success metrics that are not accuracy**, which is the single most common way an ML-adjacent SIH
  project loses credibility on stage.

DEFINE is now sufficient to gate into DEVELOP (≥5 concepts, weighted matrix, red team) — subject to
the Research Exit Review below.
