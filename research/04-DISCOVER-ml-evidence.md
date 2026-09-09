# Discover D4 — What Encrypted-Traffic ML Can and Cannot Credibly Do

**Purpose:** answer Q9–Q12 and supply the evidence base for the AI Necessity Matrix in DEFINE.

**Bottom line up front:**

> The encrypted-traffic-classification literature is in a documented **credibility crisis**. Headline
> accuracies of 95–99% collapse to **10–40%** under honest evaluation, and **hand-engineered
> protocol-header features in a Random Forest beat pretrained transformers**. Any SIH submission
> that cites SOTA accuracy numbers as its expected performance is building on sand — and a
> knowledgeable jury member can say so in one sentence.
>
> **This is not a reason to avoid ML. It is a reason to use ML for a different job.** (§6)

---

## 1. The credibility crisis — three independent, converging sources

### E-01 `[STRONG]` — *SoK: Decoding the Enigma of Encrypted Network Traffic Classifiers* (2025)

- **"The majority of proposed encrypted traffic classifiers have mistakenly utilized unencrypted
  traffic due to the use of legacy datasets."** The field's headline results were, in large part,
  measured on plaintext.
- 348 feature-occlusion experiments show design choices causing overfitting.
- Recommends: modern genuinely-encrypted datasets, **feature occlusion as standard practice**, and
  empirical validation of assumptions before claiming success.

### E-02 `[STRONG]` — *The Sweet Danger of Sugar: Debunking Representation Learning for Encrypted Traffic Classification* (2025)

The most directly damaging evidence found. Under honest evaluation:

| Model | Claimed | **Per-flow split, frozen encoder** |
|---|---|---|
| ET-BERT (WWW'22) | ~98% | **10.9%** on 120-website classification |
| Deep models generally | 95–99% | **≤40%** on complex tasks |

Mechanisms identified:
1. **Per-packet train/test splitting leaks flow identity.** Packets from the same flow land in both
   train and test; models exploit implicit flow identifiers (TCP sequence numbers, timestamps).
2. **Unfrozen encoders mean the model retrains from scratch** — hundreds of thousands of fine-tuning
   samples required, contradicting the few-shot promise of representation learning.
3. **Pre-training contributes ~nothing.** *Randomising the model's weights before fine-tuning yields
   nearly identical downstream performance.*

And the finding that matters most for our architecture:

| Task | **Random Forest (hand-engineered header features)** | Best deep representation model |
|---|---|---|
| TLS-120 (with IPs) | **82.0%** | 71.0% |
| TLS-120 (no IPs) | 41.3% | 63.7% |

> **Shallow models with domain-engineered protocol features consistently match or exceed
> representation learning.** The authors frame this as a *"credibility crisis"* in ML for networking.

### E-03 `[STRONG]` — Pretraining/downstream dataset reuse

ET-BERT pretrains and fine-tunes on the **same** ISCX-VPN and CSTNET-TLS1.3 data; YaTC and
NetMamba do the same. Dataset reuse across upstream and downstream is *"uncommon and discouraged in
the CV and NLP domains"* — the encoder can memorise task-specific patterns that deceptively inflate
downstream scores.

### E-04 `[STRONG]` — Shortcut learning

*"Bias in the Shadows"* shows models latching onto features whose correlation with labels comes from
**dataset artifacts rather than protocol semantics**, performing well in-distribution and collapsing
under domain shift.

### E-05 `[STRONG]` — *Less is More: Simplifying Network Traffic Classification Leveraging RFCs*

The constructive counterpart to E-02: use **RFC/protocol specifications to select features**.
Result — competitive or superior accuracy versus deep-learning baselines, at far lower computational
cost, and with features that are *inherently understandable to network engineers*.

> **Convergent conclusion across E-01…E-05 `[STRONG]`:** for encrypted traffic, **protocol-informed
> feature engineering + shallow models is the evidence-backed choice**, and deep representation
> learning is currently unjustified. This is not a conservative hedge; it is what the corrected
> numbers say.

---

## 2. What the length/timing side channel genuinely *can* do

The literature is not uniformly negative. There is one class of result that has survived scrutiny
for nearly two decades:

### E-06 `[FACT]` — Wright et al., *Spot Me If You Can* (IEEE S&P 2008)

Packet **lengths alone**, under VBR audio + length-preserving encryption, identify **spoken phrases**
inside encrypted VoIP: ~50% average accuracy, **>90% for some phrases**. Significant enough that the
IETF wrote **RFC 6562** (*Guidelines for the Use of Variable Bit Rate Audio with Secure RTP*) in
response.

### E-07 `[STRONG]` — Website-fingerprinting security-estimation methodology

A whole methodology exists for **quantifying** this leakage rather than merely exploiting it:

| Work | Contribution |
|---|---|
| Cherubin, *Bayes, not Naïve* (PETS 2017) | Estimates the **Bayes Error Rate** — the smallest error achievable by *any* adversary on given features — using nearest-neighbour error as a proxy. A *lower bound on defence strength*, not one attack's score. |
| Li, Guo, Hopper — **WeFDE** (CCS 2018) | Measures a defence's **information leakage in bits** via mutual information between trace features and classes. |
| **DeepSE-WF** (2022) | Unifies BER and MI for security estimation. |

Core argument of that community: **classification accuracy is not a valid metric for evaluating a
defence.** You need adversary-independent measures.

### E-08 `[STRONG]` — Two-phase passive+active architecture is state of the art

*OpenVPN is Open to VPN Fingerprinting* (USENIX Security 2022 — **Best Paper + Internet Defense
Prize**) fingerprinted >85% of OpenVPN flows with negligible false positives using a **two-phase
framework: passive filter followed by an active prober**, explicitly modelled on how the Great
Firewall operates.

> `[INFER]` Top-tier VPN-analysis research does not choose between passive and active. It **stages**
> them: cheap passive filtering to find candidates, targeted active probing to confirm. This is
> direct precedent for the architecture decision in §5.

### E-09 `[EVIDENCE, thin]` — IPsec-specific classification prior work

Very sparse, and old:
- **Okada et al.** — Gaussian/Naïve-Bayes over encrypted-tunnel features; reported +28.5% improvement
  identifying tunnelled protocol when HTTP/FTP/SMTP/SSH are mixed over PPTP and IPsec.
- **Kumano et al.** — C4.5 to classify tunnel encryption type, then SVM on few-packet flow features
  for application ID; **92.5% on a private dataset**.

> `[INFER]` **Gap G-10.** There is essentially no modern, reproducible, publicly-datasetted work on
> classification *inside IPsec ESP specifically*. Both known results use **private datasets** and
> predate the entire methodological reckoning of E-01…E-05. Treat their numbers as unverified.

---

## 3. The trap the problem statement walks into

`[INFER]` **G-1 restated with force.** Published VPN traffic classification — including ISCXVPN2016,
VNAT, and both IPsec papers above — evaluates **one application flow per tunnel**. Production IPsec
**tunnel mode multiplexes an entire subnet's traffic onto one Child SA (one SPI)**.

Consequences:
- The observable is a **superposition** of many concurrent inner flows, not a single flow.
- "Which app is inside?" is ill-posed; the honest question is "which apps, in what proportion."
- This is blind source separation / multi-label mixture estimation, not classification.
- **A testbed that runs one application at a time through the tunnel will produce excellent
  accuracy that means nothing.** That is precisely the artifact E-04 warns about, and it is the
  single most likely way this project produces a scientifically worthless result.

`[UNK]` OQ-04 remains open: no work found that addresses the tunnel-mode mixture case. If that
survives further search, **it is a genuine research gap** — and a hard one.

---

## 4. Uncertainty, abstention and calibration — the mandatory layer

`[STRONG]` The PS asks for an "AI Confidence Score." Naïve softmax confidence is not one.

Established options, in increasing rigour:
- **Reject option / selective classification** — abstain on ambiguous or out-of-distribution input.
  Argued as *essential for practical deployment* because traffic datasets cannot contain all classes
  and new applications appear constantly (Luxemburk & Čejka, fine-grained TLS classification).
- **Calibration** (temperature scaling / isotonic) — produces probabilities operators can threshold
  per class against explicit cost profiles.
- **Conformal prediction** — distribution-free, finite-sample coverage guarantees under
  exchangeability; yields *prediction sets* with a stated error rate rather than a point guess.
  Already applied to hierarchical OS fingerprinting.

> **Design position (provisional):** the "confidence score" must be a **conformal or calibrated**
> quantity with a stated guarantee, plus an explicit abstain class. A number derived from a softmax
> is decoration, and a jury member who knows this will ask.

---

## 5. Explainability — necessary, but do not overpromise

`[STRONG]`
- SHAP/TreeSHAP is the dominant post-hoc method in IDS and does improve analyst trust.
- **But:** high model accuracy does not imply high-fidelity explanation, and **LIME and SHAP can be
  adversarially manipulated to produce misleading explanations while predictions stay correct.**
- ML/DL-based IDS still suffer explainability problems that stop administrators trusting them
  relative to signature/specification-based systems.

> **Design lesson DL-03.** Post-hoc explanation of a black box is strictly worse than an
> **intrinsically interpretable** pipeline. E-05 already shows RFC-derived features are competitive
> *and* natively meaningful to network engineers. Combined with D1's finding that most attributes
> are deterministically derivable anyway, the explainability requirement is best met by **not
> creating the black box in the first place**, and reserving SHAP for the small statistical residue.

---

## 6. The reframing that makes ML both necessary and honest

The evidence above appears to argue ML out of the project. It does not — it argues ML out of *one
job* and into a better one.

**Wrong job (what the PS literally asks, and what every competing team will build):**
> *"Predict the type of traffic inside ESP."* Truth claim. Vulnerable to every criticism in §1–§3.
> A high accuracy is unbelievable; a low accuracy is a failure. **No good outcome exists.**

**Right job — CS-01, the measurement reframing:**
> *"Measure how much this specific IPsec deployment leaks to a passive adversary."*
> The classifier is an **instrument**, not an oracle. Its performance **is** the security finding.

Why this survives everything in this document:

| Criticism from §1–§5 | Effect under the reframing |
|---|---|
| Reported accuracies are inflated (E-01/E-02) | We report *our own measured* adversary performance on *our own* deployment. No external number is inherited. |
| Deep models collapse; RF wins (E-02) | Fine — use the strongest instrument available; E-07's BER estimator is a *nearest-neighbour* method anyway. |
| Shortcut learning / dataset artifacts (E-04) | Still a threat, and still must be controlled — but a shortcut *inflates* measured leakage, giving a conservative (safe-direction) security verdict. |
| "Low accuracy = failed project" | **Inverted.** Low measured leakage = strong posture = a valid, publishable result. |
| Accuracy is not a valid defence metric (E-07) | Adopt BER + mutual information instead. Methodology already exists and is peer-reviewed. |
| Explainability of black boxes (E-05, DL-03) | The output is a leakage measurement in bits, not an unexplainable label. |

**And the remediation is standards-backed and testable in our own testbed `[FACT]`:**
- ESP TFC padding, RFC 4303 §2.7 — strongSwan `tfc_padding`, **default `0` = disabled**; `mtu` pads
  to path MTU.
- ESP dummy packets — RFC 4303 mandates next-header **59** to designate a dummy packet.
- **AGGFRAG / IP-TFS, RFC 9347 (Jan 2023)** — strongSwan `mode = iptfs`; constant-send-rate,
  fixed-size tunnel that aggregates multiple inner packets per ESP packet, *"expected to reduce the
  efficacy of traffic analysis."*

> **The demonstrable experiment:** hold everything constant; vary only
> `tfc_padding = 0 | mtu` and `mode = tunnel | iptfs`. Measure mutual information and Bayes error
> before and after. If leakage drops measurably, we have produced a **quantified,
> standards-mapped, reproducible security result** that no surveyed tool can produce.
> That is a real contribution, and it is a far better demo than a confusion matrix.

`[EXP]` Must be validated: does IP-TFS in strongSwan actually collapse the length channel as claimed,
and by how many bits? Nobody appears to have measured this publicly. **OQ-17.**

---

## 7. Provisional technique assignment (input to the AI Necessity Matrix, not the matrix itself)

| Capability | Technique | Justification |
|---|---|---|
| IKE payload/transform extraction | Deterministic parsing | D1 §3.2; already solved (D2 P-01) |
| Standards compliance verdicts | Rule engine over cited clauses | Deterministic; needs traceability, not inference |
| ESP cipher-suite family | **Deterministic constraint sieve** (F-04) | Beats a classifier and is explainable |
| SA lifecycle / rekey policy | Time-series measurement + change detection | F-02; not a learning problem |
| Tunnel vs transport (no keys) | Statistical inference w/ calibrated confidence | Genuinely uncertain (A7) |
| PFS at rekey (no keys) | Length-signature inference | Hypothesis A10 |
| Negotiation-failure mode (CS-02) | **Supervised classification over structural features** | Ground truth is free from the testbed; genuine ML need |
| Metadata leakage (CS-01) | **BER + MI estimation using a classifier as instrument** | E-06/E-07; the strongest ML justification in the project |
| Implementation fingerprinting | Similarity matching / shallow classifier over VID + backoff + ordering | Feature space is small and interpretable |
| Report prose generation | LLM, strictly templated from the evidence graph | Never as a source of facts |

**Explicitly rejected:** pretrained traffic transformers (ET-BERT/YaTC/NetMamba class) as the core
engine. Evidence E-02/E-03 is decisive, and adopting them would import the field's credibility
problem into our submission. May be run *only* as a documented baseline comparison.

---

## 8. Open questions from D4

- **OQ-04** (carried, high value) Any credible work on tunnel-mode multi-flow mixture classification?
- **OQ-17** (new) How many bits of leakage do `tfc_padding` and IP-TFS actually remove? Unmeasured
  publicly. `[EXP]`
- **OQ-18** (new) Does BER/MI estimation methodology from website fingerprinting transfer soundly to
  the multiplexed-tunnel setting, where classes are mixtures? Non-trivial; may need adaptation.
- **OQ-19** (new) Can conformal prediction give useful set sizes at realistic feature dimensionality
  here, or does it degenerate to "all classes"?
