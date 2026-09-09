# Research Exit Review

**Date:** 2026-09-09 · **Scope:** everything in Discover (00–08) and Define (09).

---

## 1. What we now know (evidence tier: FACT/STRONG)

- The ESP cipher suite, tunnel/transport mode, PFS decision, peer identities and traffic selectors
  are negotiated **inside encrypted IKE_AUTH / CREATE_CHILD_SA** (RFC 7296). Only the IKE SA's own
  algorithm/DH-group/key-length is plaintext (`IKE_SA_INIT`).
- **AES-128 vs AES-256 is provably unrecoverable from ESP traffic** at T0/T1. No structural, timing
  or statistical channel exists; this is a specification fact, not a modelling limit.
- **IKEv2 negotiates no SA lifetime at all** (RFC 7296 §2.4). "Key lifetime" must be measured, not
  read, except in IKEv1 Main Mode where it's plaintext.
- **Encrypted-traffic classification's published accuracy record does not survive honest
  evaluation.** ET-BERT: 98% claimed → 10.9% under per-flow splits with frozen encoders. Random
  Forest on protocol-derived features beats pretrained transformers. This is not a single paper's
  claim; it is corroborated by an independent SoK finding the majority of prior classifiers trained
  on unencrypted traffic due to dataset defects.
- **No public dataset contains IPsec traffic labelled with cryptographic configuration.** Confirmed
  by direct inspection of ISCXVPN2016's documented composition and VNAT's scope.
- **A DISA-named government control (anti-replay enforcement, V-207212) is passively unobservable**
  under any circumstance short of endpoint access or an active test.
- **Wireshark cannot decode RFC 9370 post-quantum key exchange** (GitLab issue #21072, with a
  reproduction capture attached) while **strongSwan 6.0.0 already negotiates it**
  (`x25519-ke1_mlkem768`).
- **A multi-surface observability framework with near-identical architecture to ours was
  independently published for TLS in 2026** (arXiv:2605.02978) and is explicitly scoped away from
  IPsec/IKEv2 by its own authors.
- Suricata's shipped IKEv2 weak-DH rule **silently failed for three separate, documented reasons**
  (bug #2861) — direction filtering, wrong event names, a transaction-handling bug dropping
  first-message events.

## 2. What we strongly believe (STRONG/INFER, not yet experimentally confirmed)

- The IV/ICV/alignment-based ESP cipher-family sieve (F-04) will narrow candidates sharply but not
  always to a singleton (AES-GCM/ChaCha20-Poly1305 share a length signature).
- PQ key-exchange detection by KE-payload length asymmetry (PQ-6) will work, because it follows
  directly from FIPS 203's fixed, asymmetric key/ciphertext sizes versus symmetric DH group-element
  sizes — this is closer to a mathematical certainty than a hypothesis, but it has not been run.
- Tunnel-mode multiplexing genuinely degrades inner-traffic classification versus the single-flow
  literature, though a related multi-flow clustering literature exists (Chen et al., IEEE TNSM 2024)
  that we initially missed and then found — meaning our own search process has already demonstrated
  it is not exhaustive by construction.
- Practitioner workflows (vendor KBs) corroborate the RFC-derived observability limits independently,
  which raises our confidence in F-01 specifically, but this is five vendor knowledge-base articles,
  not a survey of practitioners.

## 3. What remains uncertain

- Whether Zeek and Suricata's IKE parsers handle `IKE_INTERMEDIATE`/ADDKE (OQ-26) — unresolved,
  would only refine the PQ novelty claim, not invalidate it (Wireshark's gap is independently
  sufficient).
- Whether the PS's own statement ID is SIH26160 or SIH26161 (OQ-16) — trivial to resolve, not yet
  resolved, zero technical impact.
- Whether our stakeholder model (four roles) reflects real analyst behaviour or only vendor-support
  and government-document behaviour. **This is the weakest evidence tier in the entire research
  base.** We have zero direct practitioner contact.
- Whether SIH's own IP/licensing rules permit the GPL components we intend to shell out to (OQ-14).

## 4. What we currently believe is novel

Ranked by confidence:

1. **The IPsec/IKEv2 instantiation of a multi-surface evidence-tiered observability model**, with a
   data-plane extension (SA lifecycle, metadata leakage) that has no analogue even in the TLS
   framework that inspired the comparison. This is our strongest claim because it survived an
   adversarial check against convergent prior art and came out narrower but intact.
2. **PQ-readiness / downgrade detection for IPsec via plaintext structure**, including a
   dissector-independent length-signature method (PQ-6) that works on captures the leading tool
   cannot parse. Strong because it's grounded in a citable open tool-issue plus a shipped
   implementation plus a dated national policy mandate.
3. **Metadata-leakage quantification for IPsec deployments** using an adapted website-fingerprinting
   security-estimation methodology (Bayes error / mutual information) that, as far as this research
   found, has never been applied to IPsec. Strong in methodology, unproven in this domain.
4. **Deterministic ESP cipher-family inference from wire-format constants** (F-04) — moderate
   novelty; the *technique* (constraint satisfaction over fixed structural constants) is not new in
   general, but its application here appears absent from the surveyed tool ecosystem.

## 5. What we have explicitly discovered is NOT novel

- Parsing IKEv1/IKEv2/ESP/AH — solved by Zeek's Spicy IPsec analyzer and Wireshark.
- Basic weak-crypto/weak-DH alerting on IKE proposals — shipped in Suricata (with known, documented
  bugs we can cite and avoid repeating).
- IKE endpoint fingerprinting via Vendor ID and retransmission backoff — solved by ike-scan, though
  IKEv2-limited.
- Multi-flow encrypted traffic clustering in general (not IPsec-specific) — solved, to a claimed
  >99% F1, by Chen et al. 2024 (though that number should be read against the general ETC
  credibility crisis before being trusted).
- Multi-surface, evidence-tiered cryptographic observability as a *general pattern* — solved for TLS
  in 2026.
- Website/VoIP traffic-length side channels as a phenomenon — established since 2008.

## 6. What existing systems already solve

Ingestion and parsing (Zeek, Wireshark, tshark, Scapy), basic rule-based alerting (Suricata),
active IKEv1-era reconnaissance (ike-scan, Nmap NSE), authoritative endpoint state (strongSwan
vici/swanctl), and — critically — a full architectural pattern for cryptographic observability,
just not for our protocol.

## 7. What still appears unsolved

Interpretation and evidence-synthesis above the parser layer; SA-lifecycle measurement as a
lifetime proxy; standards-traceable multi-baseline compliance verdicts; IPsec-specific metadata
leakage quantification; IPsec PQ-readiness/downgrade detection; and diagnosis of *why* a negotiation
failed, from structure alone.

## 8. What requires experimentation rather than further research

Everything in `registers/EXPERIMENT-REGISTER.md` — eight experiments, sequenced, each with a
falsification criterion. None of these can be resolved by reading more; they require the testbed.
The highest-priority one (EXP-04, PQ length-asymmetry detection) can be run with strongSwan 6 and
Suricata alone, no custom tooling, likely in under a day.

## 9. What could invalidate our current direction

- If EXP-02 (the AES-128/256 negative control) shows *any* classifier scoring above chance, our
  entire dataset-generation pipeline has a leakage bug, and every other experimental result built on
  the same pipeline becomes suspect until re-validated. This is the single highest-leverage risk in
  the project and is exactly why it's sequenced early.
- If EXP-04 fails (PQ detection by length does not cleanly separate), the strongest opportunity
  found in Discover weakens from "structural certainty" to "needs a real classifier," which reopens
  the AI-necessity question for that capability.
- If direct practitioner contact (still unobtained) contradicts the four-role stakeholder model,
  the product-shape assumptions in Define would need revision — this is the least-tested part of the
  whole research base.
- If a licence check (OQ-14) rules out shelling out to GPL tools, the reuse strategy in D2 needs
  rework, though this affects engineering, not the technical direction.

## 10. What evidence is still missing

Direct practitioner interviews or documented internal workflows from an Indian government/enterprise
IPsec deployment; confirmation of the problem-statement ID; Zeek/Suricata source-level confirmation
on RFC 9370 handling; and all eight experiments in the register.

---

## Honesty requirement — direct answers

- **Is the current idea weak?** No. It is narrower and more defensible than the problem statement
  as literally written, which is the correct direction for narrowing to go.
- **Is the novelty weak?** Partially tempered, not weak. Two novelty claims were voluntarily
  narrowed this session after finding prior art (multi-flow clustering, TLS observability
  framework). That is the research process working as intended, not a sign of a hollow project. What
  survives — the IPsec instantiation, the data-plane extension, PQ downgrade detection, metadata
  quantification — is still a real, evidence-backed set of contributions.
- **Is the AI component unnecessary?** For roughly half the capabilities in the PS, yes, and we have
  said so explicitly rather than padding the design with decorative ML. For the other half (CS-01,
  CS-02, tunnel/transport and PFS inference), no — these have specific, cited justifications in the
  AI Necessity Matrix, and CS-01 in particular is *strengthened* rather than weakened by the honesty
  requirement, because a low classifier score there is a good result, not a failure.
- **Does an existing product already solve the problem?** No single product does. Parsing is solved
  piecemeal (Zeek/Wireshark). Assessment, in the sense the PS asks for, is not solved by anything
  found — the closest analogue (TLS observability) explicitly excludes our protocol.
- **Is the dataset insufficient?** Currently, yes — because it does not yet exist. This is expected
  at end of Discover and is itself one of the PS's required deliverables (A, and the dataset
  deliverable). The risk is not "insufficient," it's "not yet built," and the generation methodology
  and leakage controls are specified (05-DISCOVER).
- **Is the proposed evaluation unrealistic?** The metrics in 09-DEFINE §4 are more demanding than a
  typical hackathon submission's (calibration, mutual information, cross-tier consistency, a
  mandatory negative control), which is a real execution risk for a time-boxed team, flagged
  honestly rather than downgraded to look easier.
- **Is the project scope too large?** As stated in the PS, yes — this was established early
  (00-RESEARCH-PLAN) and is why R1/R10 were re-scoped and why the covering-array design (DEC-004)
  replaces the implied full cross-product. The *research* scope for Discover was also large — nine
  documents — but that breadth was in service of the Observability Gate, not padding; each document
  changed at least one requirement disposition or decision.
- **Is the problem statement itself technically flawed?** Yes, in a specific, bounded way: it asks
  for several observations (AES-128/256 discrimination at wire level, receiver-side replay
  enforcement from passive capture, literal inner-traffic identity) that are either
  information-theoretically impossible or require access the PS's own wording doesn't name. This is
  documented, not hidden, in the requirement disposition table (09-DEFINE §2), and every declined
  item has a named legitimate substitute.
- **Would another solution direction be stronger?** Not identified. The alternative framings
  considered and rejected (pure ML classifier product, pure compliance checklist, pure active
  pentest tool) are each strictly dominated by the evidence-tiered hybrid on at least one axis
  (feasibility, novelty, or honesty) — but this has not yet been tested against ≥5 concrete concepts
  in a weighted matrix, which is what DEVELOP is for. This review is not a substitute for that step.

---

## Marginal-value check

Could any single additional literature search plausibly change the problem definition, technical
direction, novelty claim, architecture, feasibility, or validation strategy right now? Reviewing the
open questions register: the remaining open items are either (a) resolvable only by running the
testbed (the eight EXPERIMENT-REGISTER items), (b) low-coupling administrative facts (statement ID,
licensing), or (c) refinements that would narrow an already-accepted claim further (Zeek/Suricata
RFC 9370 support) without reversing any decision on record. None meet the bar for continued broad
research.

---

# STATUS: RESEARCH FREEZE — MOVE TO EXPERIMENTATION

Broad discovery research is frozen. The eight items in `registers/EXPERIMENT-REGISTER.md` are now
the active work, sequenced EXP-04 → EXP-01/02 → EXP-03/05/06 → EXP-07/08. Concept generation
(DEVELOP, ≥5 concepts + weighted matrix + red team) may proceed in parallel with the experiments,
since the AI Necessity Matrix and requirement dispositions that concept generation depends on are
already evidence-bound and do not require experimental confirmation to draft candidate architectures
— but no concept may be *selected* until EXP-02 (the leakage/contamination gate) has run at least
once on real captured data.

Targeted research may reopen if an experiment produces a contradictory result, an unexplained
protocol behaviour, or surfaces a competing solution not found in this pass — not merely because
more sources exist to read.
