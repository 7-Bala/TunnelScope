# TunnelScope — SIH26160 Pitch Deck

One section = one slide. Speaker notes in _italics_.

---

## 1 · Title
**TunnelScope** — Evidence-tiered IPsec/IKE posture & post-quantum migration assessment.
SIH26160 · NTRO · Blockchain & Cybersecurity.
_An analyzer that tells you what your VPN actually negotiated — and is honest about what it can't see._

---

## 2 · The problem, precisely
Traditional tools give packet-level visibility that needs an expert to interpret. But the real gap
isn't parsing — it's **assessment**:
- The ESP cipher, mode, and PFS are inside the **encrypted** part of IKE.
- IKEv2 doesn't even negotiate a lifetime.
- No tool tells an operator: *is this tunnel compliant, against which standard, and is it
  post-quantum — or was PQ offered but classical negotiated?*
_We spent the research phase proving where the gap really is (research/ docs 01–11)._

---

## 3 · What we built
A pipeline: **capture → per-SA evidence records → verdicts against named standards → score →
reports + CBOM + dashboard.** Every finding declares its **status** (observed / inferred / measured /
**unknown** / **not-observable** / **contradictory**), its **vantage tier**, and its **evidence**.
Every verdict **cites the standard** it's judged against.

---

## 4 · The one idea that makes it different
**We never overclaim.** "We didn't see it" and "it isn't there" are different answers, structurally.
- A capture that starts mid-tunnel → the tool says UNKNOWN, not a guess.
- Tunnel vs transport mode from passive traffic → **NOT-OBSERVABLE** (we proved it, EXP-08).
- Absence of evidence is **never** scored as compliance.
_Competing submissions we found hardcode "Mode: Tunnel" and default to "AES-256-GCM + PFS" when they
can't see the handshake. That's a confident lie. We refuse to._

---

## 5 · The headline capability: post-quantum downgrade detection
strongSwan negotiates hybrid ML-KEM IPsec today. India's DST/National Quantum Mission mandates
crypto inventory and downgrade prevention for critical infrastructure by 2027.
**TunnelScope detects, from plaintext IKE, whether a tunnel is post-quantum, classical, or was
offered PQ but negotiated classical** (the cause is not attributable passively) — and emits a
CycloneDX CBOM.
_Live demo: the downgrade capture → posture DOWNGRADED, DST verdict FAIL._

---

## 6 · It's mostly deterministic — and that's a strength
The PS says "AI-driven." We use ML in exactly **one** place — measuring metadata leakage, and even
there we report **bits of exposure, never a traffic label**. Four capabilities the design *expected*
to need ML (PFS, failure diagnosis, fingerprinting, mode) we tested and showed to be **exact
structural signatures** — no ML needed. Honest AI beats decorative AI in front of a technical jury.

---

## 7 · Everything is validated
- 9 experiments, each **pre-registered** (predictions before data). 18/18 predictions held.
- On **two independent implementations** (strongSwan + Libreswan).
- **69/69** captures pass end-to-end validation against causal ground truth.
- First IPsec dataset labelled with cryptographic configuration.
_We can show the pre-registrations and the git history: weights and predictions committed before results._

---

## 8 · Multi-baseline compliance (the honest verdict)
The same tunnel scores **100 on RFC 8247** and **38 on DISA** — because MODP-2048 meets one baseline
and not the other. We show **both**, each citing its authority (RFC 8221/8247/9395, NIST SP 800-77r1,
DISA VPN SRG, DST/NQM). A single "87/100" would hide exactly the thing an auditor needs.

---

## 9 · Architecture & deployment
Python + tshark (reused, not rebuilt), rules as versioned YAML data, SQLite, offline by default —
no cloud, air-gap-friendly for an NTRO context. Runs as a CLI; dashboard is a single self-contained
HTML file. Vantage ladder T0→T4: fully useful passively, more with endpoint access.

---

## 10 · Honest limits (we say these first)
- Traffic in the leakage experiment is synthetic — we report **measured leakage on your own tunnel**,
  so no synthetic number is inherited.
- Validated on two open-source stacks; **vendor appliances untested**.
- The CVE-2026-78135 detector: 0 false positives on 67 judgeable legitimate lab captures (2 more
  were correctly UNKNOWN); 95% upper bound ≈ 4.4%. Reproduced live in an isolated lab with a
  patched strongSwan (EXP-09), where the detector fired; the lab responder still rejected the Child
  SA, so a successful exploit isn't shown.

---

## 11 · Impact & ask
A defensible, deployable assessment tool aligned to a **dated national mandate**. It fills the gap
no surveyed open-source tool or commercial product covers: **assessing third-party IPsec, including
post-quantum posture, from the wire, with cited evidence.**
_Ask: [scale-up / pilot with an NTRO deployment / dataset publication]._
