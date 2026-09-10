# Assumption Register
Status: OPEN | VALIDATED | REFUTED | RETIRED. Every assumption needs a validation method.

| ID | Assumption | Basis | Impact if wrong | Validation method | Status |
|---|---|---|---|---|---|
| H-A | A deterministic-first architecture with a small calibrated statistical layer beats an ML-centric one for this PS | Observability Matrix (01-DISCOVER §3–5) | We would under-use ML and lose "AI-driven" credit | Must survive ≥4 rival concepts + weighted matrix in DEVELOP | OPEN |
| A-01 | Judges reward honest "not recoverable" verdicts when paired with a legitimate alternative input | Prior report's winner-pattern research (report.md) | Honesty framing backfires; need a different narrative | Mentor feedback; SIH rubric (novelty/feasibility/practicability) | OPEN |
| A-02 | We can build a strongSwan-based testbed on available hardware (Linux netns or containers) | strongSwan is open source, netns-friendly | Testbed cost/time explodes; dataset generation blocked | Build a 2-node netns tunnel end-to-end in <1 day | OPEN |
| A-03 | The evaluation vantage point that matters most is V1 (IKE visible), not V0 | Most captures in an audit context start before tunnel setup | If V0 dominates, ~10 attributes drop to "not recoverable" and the product shrinks | Stakeholder research D3 | OPEN |
| A-04 | Inner-traffic character profiling (not app identification) is both learnable and acceptable | 01-DISCOVER §4 | Requirement C's last bullet is unsatisfiable in any form | Experiment + literature (OQ-04) | OPEN |
| A-05 | ESP length-residue sieve (F-04) works across implementations, not just strongSwan | RFC-fixed constants | A5 drops from I to N at V0 | Test strongSwan + Libreswan (+ a vendor pcap if obtainable) | OPEN |
| A-06 | The team has Linux/networking capability and time for a testbed-first project | Not yet established | Whole plan is mis-sized | Ask the user | OPEN |
| H-B | The classifier-as-measuring-instrument reframing (CS-01) is acceptable to SIH judges as a satisfaction of "predicted type of traffic inside ESP" | D4 sec 6 | We would need to also ship a literal (weaker, caveated) classifier to satisfy the wording | Mentor feedback; present both framings | OPEN |
| H-C | strongSwan's IP-TFS (RFC 9347) implementation is mature enough to run in our testbed | strongSwan docs describe it as supported | OQ-17 becomes unmeasurable; fall back to tfc_padding only | Build it early in Phase 1 | OPEN |
| H-D | The F-04 length-residue sieve survives NAT-T/UDP encapsulation, IPv6, and padding-policy differences | Constants are RFC-fixed | A5 drops from I to N at T0 | Testbed + Wireshark reference captures | OPEN |
| A-07 | Practitioner evidence from vendor KBs generalises to government/NTRO deployments | Multi-vendor agreement | Stakeholder model skewed toward enterprise | Seek any Indian-government IPsec operational material | OPEN |
| H-E | CS-05 (PQ-readiness + downgrade observability) is genuinely unserved by existing tools | Wireshark issue #21072 confirmed; Zeek/Suricata unverified | Novelty claim weakens to "we integrate it well" rather than "nobody does it" | OQ-25, OQ-26, OQ-27 | OPEN — **highest-priority assumption to test** |
| H-F | Judges/mentors will value policy alignment (DST/NQM Task Force) as strongly as technical novelty | NTRO is a national technical organisation; SIH rubric includes impact and practicability | We over-invest in the policy narrative | Mentor feedback | OPEN |
| H-D | ESP length-residue sieve (F-04) survives NAT-T/UDP encapsulation, IPv6, padding differences | validated in principle, weakened in scope | see DEC-013 | strongSwan-only so far; Libreswan (EXP-07) pending | REFINED — narrower claim confirmed, original strong claim REFUTED |
| H-E | CS-05 (PQ-readiness + downgrade observability) is genuinely unserved by existing tools | Wireshark #21072 confirmed; now also EXPERIMENTALLY validated with 4 independent signals | testbed EXP-04 | — | VALIDATED (experimentally, strongSwan-only) |
