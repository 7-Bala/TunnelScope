# Risk Register
Severity x Likelihood, both 1-5.

| ID | Risk | Sev | Lik | Exposure | Mitigation | Owner | Status |
|---|---|---|---|---|---|---|---|
| R-01 | We build an ML classifier for something deterministically solvable, and a judge notices | 5 | 4 | 20 | AI Necessity Matrix is a hard gate; every ML component must beat a measured deterministic baseline | Lead | OPEN |
| R-02 | Inner-traffic classification result is a testbed artifact that does not generalise (shortcut learning) | 5 | 4 | 20 | Leave-one-config / -implementation / -network-condition-out splits; feature occlusion per SoK 2503.20093 | ML | OPEN |
| R-03 | Overclaiming: reporting AES-256 detection at V0 (impossible per F-05) | 5 | 3 | 15 | Observability Gate; vantage point printed on every finding | Lead | MITIGATING |
| R-04 | Zeek's existing IPsec analyzers already cover our "novelty" | 4 | 3 | 12 | D2 teardown before any architecture; reuse rather than rebuild parsers | Lead | OPEN |
| R-05 | Security score is invented and cannot be defended | 4 | 4 | 16 | Every scoring dimension maps to a cited standard; publish the weight rationale; show sensitivity | Sec | OPEN |
| R-06 | Testbed combinatorics consume all the time; no validation left | 4 | 4 | 16 | Covering-array design (DEC-004); automate capture+label from day one | Infra | OPEN |
| R-07 | No access to real analysts ⇒ stakeholder findings are speculation | 3 | 4 | 12 | Label inference explicitly; use documented workflows (NIST SP 800-77r1, vendor runbooks) as proxies | Lead | OPEN |
| R-08 | Data leakage across train/test (same session/host/capture window) inflates results | 5 | 4 | 20 | Split by SESSION and by CONFIGURATION, never by packet or flow | ML | OPEN |
| R-09 | Ethical/scope drift: inner-traffic inference becomes a surveillance capability | 4 | 2 | 8 | Reframe to traffic-character profiling for exposure assessment; lab-only; document the boundary | Lead | OPEN |
| R-10 | Analysis paralysis — research phase never converges | 4 | 3 | 12 | Gates with explicit pass criteria; unresolved items move to OQ register rather than blocking | Lead | OPEN |
| R-11 | We attempt to SOLVE tunnel-mode multiplexed source separation (G-12) and fail publicly | 5 | 3 | 15 | Reframe: be the project that NAMES, MEASURES and BOUNDS the degradation curve rather than claiming to solve it | Lead | MITIGATING |
| R-12 | We rebuild a parser that Zeek/Wireshark already ship, and a judge notices | 4 | 3 | 12 | DEC: reuse tshark/Zeek as ingestion and as independent oracles; our layer sits above parsing | Lead | MITIGATING |
| R-13 | Active probing (T4) is used against an out-of-scope target | 5 | 2 | 10 | Signed scope assertion, target allowlist, rate limits, refusal + audit log; T4 disabled by default | Sec | OPEN |
| R-14 | The system emits "compliant" where a control was simply unassessable | 5 | 3 | 15 | DEC-008: UNKNOWN/NOT-OBSERVABLE as first-class verdicts, visually distinct | Sec | MITIGATING |
| R-15 | Our own dataset contains a leakage artifact and every result is invalid | 5 | 3 | 15 | DEC-009 split rules + feature occlusion + the AES-128/256 negative control as a built-in contamination detector | ML | MITIGATING |
| R-16 | GPL-3 (ike-scan) or Nmap NPSL contaminates the deliverable's licensing | 3 | 3 | 9 | Shell-out only, never link/vendor; NSE reference-only; resolve OQ-14 | Lead | OPEN |
| R-17 | Testbed arms sharing a traffic selector can silently cross-route through a leftover SA, contaminating captures | 4 | 3 | 12 | Give every arm a distinct, non-overlapping traffic selector (experiment_matrix.json fix); explicitly terminate ALL other arms' SAs before each capture, not just the target arm's own | Infra | OPEN — root-caused in EXP-06 round 1 |
