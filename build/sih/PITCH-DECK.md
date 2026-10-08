# TunnelScope: pitch deck

One section is one slide. Speaker notes are in _italics_.

---

## 1 · Title
**TunnelScope**: AI-powered IPsec VPN analysis and security assessment.
SIH 2026 · SIH26160 · NTRO · Blockchain & Cybersecurity.
_It tells you what your VPN actually negotiated, how strong that is, and how to fix it._

---

## 2 · The problem
- A tunnel is only as strong as what it negotiated: the cipher, the key-exchange group, forward secrecy,
  key refresh, replay protection and, now, post-quantum key exchange.
- The configuration file says one thing; the wire can say another.
- Wireshark shows the fields, but an expert still has to read them and know which standard they break.
- India's post-quantum guidance (DST / National Quantum Mission, February 2026) asks critical
  infrastructure for a cryptographic inventory by 2027 and names VPNs.
_Nobody can build that inventory without knowing what each tunnel is really using._

---

## 3 · What we built
A pipeline: **capture or live stream → tshark → evidence records → rule engine and AI models → threat
matrix and risk score → reports, CBOM, ledger, dashboard and fixes.**
Passive: no VPN keys, nothing decrypted. Every finding says how it is known (observed, inferred or
measured) and every verdict cites its rule.

---

## 4 · What it reads
IKE v1 and v2, ESP and AH, security-association lifecycle, handshake cipher, integrity and DH group,
ESP cipher family, tunnel or transport mode, perfect forward secrecy, rekey timing, replay behaviour,
ML-KEM post-quantum key exchange and post-quantum downgrades, known-vulnerability patterns.
_Live demo: the downgrade capture. The verdict reads DOWNGRADED and names the failed rule._

---

## 5 · How it judges
- Rules live in YAML files, one set per standard: DISA VPN SRG, RFC 8247, RFC 8221 and RFC 4303, and a
  post-quantum readiness baseline from the DST report.
- A threat matrix rates each threat by likelihood and impact and links it to its evidence.
- One 0-100 risk score comes with its drivers.
- Per-standard scores stay separate: the same tunnel can pass one baseline and fail another, and the
  auditor sees both.

---

## 6 · The AI
- Random Forest models we trained ourselves read packet size and timing to predict what kind of
  traffic is inside an encrypted tunnel, with a confidence for each prediction.
- A second model detects tunnels that carry a mix of traffic.
- Anomaly detection compares each tunnel with its own history, so a cipher change or a downgrade stands out.
_The content is encrypted; the shape of the traffic is not._

---

## 7 · It fixes what it finds
- Every failed check gets a remediation plan: what is wrong, which standard says so, the exact change.
- For weak strongSwan settings TunnelScope applies the fix itself, in the lab or on a real gateway
  over SSH: allowlisted command, dry run on a copy, apply, capture again to confirm, automatic
  rollback if anything breaks, full audit log. A real gateway needs accepted written terms first.
_Demo: a failed rule, the proposed change, "Confirmed fixed"._

---

## 8 · What the user gets
Dashboard (single tunnel, fleet, live), executive and technical reports, a CycloneDX cryptographic bill
of materials for post-quantum planning, a tamper-evident evidence ledger, and a config check that
compares a strongSwan or Libreswan file with what appeared on the wire. Verdicts export to a SIEM as
Elastic ECS, syslog, Zeek or Suricata EVE-style JSON, and live alerts as ECS, syslog or JSON lines.

---

## 9 · Built and validated
- A Docker testbed with three IPsec implementations: strongSwan, Libreswan and OpenBSD iked.
- Tunnel and transport mode, AES-128/256 in CBC, CTR and GCM, ChaCha20-Poly1305, MODP and
  elliptic-curve groups, ML-KEM-768, PFS on and off, IPv4 and IPv6, AH, real applications.
- Hash-verified captures whose correct answers come from the endpoints' own logs.
- Every experiment pre-registered: predictions committed to git before the data existed.

---

## 10 · Architecture and deployment
Python and tshark, rules as versioned YAML, scikit-learn models, SQLite, React and TypeScript
dashboard. Runs on one analyst machine or server inside the organisation. Open source (Apache 2.0).
Adding a standard or a rule is a file change.

---

## 11 · Impact
Defence and NTRO teams, CERT-In, banks, telecom operators and critical infrastructure can check their
own tunnels, and tunnels shared with partners, without asking for keys. Hours of expert Wireshark work
become a cited report and a fix anyone on the team can act on, and a clear start for post-quantum
migration.
