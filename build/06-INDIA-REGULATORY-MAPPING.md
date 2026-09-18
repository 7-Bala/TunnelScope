# 06 — Indian regulatory mapping (evidence, not compliance)

**Mentor follow-up D** (`research/13-MENTOR-APPLICATION-REVIEW.md` §5). Written 2026-09-19 from the
primary texts. Data: `tunnelscope/rules/context/india.yaml`; code: `tunnelscope/assess/context.py`;
output: a section in both reports (`tunnelscope report`).

## The one-sentence position

The DPDP Rules and CERT-In's guidelines **require encryption without saying which algorithms**, so
no capture can show "compliance" with them. TunnelScope provides **audit evidence** for the
in-transit part: whether an IPsec link encrypts, how strongly, against which named standard, and
whether the endpoint would accept something weaker. Every report section says that, and says what a
capture cannot show.

## What the texts actually say (read 2026-09-19)

### DPDP Rules, 2025 — G.S.R. 846(E), Gazette of India, 13 November 2025
- **Rule 6(1)(a):** *"appropriate data security measures, such as securing of personal data through
  encryption, obfuscation, masking or the use of virtual tokens mapped to that personal data"*.
- **Rule 6(1)(g):** *"appropriate technical and organisational measures to ensure effective
  observance of security safeguards"*.
- **Rule 6(1)(b)–(f):** access control, access logs with review, continuity/backups, one-year
  retention of logs and personal data, processor contracts. A capture shows none of these.
- **Commencement, rule 1(4):** rules 3, 5–16, 22 and 23 come into force **eighteen months after
  publication, i.e. 13 May 2027**. Rule 6 is not yet in force; the report says "in force from
  2027-05-13" until then.
- Context from PIB's release (17 Nov 2025): the Act's highest penalty, up to ₹250 crore, is for
  failing to maintain reasonable security safeguards.

### CERT-In, *Guidelines on Information Security Practices for Government Entities* (30 June 2023)
Guidance for government entities, not a statute; the report labels it "guidance, issued 2023-06-30".
- **4.5.7:** *"use secure protocols such as SSH, SSL, or IP Security (IPSec) encryption for all
  remote connections to the router/switch/server"*.
- **4.5.8 / 5.8:** VPN for remote access, with MFA and VPN logs to a SIEM (not visible in a capture).
- **7.1:** *"Identify and classify sensitive/personal data and apply measures for encrypting such data
  in transit and at rest."* The same clause asks for DLP, the mentor's term, which TunnelScope is not
  (`research/13` §3, M2).
- **3.4:** internal audit at least every 6 months; third-party audit at least yearly, with
  CERT-In-empanelled auditors available.

### Deliberately not mapped
- **CERT-In Directions of 28 April 2022** (section 70B of the IT Act): six-hour incident reporting,
  180-day log retention, clock sync. Operational duties no capture can evidence.
- **Post-quantum readiness** is *not* counted as DPDP or CERT-In evidence: neither asks for it. It
  has its own baseline (DST/NQM, `dst-nqm-pq.yaml`).

## The mapping

| Clause | Evidence (existing baseline verdicts) | Not shown by a capture |
|---|---|---|
| DPDP 6(1)(a) | V-207205, V-207193, V-207223, RFC8247-DH-MUST, RFC8247-DH-OFFER, RFC8247-ENCR, CVE-2026-78135 | whether the link carries personal data; encryption at rest; masking/tokenisation; other data paths |
| DPDP 6(1)(g) | V-207205, V-207193, RFC8247-DH-MUST, RFC8247-DH-OFFER (as a repeatable check) | the organisational measures; 6(1)(b)–(e) |
| CERT-In 7.1 | V-207193, V-207223, RFC8247-DH-MUST, RFC8247-ENCR | classification; at-rest encryption; DLP |
| CERT-In 4.5.7 | V-207205, V-207193, RFC8247-DH-MUST | connections outside the capture; SSH/TLS management |
| CERT-In 3.4 | the whole report, as audit evidence | the audit itself |

Example (EXP-13's cloud-initiated arm): *"DPDP Rules 2025 … rule 6(1)(a) (in force from 2027-05-13):
3 fail, 4 pass — failing: RFC8247-DH-OFFER, V-207193, V-207223"*.

## Guards
`tests/test_context.py`: every mapped rule exists; the mapping never says "compliant"/"complies";
no post-quantum rule is counted; DPDP rule 6 commences 2027-05-13; guidance is not labelled as law.

## Limits
- Primary texts were read from the Gazette text (as hosted at dpdpa.com, matching the G.S.R. number
  and date) and cert-in.org.in. Before quoting in a slide or a submission, recheck against
  egazette.gov.in, since a hosted copy can lag an amendment.
- This is a technical mapping by the project, not legal advice.
