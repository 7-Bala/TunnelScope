# EXP-53 — NSA "Configuring IPsec Virtual Private Networks" as an opt-in rules profile, and verified source text for the DST/NQM baseline (T-122 part 3) — PRE-REGISTRATION (2026-10-15, before any rule file and any run)

## Why
T-122 asks that every baseline TunnelScope judges against quotes a verified source text. Part 1 added CNSA 2.0 (opt-in), part 2
NIST SP 800-77 Rev. 1 (opt-in, EXP-35). Two things remain on the T-122 row: **NSA IPsec guidance** and **DST/NQM**.
This experiment adds the first as an opt-in profile (`tunnelscope assess --profile nsa-ipsec-config`) and gives the second what it
lacks: the two existing DST rules carry no quote, and the link recorded for the report no longer works. As in EXP-35, nothing
changes by default: no default verdict, no pinned golden, no existing test changes.

## Sources (fixed here)
**NSA.** File `NSA-configuring-ipsec-vpns.pdf`, 395,890 bytes, SHA-256
`5b972578242cca5c49233863754b5bea9493ef416380434a0f08c68030ecff56`, 11 pages, PDF created 2025-02-21. Title page text:
"U/OO/148260-20 | PP-20-0712 | February 2025 ver. 1.3 — National Security Agency | Cybersecurity Information — Configuring
IPsec Virtual Private Networks". Source URL (media.defense.gov, NSA's publication host):
https://media.defense.gov/2020/Jul/02/2002355501/-1/-1/0/CONFIGURING_IPSEC_VIRTUAL_PRIVATE_NETWORKS_2020_07_01_FINAL_RELEASE.PDF.
That host refuses scripted downloads (HTTP 403), so the file was saved from the owner's own Chrome on 2026-10-15 (the browser's
normal save of the document it displays). It is kept outside the repository (`~/Datasets/sources/`); `analyze.py` takes its path and
refuses a file with a different hash. This guide is the companion of NSA's "Securing IPsec Virtual Private Networks" (June 2020),
which it cites as [1]; that two-page sheet could not be saved the same way and is **not** used. Its version history says: "February
2025: removed outdated SHA1 mention in Appendix C." The guide's examples are "per CNSSP 15 as of June 2020" (its own wording); CNSSP 15
itself is not read here.

**DST/NQM.** The report the baseline already names: "Implementation of Quantum Safe Ecosystem in India, Report of the Task Force",
Department of Science and Technology, National Quantum Mission, file name `Report_TaskForce_PQMigration_4Feb26 (v1).pdf`, 128 pages,
PDF created 2026-02-04, 1,982,388 bytes, SHA-256 `461d8b42aea3847a3f9083e369065eff7985b03f8e4b1e9974f236ce93d99f31`.
The original address in `dst-nqm-pq.yaml` (dst.gov.in/sites/default/files/...) returns HTTP 404 on 2026-10-15 and DST's landing
page (https://www.dst.gov.in/quantum-safe-ecosystem-in-india) lists no document. The file used here is the Internet Archive's copy of
that original address taken on 2026-09-26:
https://web.archive.org/web/20260926154852id_/https://dst.gov.in/sites/default/files/Report_TaskForce_PQMigration_4Feb26%20%28v1%29.pdf
(the `id_` form serves the stored bytes unchanged). Press coverage says a longer final version (about 140 pages) was published and
withdrawn; it was not found, and nothing here depends on it.

**Text and quotes.** Extraction: `pdftotext -raw` (poppler). Normalisation for every quote check, and nothing else: runs of whitespace
collapse to one space; a hyphen at a line end followed by a word is rejoined. A quote passes only if it is a substring of the
normalised text. `page` below is the PDF page number (the DST report's own printed labels, "Page 18 of 26", restart inside the
document and are not used).

## How a sentence becomes a rule (fixed here)
1. Only requirements about the negotiated algorithms or the offered proposals, where TunnelScope already produces the attribute.
2. Severity follows the strength of the text. The guide's "an example of a recommended ... setting" is an example, not a ban on
   other choices: rules that test a value against an example are **informational**, and their fail message says so. A statement that
   NSA "recommends" or that administrators "should" act on named outdated algorithms is **medium**. The guide has no "shall".
3. A value that differs FAILs. An absent, UNKNOWN or NOT_OBSERVABLE attribute is UNKNOWN or NOT_OBSERVABLE, never PASS (engine,
   unchanged). ESP rules use the ESP cipher *candidate set*: they FAIL only when the wire rules the wanted suite out (or every
   candidate is outdated) and otherwise stay UNKNOWN; they never PASS the AES-256 key length, which is not observable (F-05).

## Rules (9), each with the text it rests on
| # | Rule id | Attribute / assertion | Sev. | Source (PDF page) and verbatim quote |
|---|---|---|---|---|
| 1 | NSA-IKE-DH-EXAMPLE | `ike_dh_group` is MODP-4096 (group 16) | informational | p.1: "an example of a recommended ISAKMP/IKE setting per CNSSP 15 as of June 2020"; "Diffie-Hellman Group: 16" |
| 2 | NSA-IKE-ENCR-EXAMPLE | `ike_encr` is an AES mode with a 256-bit key (AES-CBC-256, AES-CTR-256, AES-GCM/CCM -8/-12/-16 with 256) | informational | p.1: same example sentence; "Encryption: AES-256" |
| 3 | NSA-IKE-PRF-EXAMPLE | `ike_prf` is PRF-HMAC-SHA2-384 | informational | p.1: same example sentence; "Hash: SHA-384" |
| 4 | NSA-IKE-INTEG-EXAMPLE | `ike_integ` is HMAC-SHA2-384-192 | informational | p.1: same example sentence; "Hash: SHA-384" |
| 5 | NSA-ESP-SUITE-EXAMPLE | ESP only: `esp_cipher_family` must still contain AES-CBC+HMAC-SHA384-192 (`candidate_required`) | informational | p.2: "an example of a recommended IPsec setting per CNSSP 15 as of June 2020"; "Encryption: AES-256"; "Hash: SHA-384"; "Block Cipher Mode: CBC" |
| 6 | NSA-IKE-OUTDATED-ENCR | `ike_encr` not DES, DES-CBC or 3DES (`not_in`) | medium | p.2: "such as the Data Encryption Standard (DES), Triple DES (3DES) and Diffie-Hellman groups 1, 2, and 5"; "If SAs are identified with non-compliant algorithms, administrators should immediately investigate" |
| 7 | NSA-IKE-OUTDATED-DH | `ike_dh_group` not group 1, 2 or 5 (`dh_group_not_in`) | medium | p.2: same two sentences |
| 8 | NSA-OFFER-OUTDATED-DH | `ike_offered_dh`: no offered group is 1, 2 or 5 (`dh_groups_none_in`) | medium | p.3: "Leaving extra ISAKMP/IKE and IPsec policies as acceptable ISAKMP/IKE and IPsec policies creates a vulnerability known as a downgrade attack."; p.1: "NSA recommends only configuring policies that strictly use CNSSP 15-compliant algorithms, and removing all others." |
| 9 | NSA-ESP-OUTDATED | ESP only: not every ESP candidate is DES or 3DES (`candidates_none_in`: 3DES-CBC+HMAC-SHA1-96, DES-CBC+HMAC-96, DES-CBC+HMAC-SHA256-128, -SHA384-192, -SHA512-256) | medium | p.2: same two sentences as rule 6 |

Rules 1 to 4 and 6 to 8 read the IKE SA's selected values (and, for rule 8, the initiator's offer). Group numbers are IANA numbers
(`MODP-1024` is 2, `MODP-1536` is 5, `MODP-4096` is 16), as the engine already maps them.

## Not made into rules (with the reason)
- **ACLs on UDP 500, UDP 4500 and ESP, an IPS in front of the gateway** (p.1, appendices A and D): network policy at the gateway, not a
  property of the negotiated tunnel; a capture of one tunnel cannot show what else is filtered.
- **FIPS-validated cryptography, vendor patch levels, "avoid default settings", periodic review, cryptographic agility** (pp.2 to 4):
  properties of a product or a process, not of the wire. (Software version is already covered by the known-vulnerabilities lookup.)
- **Replacing pre-shared keys** (p.2): PSK use is inside the encrypted IKE_AUTH (EXP-11).
- **"Remove unused or non-compliant suites"** for encryption and integrity (p.3): the offered encryption and integrity lists are not
  attributes today (only `ike_offered_dh` is). Rule 8 covers the offered DH groups; the other offers need a new attribute and a new
  experiment. This is the main thing the guide asks for that the tool cannot yet judge.
- **Appendices B and C** (vendor commands, vendor configuration examples): how to configure products, not requirements.

## The DST baseline (`dst-nqm-pq.yaml`), changed in provenance only
No rule's id, attribute, assertion, severity or fail message changes. Each of the two rules gains `section`, `page` and `quote` fields
(read by nothing in the engine; pinned by a test), and the file's `url` records the original address, the archived address and the
file's hash.
- **DST-PQ-KE** (informational): p.20: "recognising the risk of “Harvest Now, Decrypt Later” (HNDL) attacks"; p.20: "CII sectors such
  as defence, power, and telecom follow accelerated timelines — Foundations by 2027, High-Priority Migration by 2028, and Full PQC
  Adoption by 2029." **Disclosed reading:** the report sets timelines and names the harvest-now-decrypt-later risk; it does not name a
  key-exchange mechanism for IPsec. The rule is an informational reading of those timelines at the key exchange (the part such
  attacks target). The title's wording "should negotiate" is the project's reading, not a quoted requirement; a `note` field says so.
- **DST-PQ-DOWNGRADE** (severity high, unchanged): p.17: "Coexistence of classical and quantum-safe cryptography increases complexity
  and introduces risks of downgrade or insecure fallback."; p.34: "without introducing downgrade vulnerabilities or interoperability
  failures"; p.39: "Resistance to PQC Parameter Downgrade Attacks". **Disclosed:** the report does not rank downgrade as "high"; that severity
  is the project's earlier choice and is not re-decided here.

## Hypotheses and bars
- **H1 (defaults unchanged):** with no profile, the default verdicts (rule id, verdict, observed, message) on every capture in
  `testbed/captures/` are identical between this branch and `main` (a clean worktree, run with main's code). One difference fails H1.
  Every existing test passes without edits.
- **H2 (quotes are real):** every quote in the NSA profile is a substring of the normalised text of the NSA PDF with the hash above, and
  every quote added to the DST baseline is a substring of the normalised text of the DST PDF with its hash. One miss fails H2.
- **H3 (pre-stated verdicts):** with `--profile nsa-ipsec-config`, these verdicts hold exactly (P = PASS, F = FAIL, U = UNKNOWN, - = no
  verdict because the rule applies only to ESP). They come from an attribute inventory made before this document (IKE values and ESP
  candidate-set sizes only; no rule existed):

| Capture (testbed/captures/…) | 1 DH | 2 ENCR | 3 PRF | 4 INTEG | 5 ESP-SUITE | 6 OUT-ENCR | 7 OUT-DH | 8 OFFER | 9 ESP-OUT |
|---|---|---|---|---|---|---|---|---|---|
| exp15/s-ecp256.pcap | F | F | F | U | F | P | P | P | P |
| exp15/s-3des.pcap | F | F | F | F | F | F | F | F | U |
| exp15/s-x25519.pcap | F | P | F | F | F | P | P | P | P |
| exp15/s-modp1536.pcap | F | F | F | F | F | P | F | F | U |
| exp15/s-modp4096.pcap | P | P | P | P | F | P | P | P | P |
| cloud/c-v1.pcap | F | F | F | U | F | P | F | U | U |
| cloud/c-w.pcap | F | F | F | F | F | P | F | F | U |
| exp15/a-tra-sha1.pcap | F | P | F | F | - | P | P | P | - |
| exp07/e7-pfs-on.pcap | F | P | F | F | F | P | P | P | P |
| a7-cs-aes256gcm16.pcap (ESP only) | U | U | U | U | F | U | U | U | P |

  (Inventory used: s-ecp256 = AES-GCM-16-128 / PRF-HMAC-SHA2-256 / no integrity / ECP-256; s-3des = 3DES / PRF-HMAC-SHA1 / HMAC-SHA1-96 /
  MODP-1024; s-x25519 = AES-CBC-256 / SHA2-256 / Curve25519; s-modp1536 = AES-CBC-128 / SHA2-256 / MODP-1536; s-modp4096 = AES-CBC-256 /
  PRF-HMAC-SHA2-384 / HMAC-SHA2-384-192 / MODP-4096; c-v1 = AES-CBC-128 / PRF-HMAC-SHA1 / MODP-1024, offer not read; c-w = AES-CBC-128 /
  SHA1 / MODP-1024; a-tra-sha1 = AH only, AES-CBC-256 / SHA2-256 / MODP-2048; e7-pfs-on = AES-CBC-256 / SHA2-256 / MODP-2048; a7 = ESP
  only, no IKE. ESP candidate sets: 7 entries with no DES/3DES for s-ecp256, s-x25519, s-modp4096, e7-pfs-on and a7; 11 to 13 entries that
  include DES or 3DES for the others. None of the ESP sets contains AES-CBC+HMAC-SHA384-192, so rule 5 FAILs on every ESP capture.)
- **H4 (never passes on missing evidence):** on every capture in the corpus, no profile rule is PASS when its attribute is absent,
  UNKNOWN or NOT_OBSERVABLE (checked over the whole corpus).
- **H5 (the DST edit changes nothing the engine reads):** the default verdicts of H1 include the DST baseline, so H1 covers it; in
  addition a test pins that the two DST rules keep their ids, attributes, assertions, severities and messages.

## Code this experiment will add (after this commit)
- `tunnelscope/rules/profiles/nsa-ipsec-config.yaml` (rules above, each with `section`, `page` and `quote`).
- `tunnelscope/rules/dst-nqm-pq.yaml`: `section`, `page`, `quote` and a `note` on the two rules; `url` with the original and archived
  addresses and the hash. No other change.
- `tunnelscope/explain/explain.py`: a plain explanation per new rule (as for NIST77-*).
- `tests/test_nsa_ipsec_profile.py`: opt-in (default baselines unchanged), H3 verdicts on real captures, every rule has
  section/page/quote, the DST rules unchanged and quoted, explanations present; mutation checks recorded in RESULT.md.
- `experiments/exp53-nsa-dst-profile/analyze.py` -> `results/summary.json` (H1 against a clean worktree of `main`; H2 against both PDFs;
  H3 parsed from this file; H4).

## Rules of this experiment
No rule, quote, bar or prediction above changes after this commit. RESULT.md quotes `results/summary.json` only.
Addenda go below this line, dated, before the run they govern.
