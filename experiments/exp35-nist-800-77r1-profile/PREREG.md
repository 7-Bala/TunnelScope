# EXP-35 — NIST SP 800-77 Rev. 1 as an opt-in rules profile (T-122 part 2) — PRE-REGISTRATION (2026-09-29, before any code and any run)

## Why
T-122 asks that every baseline TunnelScope judges against quotes a verified source text. Part 1 added CNSA 2.0 as an
opt-in profile. Part 2 adds NIST SP 800-77 Rev. 1, *Guide to IPsec VPNs* (June 2020), the US federal guide that the
research registers cite (research/SOURCES.md) but no rule used. It is an opt-in profile
(`tunnelscope assess --profile nist-sp800-77r1`), not a default: the owner asked that the default 15-rule results and
every pinned golden stay unchanged.

## Source (fixed here)
- File: `NIST.SP.800-77r1.pdf`, 3,106,924 bytes, SHA-256
  `bc2a36dcccf96476d4e0d09468901726c930f2554115c440988bae746074bd70`, downloaded 2026-09-28 from
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-77r1.pdf (the link on the official page
  https://csrc.nist.gov/pubs/sp/800/77/r1/final). PDF metadata: title "Guide to IPsec VPNs", created 2020-06-26.
  Kept outside the repository (not committed); `analyze.py` takes its path as an argument and refuses a file with a
  different hash.
- Text extraction: `pdftotext -raw` (poppler). Normalisation used for every quote check, and nothing else: runs of
  whitespace collapse to one space; a hyphen at a line end followed by a word is rejoined (`AES-` + newline + `CCM`
  -> `AES-CCM`). A quote passes only if it is a substring of the normalised text.
- Page numbers below are the printed page labels (Table 1 is on pp. vii-viii; printed page = PDF page - 17 for the
  body).
- Document conventions (quoted, p. ii): "shall"/"shall not" are strict requirements; "should"/"should not"
  recommend or discourage without prohibiting.

## How a sentence becomes a rule (fixed here)
1. Only algorithm/protocol requirements. Table 1 ("Approved Algorithms and Options", columns Recommended / Legacy /
   Expected) is the primary source; body sentences back it.
2. A rule is written only where TunnelScope already produces the attribute; a requirement the wire cannot show
   stays a rule when a report must show it as not observable (as CNSA2-AUTH does), otherwise it is listed under
   "Not made into rules" with the reason.
3. Severity follows the strength of the text: "shall / shall not / not NIST-approved" -> high; "should / should
   not / Recommended column" -> medium; a conditional "should ... unless" -> informational.
4. A value outside the Recommended column FAILs; the fail message says which column the value is in (Legacy /
   Expected / not listed). An absent or UNKNOWN attribute is UNKNOWN, never PASS (engine behaviour, unchanged).

## Rules (11), each with the text it rests on
| # | Rule id | Attribute / assertion | Sev. | Source (section, printed page) and verbatim quote |
|---|---|---|---|---|
| 1 | NIST77-IKE-VERSION | `ike_version` equals `IKEv2` | medium | Table 1 (p. vii), Version row: Recommended "IKEv2", Legacy "IKEv1". Sec 3.11 (p. 35): "IKEv1 should not be used for new deployments, and existing deployments using IKEv1 should be converted to IKEv2 when possible." |
| 2 | NIST77-IKE-ENCR | `ike_encr` matches one of AES-GCM, AES-CTR, AES-CBC, AES-CCM | medium | Table 1 (p. vii), IKE Encryption, Recommended: "AES-GCM, AES-CTR, AES-CBC, AES-CCM (128, 192, 256-bit keys)"; Legacy: TDEA, footnote 3: "NIST recommends upgrading all Triple Data Encryption Algorithm (TDEA) use to the Advanced Encryption Standard (AES)." |
| 3 | NIST77-IKE-PRF | `ike_prf` in PRF-HMAC-SHA2-256/384/512 | medium | Table 1 (p. vii), Integrity/Pseudorandom Function (PRF), Recommended: "HMAC-SHA256, HMAC-SHA384, HMAC-SHA512"; Legacy: "HMAC-SHA-1". Sec 7.2.3 (p. 70): "HMAC-MD5 has never been a NIST-approved algorithm and shall not be used." |
| 4 | NIST77-IKE-INTEG | `ike_integ` in HMAC-SHA2-256-128 / -384-192 / -512-256 | medium | Same Table 1 row. Sec 7.2.3 (p. 70): "Even though HMAC-SHA-1 is still a NIST-approved option, the HMAC-SHA-2 algorithms are recommended because they have stronger security than HMAC-SHA-1." |
| 5 | NIST77-DH-APPROVED | `ike_dh_group` not group 1, 2, 5 or 22 (`dh_group_not_in`) | high | Sec 7.2.4.2 (p. 72): "DH groups 1, 2, 5, and 22 are not NIST-approved because these groups do not supply the minimum of 112 bits of security." |
| 6 | NIST77-DH-RECOMMENDED | `ike_dh_group` in MODP-2048/3072/4096/6144/8192, ECP-256/384/521 (groups 14-21) | medium | Table 1 (p. vii), DH group, Recommended: "DH 14 to DH 21"; Expected: "DH 31 and DH 32, RFC 8031". Sec 7.2.6 (p. 76): "DH group numbers 14, 15, 16, 17, 18 [15], 19, 20, and 21 [65] are NIST-approved groups." |
| 7 | NIST77-PFS | `pfs` equals `true` | informational | Sec 2.2 (p. 7): "When resources allow, PFS should be used." Sec 7.2.6 (p. 76): "Because the PFS option provides stronger security, it should be used unless the additional computational requirements of the additional DH key exchanged would pose a problem." |
| 8 | NIST77-AH | `ipsec_protocols` does not contain `AH` (new engine op `not_contains`) | medium | Table 1 (p. viii), IPsec Protocol: Recommended "ESP, IPComp", Legacy "AH". Sec 4.5 (p. 46): "AH has been obsoleted and should not be implemented or deployed." and "If encryption is undesirable, ESP with null encryption (ESP-NULL) or AES-GMAC should be used instead of AH." |
| 9 | NIST77-ESP-ENCR | ESP only: `esp_cipher_family` candidates, FAIL only if every candidate is a non-AES cipher (3DES, DES, Blowfish, Twofish, CAST, ChaCha20-Poly1305) (`candidates_none_in`); ESP-NULL is allowed (sec 4.5) | medium | Table 1 (p. viii), IPsec Encryption, Recommended: "AES-GCM, AES-CTR, AES-CBC, AES-CCM (128, 192, 256-bit keys)". Sec 4.1.4 (p. 39): "Triple DES has been deprecated since 2019 and will be disallowed after 2023." |
| 10 | NIST77-ESP-INTEG | ESP only: FAIL only if every candidate has a 96-bit legacy ICV (…HMAC-SHA1-96, …HMAC-96) (`candidates_none_in`) | medium | Table 1 (p. viii), IPsec Integrity, Recommended: "HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, AES-GMAC". Sec 4.1.4 (p. 39): "The HMAC-MD5 and HMAC-SHA-1 integrity algorithms are also no longer NIST-approved." |
| 11 | NIST77-AUTH | `peer_auth_method` (NOT_OBSERVABLE today: inside encrypted IKE_AUTH, EXP-11) | medium | Table 1 (p. vii), Peer authentication, Recommended: "RSA, DSA, and ECDSA with 128-bit security strength (for example, RSA with 3072-bit or larger key)". |

Disclosed inconsistency in the source: sec 7.2.3 (p. 70) calls HMAC-SHA-1 "still a NIST-approved option", sec 4.1.4
(p. 39) says it is "no longer NIST-approved". Rules 3, 4 and 10 do not depend on which is right: they test the
Recommended column, which lists SHA-2 only.

## Not made into rules (with the reason)
- FIPS-validated modules (executive summary, p. vi-vii, "shall"): a property of the product, not visible on the wire.
- IKE/IPsec lifetimes (Table 1: 24 h / 8 h): not negotiated (sec 7.2.4.2, p. 73: "The IKE SA and IPsec SA lifetimes are
  not negotiated."); `rekey_cadence` needs two rekeys, i.e. a capture of more than 16 h, which the corpus does not
  have. A rule would be UNKNOWN on every capture.
- PFS group "Same or stronger DH as initial IKE DH" (Table 1, p. viii): the rekey's KE group is inside the encrypted
  CREATE_CHILD_SA.
- NULL authentication (sec 3.3.5, p. 29, "NIST does not approve the use of NULL authentication-based IPsec."), PSK
  strength (sec 3.3.4), manual keying (sec 3.10, "shall not be used"): authentication is encrypted; manual keying
  cannot be told apart from a capture that started after IKE.
- IKEv1 Aggressive Mode (Table 1 Legacy; sec 7.2.6 "should be avoided"): any IKEv1 SA already fails rule 1; a
  separate rule would PASS vacuously on every IKEv2 SA, and the corpus has no Aggressive Mode capture to check it.
- Tunnel/transport mode (both Recommended), IPComp, IPsec-v3 vs v2 (not reliably visible), key lengths (the ESP key
  length is not observable, F-05; every AES key size is in the Recommended column).

## Hypotheses and bars
- **H1 (defaults unchanged):** with no profile, the default verdicts (rule id, verdict, observed, message) on every
  capture in `testbed/captures/` are identical between this branch and `main` (85777ca). One difference fails H1.
  The pinned explain golden (`tests/test_rephrase.py`) and every existing test pass without edits.
- **H2 (quotes are real):** every quote in the profile file's `quote:` fields is a substring of the normalised text
  of the PDF with the hash above. One miss fails H2.
- **H3 (pre-stated verdicts):** with `--profile nist-sp800-77r1`, these verdicts hold exactly (P = PASS, F = FAIL,
  U = UNKNOWN, N = NOT_OBSERVABLE, - = no verdict because the rule applies only to ESP). Predictions come from the
  capture findings (inventory made before this PREREG, attributes only) and the rules above:

| Capture (testbed/captures/…) | 1 VER | 2 ENCR | 3 PRF | 4 INTEG | 5 DH-APP | 6 DH-REC | 7 PFS | 8 AH | 9 ESP-ENCR | 10 ESP-INTEG | 11 AUTH |
|---|---|---|---|---|---|---|---|---|---|---|---|
| exp15/s-ecp256.pcap | P | P | P | U (AEAD) | P | P | U | P | U | U | N |
| exp15/s-3des.pcap | P | F | F | F | F | F | F | P | U | U | N |
| exp15/s-x25519.pcap | P | P | P | P | P | F | U | P | U | U | N |
| exp15/s-modp1536.pcap | P | P | P | P | F | F | F | P | U | U | N |
| exp15/s-modp4096.pcap | P | P | P | P | P | P | P | P | U | U | N |
| cloud/c-v1.pcap | F | U | U | U | U | U | N | P | U | U | N |
| cloud/c-w.pcap | P | P | F | F | F | F | N | P | U | U | N |
| exp15/a-tra-sha1.pcap | P | P | P | P | P | P | F | F | - | - | N |
| exp07/e7-pfs-on.pcap | P | P | P | P | P | P | P | P | U | U | N |
| a7-cs-aes256gcm16.pcap (ESP only) | U | U | U | U | U | U | N | P | U | U | U |

  (Inventory values used: s-modp4096 = AES-CBC-256 / PRF-HMAC-SHA2-384 / HMAC-SHA2-384-192 / MODP-4096 / PFS
  inferred true; e7-pfs-on = AES-CBC-256 / SHA2-256 / MODP-2048 / PFS inferred true.)
  Corpus-wide prediction: rules 9 and 10 give 0 PASS and 0 FAIL on the whole corpus (every observed ESP candidate
  set mixes AES/AEAD candidates with non-approved ones, so the sieve cannot decide; the report must say UNKNOWN).
- **H4 (never passes on missing evidence):** on every capture, no profile rule is PASS when its attribute is absent,
  UNKNOWN or NOT_OBSERVABLE (checked over the whole corpus by `analyze.py`).

## Code this experiment will add (after this commit)
- `tunnelscope/rules/profiles/nist-sp800-77r1.yaml` (rules above, each with `section`, `page` and `quote` fields).
- `tunnelscope/assess/engine.py`: one new op `not_contains` (list value; FAIL if the item is present; a non-list is
  UNKNOWN).
- `tunnelscope/explain/explain.py`: a plain explanation per new rule (as for CNSA2-*).
- `tests/test_nist80077_profile.py`: opt-in (default baselines unchanged), H3 verdicts on real captures, every rule
  has section/page/quote, `not_contains`, profile rules have explanations; mutation checks recorded in RESULT.md.
- `experiments/exp35-nist-800-77r1-profile/analyze.py` -> `results/summary.json` (H1 by running the default
  baselines in a clean worktree of `main` and on this branch; H2 against the PDF; H3; H4).

## Rules of this experiment
No rule, quote, bar or prediction above changes after this commit. RESULT.md quotes `results/summary.json` only.
Addenda go below this line, dated, before the run they govern.
