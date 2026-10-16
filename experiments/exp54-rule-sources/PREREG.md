# EXP-54: verified source text for the 21 rules that still lack it (T-122 part 4): PRE-REGISTRATION

Written 2026-10-15, committed **before** any rule file is edited and before the scorer exists. T-122's target is "every rule cites a
verified source text". EXP-35 (NIST profile, 11 rules), EXP-53 (NSA profile, 9 rules, and the 2 DST rules) did it for 22 rules. This
experiment does it for the other 21, in the four default baselines (CVE, DISA, RFC 8221/4303, RFC 8247) and the opt-in CNSA 2.0 profile.

## What changes, and what must not
Only **metadata** is added to each of the 21 rules: `section`, `page`, `quote` (a list of verbatim strings), `source` (which registered
source files the quotes come from) and, where this PREREG discloses a gap between the source and the rule, `note`. Each file also gets a
`sources` map (key, file name, address, SHA-256) and a header comment. **Nothing the engine reads changes:** not `id`, `attribute`,
`assert`, `severity`, `title`, `fail_message`, `applies_to_*`, not the order of rules. Where a source and a rule disagree, the rule is
**left as it is** and the gap is written in `note` (listed below). Changing a rule is a separate, later decision (a DEC).

## Sources (kept outside the repository; the scorer refuses a file whose SHA-256 differs)
All fetched 2026-10-15. RFCs from the RFC Editor as plain text; the CNSA 2.0 draft from the IETF archive; NVD records from the NVD REST
API (the `descriptions` entry with `lang` = `en` is the quoted text); the strongSwan release note as the page's HTML; the DISA text from
the **cyber.trackr.live mirror** of the V2R6 STIG, not from DISA's own download (DISA's zip could not be located at the address tried).

| key | file (in `~/Datasets/sources/part4/`) | SHA-256 | origin |
|---|---|---|---|
| `cnsa2-draft-04` | `cnsa2-draft-04.txt` | `4b8597a7491a8477729dafe507165bd3ef217c5c2410f6678fae73b9a5188f25` | https://www.ietf.org/archive/id/draft-guthrie-cnsa2-ipsec-profile-04.txt |
| `disa-vpn-srg-v2r6` | `disa-v2r6-index.html` | `6ee29b0be3cddefadc9ef4f0382686e9b373f949bab604e691a671a628897f45` | https://cyber.trackr.live/stig/Virtual_Private_Network_(VPN)_Security_Requirements_Guide/2/6 |
| `nvd-CVE-2008-4551` | `nvd-CVE-2008-4551.json` | `ead323fe2dc1a2b3bba4246a9b5efa9135f01693797843c2e9327a721e96bf09` | https://nvd.nist.gov/vuln/detail/CVE-2008-4551 |
| `nvd-CVE-2013-6467` | `nvd-CVE-2013-6467.json` | `35776983e532d4b7f15e2c19feb037b8ca10c07edb293311e7ae37f007213dc9` | https://nvd.nist.gov/vuln/detail/CVE-2013-6467 |
| `nvd-CVE-2013-7294` | `nvd-CVE-2013-7294.json` | `e2dda9f71a0855b24dbe0c513ed47153c3243d102414f6beb5013b58b0354405` | https://nvd.nist.gov/vuln/detail/CVE-2013-7294 |
| `nvd-CVE-2015-3240` | `nvd-CVE-2015-3240.json` | `6f91b0e017cd6d00978d1a79163aaf4345d07a270d7537ceb8fdf4c0e065a488` | https://nvd.nist.gov/vuln/detail/CVE-2015-3240 |
| `nvd-CVE-2019-12312` | `nvd-CVE-2019-12312.json` | `a3dde6c22108ffcf7f010bb7f9a03cfedd650642824fd3990dcbcc51381e69e3` | https://nvd.nist.gov/vuln/detail/CVE-2019-12312 |
| `nvd-CVE-2023-41913` | `nvd-CVE-2023-41913.json` | `f09b3a6ec861f60141294afe1cc0dea35759f8055d7f3d01256dd55752cd5cf6` | https://nvd.nist.gov/vuln/detail/CVE-2023-41913 |
| `nvd-CVE-2026-78135` | `nvd-CVE-2026-78135.json` | `d4c196da189523e13254813fdea58862c5fab5eb20376434f2ea6cca2c6c3596` | https://nvd.nist.gov/vuln/detail/CVE-2026-78135 |
| `rfc4301` | `rfc4301.txt` | `a2411e90515f59665e1059b1bb66d8123bd9e384ccfc8b7ccca65db85d5d7736` | https://www.rfc-editor.org/rfc/rfc4301.txt |
| `rfc4302` | `rfc4302.txt` | `c9de28181a78bb85ec6d1e6bda86da133307310de736632f26aa890e1f08e56b` | https://www.rfc-editor.org/rfc/rfc4302.txt |
| `rfc4303` | `rfc4303.txt` | `d22f9d4120e5645525b63ac7bbf8ef78c334fe003a2c48bf1e25ac25f6e7dc58` | https://www.rfc-editor.org/rfc/rfc4303.txt |
| `rfc7296` | `rfc7296.txt` | `b6c1bf3921e85dd3674f427ffcaded0209e1f9718e8d601e2f918371f46329a1` | https://www.rfc-editor.org/rfc/rfc7296.txt |
| `rfc8221` | `rfc8221.txt` | `e070689e9b8828a2a7ac309ad4d94c1bd0e00ea2cc14bf1a2714bf4243029f1e` | https://www.rfc-editor.org/rfc/rfc8221.txt |
| `rfc8247` | `rfc8247.txt` | `e1e6a86cfddcb2ebbe39ba1c2cf5516b8cb5f39fd0d53dea468a522a3b7a7250` | https://www.rfc-editor.org/rfc/rfc8247.txt |
| `rfc9395` | `rfc9395.txt` | `24b4079e09cc222e8353b31ba9cd4d80fbaf3fe1434884553df80e20f2e55b0a` | https://www.rfc-editor.org/rfc/rfc9395.txt |
| `strongswan-6.1.0` | `strongswan-6.1.0.html` | `15a0d7f2c821568a72330f4809908254537adcce9504e826cc2a2c301efca384` | https://www.strongswan.org/blog/2026/09/07/strongswan-6.1.0-released.html |

## The 21 rules
Pages are the `[Page N]` numbers printed in the plain-text RFCs and the draft. Sources with no page numbers in the form used (RFC 9395,
the DISA web page, the strongSwan page, NVD records) are not given a page; a rule whose sources are all of that kind has `page: "n/a"`.
The `page` field reads `source:N,N; source:N`.

| # rule | file | sources | section | pages | quotes |
|---|---|---|---|---|---|---|
| 1 | `CVE-2026-78135` | `cve-2026-78135.yaml` | `strongswan-6.1.0`, `nvd-CVE-2026-78135`, `rfc7296` | strongSwan 6.1.0 release notes; NVD CVE-2026-78135; RFC 7296 1.3 | `rfc7296:13` | 3 |
| 2 | `CVE-WATCH-KE-MALFORMED` | `cve-2026-78135.yaml` | `rfc7296`, `nvd-CVE-2015-3240`, `nvd-CVE-2008-4551`, `nvd-CVE-2023-41913` | RFC 7296 3.4; NVD CVE-2015-3240, CVE-2008-4551, CVE-2023-41913 | `rfc7296:89` | 4 |
| 3 | `CVE-WATCH-INFO-BEFORE-AUTH` | `cve-2026-78135.yaml` | `rfc7296`, `nvd-CVE-2019-12312` | RFC 7296 1.4; NVD CVE-2019-12312 | `rfc7296:17` | 2 |
| 4 | `CVE-WATCH-INIT-PAYLOADS` | `cve-2026-78135.yaml` | `rfc7296`, `nvd-CVE-2013-7294`, `nvd-CVE-2013-6467` | RFC 7296 1.2; NVD CVE-2013-7294, CVE-2013-6467 | `rfc7296:10` | 3 |
| 5 | `V-207205` | `disa-vpn-srg-v2r6.yaml` | `disa-vpn-srg-v2r6`, `rfc9395` | DISA VPN SRG V2R6, V-207205 (SRG-NET-000132-VPN-000460); RFC 9395 1 | `n/a` | 3 |
| 6 | `V-207193` | `disa-vpn-srg-v2r6.yaml` | `disa-vpn-srg-v2r6` | DISA VPN SRG V2R6, V-207193 (SRG-NET-000074-VPN-000250) | `n/a` | 2 |
| 7 | `V-207223` | `disa-vpn-srg-v2r6.yaml` | `disa-vpn-srg-v2r6` | DISA VPN SRG V2R6, V-207223 (SRG-NET-000230-VPN-000780) | `n/a` | 2 |
| 8 | `RFC4301-CONFIDENTIALITY` | `rfc8221-4303-ipsec.yaml` | `rfc4301` | RFC 4301 3.2 | `rfc4301:9` | 2 |
| 9 | `RFC8221-AH-INTEG` | `rfc8221-4303-ipsec.yaml` | `rfc8221` | RFC 8221 6 | `rfc8221:9` | 4 |
| 10 | `RFC8221-AH-LEGACY` | `rfc8221-4303-ipsec.yaml` | `rfc8221` | RFC 8221 6 | `rfc8221:9,10` | 3 |
| 11 | `RFC8221-ESP-3DES` | `rfc8221-4303-ipsec.yaml` | `rfc8221` | RFC 8221 5 | `rfc8221:7,8` | 2 |
| 12 | `RFC4303-SEQ` | `rfc8221-4303-ipsec.yaml` | `rfc4303`, `rfc4302` | RFC 4303 2.2 and 3.3.3; RFC 4302 3.3.2 | `rfc4303:12,25; rfc4302:8,12` | 2 |
| 13 | `RFC8247-DH-MUST` | `rfc8247-ikev2.yaml` | `rfc8247` | RFC 8247 2.4 | `rfc8247:10,11` | 5 |
| 14 | `RFC8247-DH-OFFER` | `rfc8247-ikev2.yaml` | `rfc8247` | RFC 8247 2.4 | `rfc8247:10,11` | 3 |
| 15 | `RFC8247-ENCR` | `rfc8247-ikev2.yaml` | `rfc8247` | RFC 8247 2.1 | `rfc8247:6` | 4 |
| 16 | `CNSA2-IKE-ENCR` | `profiles/cnsa2-ipsec.yaml` | `cnsa2-draft-04` | 6.2 | `cnsa2-draft-04:7` | 1 |
| 17 | `CNSA2-IKE-PRF` | `profiles/cnsa2-ipsec.yaml` | `cnsa2-draft-04` | 6.2 | `cnsa2-draft-04:7` | 1 |
| 18 | `CNSA2-IKE-KE` | `profiles/cnsa2-ipsec.yaml` | `cnsa2-draft-04` | 6.2 | `cnsa2-draft-04:7` | 1 |
| 19 | `CNSA2-ADDKE` | `profiles/cnsa2-ipsec.yaml` | `cnsa2-draft-04` | 6.2 | `cnsa2-draft-04:7` | 1 |
| 20 | `CNSA2-ESP-ENCR` | `profiles/cnsa2-ipsec.yaml` | `cnsa2-draft-04` | 8.2 | `cnsa2-draft-04:11` | 1 |
| 21 | `CNSA2-AUTH` | `profiles/cnsa2-ipsec.yaml` | `cnsa2-draft-04` | 8.3 | `cnsa2-draft-04:12` | 1 |

## Hypotheses and bars (all must hold; any miss is reported as a miss)
- **H1, nothing the engine reads changed.** (a) For every capture in `testbed/captures/` (1,223 files at the time of writing), the verdicts
  of all default baselines **and all opt-in profiles** are identical between this branch and a clean worktree of `main`
  (hash of rule id, verdict, observed value and message per SA). (b) For every rule in every rules file, the dictionary of fields
  *other than* `section`, `page`, `quote`, `source`, `note` is identical to `main`'s, and so is the rule order and the file's `baseline`,
  `authority` and `url`. Bar: zero differences in both.
- **H2, every quote is verbatim.** Each quote, after one fixed normalisation (runs of white space become one space; a hyphen at a line
  end is rejoined; the pages of text RFCs are split at their `[Page N]` footers; HTML tags are stripped and entities decoded), is a
  substring of at least one of that rule's registered sources, and each quote is at least 20 characters. Bar: 0 missing of all quotes;
  every source hashes to the value above.
- **H3, pages are real.** For each rule, every quote has at least one hit on a declared (source, page), and every declared (source,
  page) is hit by at least one quote; rules with `page: "n/a"` hit no paged source. Bar: 0 violations.
- **H4, coverage.** Every rule in `tunnelscope/rules/*.yaml` and `tunnelscope/rules/profiles/*.yaml` (43 rules) has non-empty `section`,
  `page` and `quote`. Bar: 0 rules without.
- **H5, the disclosed gaps are written down.** Every note in the appendix exists verbatim in its rule (pinned by tests), so a later edit cannot quietly drop one. Bar: 0 missing.

Also required: the whole unit suite passes, the new tests (`tests/test_rule_sources.py`) pass, and **mutation checks** each fail at least one
test: a quote with one word changed; a page changed; a source file's hash changed; a rule's severity changed; an assertion value
changed; a rule's quote list emptied; a note removed from V-207223; an unknown source key.

## Gaps between source and rule, stated before the work (kept as notes; the rules are not changed here)
1. **V-207205** (IKEv2): DISA rates it Medium; the rule says high. DISA's check sentence has an apparent slip. Text read from a mirror.
2. **V-207223** (SHA-2 384+): DISA rates it High; the rule says medium. "FIPS-validated" is not visible on the wire. DISA's discussion says SHA-2 where it means SHA-1.
3. **V-207193** (DH 16+): DISA says all IKE proposals; the rule judges the negotiated group only.
4. **RFC8247-ENCR**: the rule is stricter than RFC 8247: it fails ENCR_3DES (RFC: MAY) and AES-CCM-8 (RFC: SHOULD, for IoT); the RFC's MUST algorithm is AES-CBC.
5. **RFC8247-DH-OFFER**: the RFC does not say that merely offering a discouraged group is a downgrade exposure; that is the project's reasoning.
6. **RFC4301-CONFIDENTIALITY**: RFC 4301 does not forbid AH-only protection; "should be ESP" is the project's judgement.
7. **RFC8221-AH-LEGACY**: RFC 8221 does not say HMAC-SHA1-96 or AES-XCBC-96 should be avoided; "informational" is the project's severity.
8. **RFC4303-SEQ**: the RFC text is about the sender's counter cycling; the rule observes a repeated number, which is also what a replayed or duplicated packet looks like.
9. **CVE-2026-78135**: the fixed-in version (6.1.0) comes from strongSwan's release notes; NVD gives only the affected range. The rule matches a request pattern; acceptance is not visible.
10. **The four CVE watch rules**: the CVEs are examples of a trigger pattern (and are from Libreswan, strongSwan, Openswan); a match is not shown to be an exploit.

## What this cannot show
- That a quote *proves* the rule's exact assertion; that is a judgement, which the notes above make visible where the two differ.
- That the sources are the latest. RFC errata, later drafts and later NVD edits are not checked.
- That the DISA mirror equals DISA's own file.
- Nothing about detection quality: no verdict changes by design.

## Files
`tunnelscope/rules/{cve-2026-78135,disa-vpn-srg-v2r6,rfc8221-4303-ipsec,rfc8247-ikev2}.yaml`, `tunnelscope/rules/profiles/cnsa2-ipsec.yaml`,
`tests/test_rule_sources.py`, `experiments/exp54-rule-sources/{PREREG.md,analyze.py,RESULT.md,results/summary.json}`,
`research/registers/{DECISIONS.md,EXPERIMENT-REGISTER.md}`, `TODO.md`. No other file.

## Appendix: the exact quotes and notes to be added
**CVE-2026-78135**
- “CVE-2026-78135 - Fixed a vulnerability in libcharon related to the handling of CREATE_CHILD_SA requests on unestablished IKE SAs that can result in the creation of a usable Child SA before authentication completes. Affects 5.9.7 and newer.”
- “libcharon in strongSwan 5.9.7 through 6.0.7 mishandles behavioral workflow in the IKEv2 state machine. Because CREATE_CHILD_SA requests are mishandled, there can be an authentication bypass.”
- “It MAY be initiated by either end of the IKE SA after the initial exchanges are completed.”
- *Note to be recorded:* The fixed-in version (6.1.0) is from strongSwan's release notes; the NVD record gives the affected range (5.9.7 through 6.0.7) but no fix version. The rule matches the request pattern on the wire; whether the responder accepted it is not visible passively, as its message says.

**CVE-WATCH-KE-MALFORMED**
- “The length of the Diffie-Hellman public value for MODP groups MUST be equal to the length of the prime modulus over which the exponentiation was performed, prepending zero bits to the value if necessary.”
- “allows remote attackers to cause a denial of service (assertion failure and daemon restart) via a zero DH g^x value in a KE payload in a IKE packet.”
- “allows remote attackers to cause a denial of service (daemon crash) via an IKE_SA_INIT message with a large number of NULL values in a Key Exchange payload”
- “strongSwan before 5.9.12 has a buffer overflow and possible unauthenticated remote code execution via a DH public value that exceeds the internal buffer in charon-tkm's DH proxy.”
- *Note to be recorded:* The CVEs are named as examples of the trigger pattern (an all-zero, or too long, key-exchange value). A packet that matches the pattern is not shown to be an exploit, and an unpatched or patched daemon cannot be told apart from the wire.

**CVE-WATCH-INFO-BEFORE-AUTH**
- “INFORMATIONAL exchanges MUST ONLY occur after the initial exchanges and are cryptographically protected with the negotiated keys.”
- “An attacker can trigger a NULL pointer dereference by initiating an IKEv2 IKE_SA_INIT exchange, followed by a bogus INFORMATIONAL exchange instead of the normallly expected IKE_AUTH exchange.”
- *Note to be recorded:* The NVD sentence is quoted with its original spelling. The record describes Libreswan 3.27; the rule flags the exchange order, not a product or version.

**CVE-WATCH-INIT-PAYLOADS**
- “The first pair of messages (IKE_SA_INIT) negotiate cryptographic algorithms, exchange nonces, and do a Diffie-Hellman exchange”
- “allows remote attackers to cause a denial of service (restart) via an IKEv2 I1 notification without a KE payload.”
- “allows remote attackers to cause a denial of service (NULL pointer dereference and IKE daemon restart) via IKEv2 packets that lack expected payloads.”
- *Note to be recorded:* RFC 7296 1.2 is the text behind 'IKE_SA_INIT carries SA, KE and Nonce'; it does not use the words 'must carry'. The CVE records are examples of the trigger pattern, from Libreswan.

**V-207205**
- “The IPsec VPN Gateway must use IKEv2 for IPsec VPN security associations.”
- “Use of IKEv2 leverages DoS protections because of improved bandwidth management and leverages more secure encryption algorithms.”
- “IKEv1 has been moved to Historic status.”
- *Note to be recorded:* DISA rates this requirement Medium (CAT II); this rule's severity is high, the project's choice, and is left as it was. DISA's check text contains an apparent slip ('If the IPsec VPN Gateway must use IKEv2 ... this is a finding'); the requirement sentence above is unambiguous. The DISA text was read from the cyber.trackr.live mirror, not DISA's own download.

**V-207193**
- “Verify all IKE proposals are set to use DH Group of 16 or greater for IKE Phase 1.”
- “If the IKE option is not set to use DH Group of 16 or greater for IKE Phase 1, this is a finding.”
- *Note to be recorded:* DISA says all IKE proposals; this rule judges only the group that was negotiated, not every group offered. Severity High matches DISA's. The requirement is stricter than RFC 8247, which allows group 14 (said in the rule's message). Judged by IANA group number, as the file's comment says.

**V-207223**
- “Verify the IPsec VPN Gateway uses IKE with SHA-2 at 384 bits or greater to protect the authenticity of communications sessions.”
- “If the IPsec VPN Gateway is not configured to use IKE with SHA-2 at 384 bits or greater to protect the authenticity of communications sessions, this is a finding.”
- *Note to be recorded:* DISA rates this requirement High (CAT I); this rule's severity is medium, the project's choice, and is left as it was. 'FIPS-validated' in DISA's title cannot be seen on the wire. The DISA discussion text says 'should not be configured to use SHA-2' where it evidently means SHA-1. The DISA text was read from the cyber.trackr.live mirror.

**RFC4301-CONFIDENTIALITY**
- “The IP Authentication Header (AH) [Ken05b] offers integrity and data origin authentication, with optional (at the discretion of the receiver) anti-replay features.”
- “The Encapsulating Security Payload (ESP) protocol [Ken05a] offers the same set of services, and also offers confidentiality.”
- *Note to be recorded:* RFC 4301 does not forbid AH-only protection (implementations MAY support AH and ESP can also be used for integrity only); that AH-only traffic 'should' be ESP is this project's judgement, medium.

**RFC8221-AH-INTEG**
- “AUTH_HMAC_MD5_96 | MUST NOT”
- “As MD5 is known to be vulnerable to collisions, these algorithms MUST NOT be used.”
- “AUTH_HMAC_SHA1_96 | MUST-”
- “AUTH_HMAC_SHA2_256_128 | MUST”

**RFC8221-AH-LEGACY**
- “AUTH_HMAC_SHA1_96 has been downgraded from MUST in [RFC7321] to MUST- as there is an industry-wide trend to deprecate its usage.”
- “AUTH_AES_XCBC_96 | SHOULD / MAY”
- “AUTH_AES_XCBC_96 is set as SHOULD only in the scope of IoT”
- *Note to be recorded:* RFC 8221 does not say HMAC-SHA1-96 or AES-XCBC-96 should not be used; 'informational' is this project's severity. That a 12-byte AH ICV means a 96-bit algorithm is packet geometry, not RFC 8221 text.

**RFC8221-ESP-3DES**
- “ENCR_3DES | SHOULD NOT | No | [RFC2451]”
- “ENCR_3DES status has been downgraded from MAY in [RFC7321] to SHOULD NOT.”

**RFC4303-SEQ**
- “the transmitted sequence number must never be allowed to cycle.”
- “In other words, the sender MUST NOT send a packet on an SA if doing so would cause the sequence number to cycle.”
- *Note to be recorded:* The RFC text is about the sender's counter not cycling. The rule observes a number used twice on one SA, which is a symptom of a cycled counter but also of a replayed or duplicated packet; its message says so. Receiver-side anti-replay is not visible passively.

**RFC8247-DH-MUST**
- “Group 5 or the 1536-bit MODP Group has been downgraded from MAY in RFC 4307 to SHOULD NOT.”
- “Group 2 or the 1024-bit MODP Group has been downgraded from MUST- in RFC 4307 to SHOULD NOT.”
- “It has, therefore, been downgraded to MUST NOT.”
- “This has resulted in group 22 to be demoted to MUST NOT.”
- “Groups 23 and 24 have been demoted to SHOULD NOT”

**RFC8247-DH-OFFER**
- “Group 5 or the 1536-bit MODP Group has been downgraded from MAY in RFC 4307 to SHOULD NOT.”
- “Group 2 or the 1024-bit MODP Group has been downgraded from MUST- in RFC 4307 to SHOULD NOT.”
- “This has resulted in group 22 to be demoted to MUST NOT.”
- *Note to be recorded:* RFC 8247 marks these groups SHOULD NOT / MUST NOT; it does not say that merely offering one is a downgrade exposure. That reasoning, and the medium severity, are this project's.

**RFC8247-ENCR**
- “ENCR_AES_CBC | MUST | No”
- “ENCR_AES_GCM_16 | SHOULD | Yes”
- “ENCR_CHACHA20_POLY1305 | SHOULD | Yes”
- “The reason for promotion from MAY to SHOULD is to promote the slightly more secure AEAD method over the traditional encrypt+auth method.”
- *Note to be recorded:* Stricter than the RFC in two places, both left as they were: the rule fails ENCR_3DES (the RFC says MAY) and AES-CCM-8 (the RFC says SHOULD, for IoT), because it accepts only names containing AES-GCM, AES-CBC or ChaCha20. The RFC makes AES-CBC the MUST algorithm, GCM and ChaCha20 SHOULD.

**CNSA2-IKE-ENCR**
- “Encryption Algorithm (Transform Type 1): ENCR_AES_GCM_16 (with key size 256 bits)”

**CNSA2-IKE-PRF**
- “Pseudorandom Function (Transform Type 2): PRF_HMAC_SHA2_512 or PRF_HMAC_SHA2_384”

**CNSA2-IKE-KE**
- “Key Exchange Method (Transform Type 4): 384-bit random ECP group or 3072-bit MODP group or 4096-bit MODP group”

**CNSA2-ADDKE**
- “Additional Key Exchange 1 (Transform Type 6): ML-KEM-1024”

**CNSA2-ESP-ENCR**
- “Encryption Algorithm (Transform Type 1): ENCR_AES_GCM_16 (with key size 256 bits)”

**CNSA2-AUTH**
- “This profile REQUIRES the use of digital signature ML-DSA-87”

