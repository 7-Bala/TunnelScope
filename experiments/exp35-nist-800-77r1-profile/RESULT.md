# EXP-35 — NIST SP 800-77 Rev. 1 as an opt-in rules profile (T-122 part 2) — RESULT (2026-09-29)

Pre-registration `PREREG.md` (654e2ff), committed before any code and any run; no addendum. Scored by `analyze.py`
-> `results/summary.json` (every number below is from that file).

## What was built
`tunnelscope/rules/profiles/nist-sp800-77r1.yaml`: 11 rules from Table 1 ("Approved Algorithms and Options") and
sections 2.2, 3.11, 4.1.4, 4.5, 7.2.3, 7.2.4.2 and 7.2.6 of NIST SP 800-77r1, each with `section`, `page` and the
verbatim `quote`s it rests on. Opt-in only: `tunnelscope assess --profile nist-sp800-77r1`. One new engine operator,
`not_contains` (for "AH should not be deployed"; a non-list is UNKNOWN). A plain explanation for every rule.

## Results
| Bar | Result |
|---|---|
| H1 default verdicts unchanged | **0 differences over 695 captures** between this branch and a clean worktree of `main` (85777ca), each run importing its own code (checked) |
| H2 quotes are verbatim | **20/20 quotes found** in the normalised `pdftotext -raw` text of the PDF with SHA-256 `bc2a36dc…74bd70` |
| H3 pre-stated verdicts | **10/10 captures, all 11 rules exactly as pre-registered** |
| H3 corpus: ESP rules undecided | NIST77-ESP-ENCR and NIST77-ESP-INTEG: **0 PASS, 0 FAIL** on 668 SAs (619 UNKNOWN, 49 no verdict: not ESP) |
| H4 no PASS without evidence | **0 violations** over 695 captures / 668 SAs |

Verdict counts over the corpus (668 SAs; 509 have no handshake in the capture, so the IKE rules are UNKNOWN there):

| Rule | PASS | FAIL | UNKNOWN | NOT_OBSERVABLE |
|---|---|---|---|---|
| NIST77-IKE-VERSION | 159 | 1 | 508 | 0 |
| NIST77-IKE-ENCR | 143 | 2 | 523 | 0 |
| NIST77-IKE-PRF | 141 | 4 | 523 | 0 |
| NIST77-IKE-INTEG | 138 | 4 | 526 | 0 |
| NIST77-DH-APPROVED | 140 | 5 | 523 | 0 |
| NIST77-DH-RECOMMENDED | 137 | 8 | 523 | 0 |
| NIST77-PFS | 10 | 14 | 6 | 638 |
| NIST77-AH | 619 | 5 | 44 | 0 |
| NIST77-ESP-ENCR | 0 | 0 | 619 | 0 |
| NIST77-ESP-INTEG | 0 | 0 | 619 | 0 |
| NIST77-AUTH | 0 | 0 | 504 | 164 |

Tests: `tests/test_nist80077_profile.py` (16: opt-in, the 10 pre-registered rows, source fields, explanations for
every profile's rules, `not_contains`, ESP candidate logic). 7 mutation checks, all caught: `not_contains` inverted;
`not_contains` passing a non-list; the profile copied into the default rules; DH-APPROVED loosened to groups 1, 2;
`applies_to_protocol: ESP` removed; 3DES accepted for IKE; Curve25519 treated as Recommended.

## What this does and does not show
- It shows the rules say what the publication says (H2 is a mechanical substring check against the hashed PDF) and
  judge real captures as pre-stated. It does not show NIST endorses this mapping; the rule-making method (which
  sentence becomes which rule, severity from shall/should) is ours and is written in the PREREG.
- The two ESP rules are honest but, on today's corpus, never decisive: packet sizes cannot separate AES-GCM from
  ChaCha20 or AES-CBC+HMAC-SHA1-96 from 3DES. They report UNKNOWN rather than guess.
- Peer authentication, FIPS-validated modules, lifetimes, the PFS group, NULL authentication, PSK strength and
  manual keying are not decidable from a capture; the PREREG lists each with its reason.
- The source itself is inconsistent on HMAC-SHA-1 (sec 7.2.3 "still a NIST-approved option"; sec 4.1.4 "no longer
  NIST-approved"). The rules test Table 1's Recommended column (SHA-2 only), which does not depend on that.
- Curve25519 (DH 31) FAILs NIST77-DH-RECOMMENDED: Table 1 puts DH 31/32 in its "Expected" column (2020). That is the
  publication's position as written, not a claim that X25519 is weak; it PASSes NIST77-DH-APPROVED.

## Decision
DEC-049: the profile ships opt-in; defaults, goldens and the public demo are unchanged.
