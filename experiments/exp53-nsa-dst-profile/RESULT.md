# EXP-53 — NSA "Configuring IPsec Virtual Private Networks" as an opt-in profile, and verified source text for the DST/NQM baseline — RESULT (2026-10-15)

Pre-registration `bad7fdf`; code and scorer `2a72e51` (both committed before the scored run). Numbers below are from
`results/summary.json` only (1,223 captures, 1,462 security associations, scored against `main` at `be79356`).

## Verdict by the pre-registered bars
**All five hold.** Nothing about the default reports changed; a new opt-in profile exists; the two DST rules now cite verified text.

| # | Bar | Result | |
|---|---|---|---|
| H1 | default verdicts on every capture identical to `main` (the DST baseline is a default baseline) | 1,223 of 1,223 captures compared, **0 differences** | held |
| H2 | every quote is verbatim in its source PDF | NSA **20 of 20** quote strings found in the NSA guide; DST **5 of 5** found in the DST report; none missing | held |
| H3 | the pre-stated verdicts on ten real captures | **10 of 10** rows matched, all 90 verdicts | held |
| H4 | no profile rule PASSes on an absent, UNKNOWN or NOT_OBSERVABLE attribute, over the whole corpus | **0 violations** | held |
| H5 | the DST rules keep id, attribute, assertion, severity, message and title | identical to `main` | held |

The whole unit suite and the tests added here (`tests/test_nsa_ipsec_profile.py`, 15 tests) pass. **Mutation checks:** 12 deliberate
breakages of the rules (the outdated-DH list without group 5, the offer rule without group 5, the wrong ESP suite, the wrong integrity
hash, 3DES forgotten, the ESP outdated list cut to one name, the DH example widened to ECP, AES-CBC-256 dropped from the example, an
example rule promoted to medium, a DST severity lowered, a DST assertion changed, a DST rule's quote removed) were each caught by at
least one test. One first attempt at the "promoted" mutant was a bad edit that broke the YAML and failed 14 tests for the wrong reason; it
was redone correctly and caught for the right one.

## What the profile shows on the corpus (verdict counts over all 1,462 SAs; rules 5 and 9 have no verdict on the 328 SAs without ESP)
| Rule | PASS | FAIL | UNKNOWN |
|---|---|---|---|
| NSA-IKE-DH-EXAMPLE (group 16) | 2 | 435 | 1,025 |
| NSA-IKE-ENCR-EXAMPLE (AES-256) | 164 | 273 | 1,025 |
| NSA-IKE-PRF-EXAMPLE (SHA-384) | 49 | 388 | 1,025 |
| NSA-IKE-INTEG-EXAMPLE (SHA-384) | 45 | 376 | 1,041 |
| NSA-ESP-SUITE-EXAMPLE | 0 | 1,102 | 32 |
| NSA-IKE-OUTDATED-ENCR (DES/3DES) | 174 | 263 | 1,025 |
| NSA-IKE-OUTDATED-DH (groups 1, 2, 5) | 424 | 13 | 1,025 |
| NSA-OFFER-OUTDATED-DH | 439 | 11 | 1,012 |
| NSA-ESP-OUTDATED | 723 | 0 | 411 |

Read these with care.
- The five "example" rules are **informational** and compare against the guide's own example. On this corpus almost everything fails
  them (for instance 2 of 437 IKE SAs use DH group 16) because the guide's example is a narrow, strict setting; that is not a finding that those tunnels are weak.
- **1,025 of 1,462 SAs have no readable IKE handshake** (ESP-only or handshake-less captures), so the IKE rules are UNKNOWN there. They are never PASS.
- The 263 "outdated encryption" FAILs and the 13 "outdated DH" FAILs come from a corpus that includes lab captures made with weak algorithms on purpose; this experiment did not split them by origin, so they show that the rules fire, not how common weak crypto is on real networks.
- **ESP rules rarely decide.** NSA-ESP-OUTDATED never FAILs (it fails only if *every* cipher that fits the packets is DES/3DES) and NSA-ESP-SUITE-EXAMPLE
  can only FAIL or stay UNKNOWN: the ESP key length cannot be seen (F-05), so a pass is never claimed.

## What this experiment did not do
- **The guide's main ask for tunnel owners is not judged.** NSA says to remove every non-compliant suite from the configuration. Only the
  *offered DH groups* are an attribute today, so only rule 8 tests an offer. Offered encryption and integrity lists need a new attribute and a new experiment.
- **Not made into rules** (listed in the PREREG with reasons): gateway ACLs and IPS, FIPS validation, patching, vendor defaults, pre-shared-key replacement, the vendor appendices.
- **The shorter NSA sheet** ("Securing IPsec Virtual Private Networks", two pages) could not be saved and was not used.
- **The DST report does not name a key-exchange mechanism for IPsec**, and does not rank downgrade as high. The two rules' notes say so; their wording and severity are unchanged and are the project's choices, not DST's.
- **DST's own copy is gone.** The report's original address returns 404 and DST's page lists no document (2026-10-15). The quotes were checked against the
  Internet Archive's copy of that address (2026-09-26, SHA-256 `461d8b42...`). The longer final version reported in the press was not found.
- **The CNSSP 15 policy itself was not read.** The guide's examples are "per CNSSP 15 as of June 2020" in its own words; CNSA 2.0 is covered separately by `cnsa2-ipsec`.

## What is still open on T-122
The T-122 target is "every rule cites a verified source text". After this experiment that holds for the NIST profile (11 rules), the NSA profile (9) and the DST baseline (2).
It does **not** hold for the default DISA, RFC 8221/4303, RFC 8247 and CVE baselines or for the CNSA 2.0 profile: those rules have no `section`, `page` or `quote` field (the CNSA 2.0 file's header says its text was quoted from the draft, but nothing checks it).

## Deviations and incidents
- The NSA PDF was saved through the owner's own Chrome on 2026-10-15; the publisher's host answers scripted downloads with HTTP 403. The file is not in the repository.
- Both source files live outside the repository (`~/Datasets/sources/`); the scorer refuses a file whose hash differs from the pre-registered one.
- The scored run is slow (tens of minutes): it reads every capture three times (this branch, `main`, and the profile check) on a shared machine.
