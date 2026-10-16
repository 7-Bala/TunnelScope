# EXP-54: verified source text for the 21 rules that still lacked it (T-122 part 4): RESULT (2026-10-15)

Pre-registration `a28b90c`; rule metadata, scorer and tests `cd4645e` (both committed before the scored result was read).
Numbers below are from `results/summary.json` only (1,223 captures, scored against `main` at `7820c65`), except the mutation counts, which come from `mutate.py`.

## Verdict by the pre-registered bars
**All five hold.** No verdict, severity, assertion or message changed; the 21 rules now carry section, page, verbatim quotes and the notes the PREREG promised.

| # | Bar | Result | |
|---|---|---|---|
| H1 | nothing the engine reads changed | verdicts of all default baselines and all opt-in profiles identical to `main` on **1,223 of 1,223** captures (**0 differences**); 8 rules files compared field by field, **0 differences** | held |
| H2 | every quote verbatim | **50 quotes**, 0 missing, 0 under 20 characters, 0 that differ from the PREREG appendix; all **17 of 17** source files hash to the registered SHA-256 | held |
| H3 | pages are real | 0 violations; 0 rules whose section, page or sources differ from the PREREG table | held |
| H4 | coverage | all **43** rules in the rules directory (default baselines and profiles) now have section, page and quote; **0 without** | held |
| H5 | disclosed gaps written down | **12** registered notes, all present verbatim; 0 problems | held |

The whole unit suite passes, and the 29 tests added here (`tests/test_rule_sources.py`) pass. **Mutation checks (`mutate.py`): 8 of 8 mutants were caught, each by the test that should catch it:**
a changed word in a quote (V-207193), a changed page (RFC8247-ENCR), a changed source hash (RFC 8221), a changed severity (V-207223), a changed assertion value (V-207193),
an emptied quote list (CNSA2-AUTH), a removed note (V-207223) and an unknown source key (CVE-WATCH-INIT-PAYLOADS).

## What this means for T-122
The T-122 target is "every rule cites a verified source text". After this experiment that is true for every rule the project ships (43 of 43): the NIST profile (11), the NSA profile (9), the DST baseline (2) and these 21 (CVE 4, DISA 3, RFC 8221/4303 5, RFC 8247 3, CNSA 2.0 6).
**Still open under T-122:** the offered encryption and integrity lists as attributes (the NSA guide's main ask), which need a new attribute and their own experiment.

## Gaps between source and rule (written into the rules as `note`; the rules are unchanged)
- **V-207205** (IKEv2): DISA rates it Medium, the rule says high. **V-207223** (SHA-2 384+): DISA rates it High, the rule says medium. Both left as they were; whether to follow DISA is the owner's decision.
- **V-207193** judges only the negotiated DH group; DISA says "all IKE proposals".
- **RFC8247-ENCR** is stricter than RFC 8247: it fails ENCR_3DES (RFC: MAY) and AES-CCM-8 (RFC: SHOULD, for IoT).
- **RFC8247-DH-OFFER, RFC4301-CONFIDENTIALITY, RFC8221-AH-LEGACY, RFC4303-SEQ:** the sources do not say what the rule says (downgrade exposure; "should be ESP"; "informational"; a repeated number versus a cycled counter). Each note says which part is the project's own reasoning.
- **CVE-2026-78135:** the fixed-in version (6.1.0) is from strongSwan's release notes; NVD gives the affected range only. The four CVE watch rules cite CVEs as *examples* of a trigger pattern, from other products (Libreswan, Openswan, strongSwan); a match on the wire is not shown to be an exploit.

## What this experiment did not do
- It does not show that a quote *proves* the rule's exact assertion; that is a judgement, and the notes above mark the places where the two differ.
- The DISA text was read from the cyber.trackr.live mirror of the V2R6 STIG, not from DISA's own download (its address could not be found); it was not compared with DISA's file.
- RFC errata, later drafts and later NVD edits were not checked. The CNSA 2.0 text is an Internet-Draft (version 04, 19 July 2026), not a standard.
- The source files live outside the repository (`~/Datasets/sources/part4/`); the scorer and one test refuse a file whose hash differs.

## Deviations and incidents
- **The first scored run had a scorer bug, not a rule problem:** H3 reported six "not in the PREREG table / wrong file" violations for the CNSA 2.0 rules because the scorer compared a file's base name with the PREREG's `profiles/cnsa2-ipsec.yaml`. H1, H2, H4 and H5 held in that run. The comparison was fixed (`analyze.py`, one line) and the whole scorer rerun; this RESULT is the rerun. The first run's 44 quotes (not 50) are the six CNSA quotes the bug skipped.
- A first attempt at the mutation checks ran them with `TUNNELSCOPE_RULES_DIR`, which `tests/conftest.py` deliberately strips, so all eight "survived"; that was an invalid test of the method, not a weakness in the tests. They were rerun on a scratch copy of the code (see `mutate.py`) and all eight were caught.
- Two of the new tests (source hashes on disk; quotes verbatim and on the declared pages) exist only where `~/Datasets/sources/part4/` exists, because the sources are not ours to redistribute; CI does not have them and does not run them. The guard refuses `skipif`, so they are defined conditionally instead and this is stated here and in the test file. `analyze.py` applies the same checks, and the mutants M1 to M3 are caught only by those two tests.
- The 20-character floor for quotes applies to the 21 rules only (pre-registered); five earlier quotes in the NSA and NIST profiles are shorter and were left alone.
- Commit `cd4645e` was made in this checkout by another session of this project while the rerun was in progress (not by the session that wrote this file); it contains the rule metadata, scorer fix and tests described here and nothing else.
