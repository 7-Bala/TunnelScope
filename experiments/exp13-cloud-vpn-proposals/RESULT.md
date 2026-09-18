# EXP-13 — Cloud-VPN-style proposal sets — RESULT (2026-09-19)

Pre-registration: `PREREG.md` (commit `7b60c0d`, before any capture). Mentor follow-up C1.

**Verdict: TunnelScope can assess office-to-cloud IPsec links, and now reports the part that
matters most for them: what the cloud endpoint would *accept*, not only what one tunnel happened to
negotiate. Getting there took four fixes the experiment found, one of them a silent correctness bug
that affects any tunnel whose first key-exchange guess is refused.**

Scope, unchanged from the pre-registration: the "cloud" peer is strongSwan 5.9.8 with the **AWS
Site-to-Site VPN default proposal set** (AWS documentation, read 2026-09-18). This supports "assesses
cloud-style proposal sets correctly", **not** "tested against AWS". A real AWS tunnel is follow-up C2.

## Captures
`testbed/captures/cloud/{c-w,c-m,c-s,c-v1,a-start}.pcap` with T2 ground truth (`swanctl --list-sas`
on both peers) in the matching `*.groundtruth.json`. Registered in the dataset as `EXP-13-cloud-vpn`
(excluded split). Lab: `testbed/docker-compose.encap.yml` with `LAB_CONFIGS=cloud`,
`testbed/configs/cloud/`, `testbed/scripts/run_encap.sh <arm> <peer> [initiator]`, `CAP_SUBDIR=cloud`.

## Predictions vs results (first run, before any fix)

| # | Prediction | Result |
|---|---|---|
| P1 | IKEv2 suites OBSERVED = T2 | **Held for C-W, C-M, C-S. Failed for A-START**: suite read UNKNOWN "no IKE SA suite selected" although it is on the wire. Not predicted: a real bug (below, fix 1). |
| P2 | Exact verdicts | Held for C-M, C-S, A-START's intended verdicts. **C-W's FAILs were right for the wrong reason**: group 2 had no name (`dh-2`) and the engine scored any unnamed group as -1, i.e. FAIL (fix 2). |
| P3 | AES-GCM: `ike_integ` UNKNOWN with the wrong note "no IKE SA suite selected"; V-207223 UNKNOWN | **Confirmed exactly** (fix 3). |
| P4 | IKEv1: V-207205 FAIL; DH/integrity UNKNOWN, never PASS | **Confirmed.** |
| P5 | Weak *offered* groups not reported | **Confirmed**: the cloud's IKE_SA_INIT offered groups 2 and 22 in plaintext, nothing reported it (fix 4). |
| P6 | NAT-T arms: ESP parsed, true family kept | **Confirmed** (C-W keeps AES-CBC+SHA1; C-S excludes CBC). |
| P7 | No finding contradicts T2 | Held, except the P1 failure above (UNKNOWN, not a wrong value). |

## Lab note that became a finding
In A-START the cloud peer offers its whole default list. On the first attempt the customer side,
which then still held five configs for the same address, answered with the **first** config it had,
the legacy one, and the negotiation settled on **AES-128 / SHA-1 / MODP-1024**. That run was a lab
artefact (a real customer gateway has one config per tunnel; the arm was re-run with one) but it is
the mechanism the mentor's cloud point is about: an endpoint that *accepts* weak groups will use them
as soon as any peer asks.

## Fixes (each with a regression test in `tests/test_cloud_vpn.py`)

1. **Suite lost after an INVALID_KE_PAYLOAD retry.** The cloud opened with a DH-group-2 key
   exchange (first in AWS's list); the customer answered INVALID_KE_PAYLOAD asking for group 14; the
   retry selected MODP-2048. `ike_sa_crypto()` took the **first** IKE_SA_INIT response, the
   error-only one, and reported no suite. It now takes the last response that selects a suite (the
   rule the PQ extractor already used). Any tunnel whose first KE guess is refused had lost its IKE
   crypto findings this way; an endpoint offering many groups makes that likely.
2. **DH groups judged by name.** Groups 1, 2, 5, 17, 18, 22–24 had no name, and the engine scored an
   unnamed group as -1: strong groups 17/18 (MODP-6144/8192, both in AWS's default set) would have
   FAILed. All IANA classical groups are now named from one table; a value a rule cannot judge is
   **UNKNOWN**, never FAIL or PASS.
3. **RFC 8247 rule used group numbers.** "Group ≥ 14" passed group 22, which RFC 8247 §2.4 marks
   **MUST NOT** ("too weak"). The rule now uses the RFC's own table: FAIL for 1, 2, 5, 22, 23, 24
   (MUST NOT / SHOULD NOT). The DISA rule stays literal ("DH Group of 16 or greater", SRG text
   checked 2026-09-18), judged by IANA number, with a note that 22–24 pass it but fail RFC 8247.
4. **Offer exposure.** New finding `ike_offered_dh` (the initiator's offered groups, plaintext) and
   rule `RFC8247-DH-OFFER` (medium): FAIL if the offer includes a MUST NOT / SHOULD NOT group. On
   A-START the tunnel negotiated MODP-2048, **but the cloud endpoint offered 12 groups including 2
   and 22**: `RFC8247-DH-OFFER` FAILs. Limit, stated in the finding: only the initiator's offer is on
   the wire; a responder's acceptable set never is. So this is visible when the cloud initiates (AWS
   `Start`) or when auditing the customer's own offer; with AWS's default `Add` the cloud's accepted
   set is invisible passively and needs T2 (the provider's tunnel options) or active probing.

Also: the AEAD integrity note now says what is true ("AEAD suite: no separate integrity transform;
integrity is part of the cipher, PRF …"), and the PRF is a finding (`ike_prf`). DISA V-207223 stays
UNKNOWN for AEAD suites: whether DISA's SHA-384 integrity requirement is met by the PRF of a GCM
suite is DISA's call, not ours to guess.

## Final verdicts
| Arm | Selected suite | Offered groups | V-207205 | V-207193 | V-207223 | RFC8247-DH-MUST | RFC8247-DH-OFFER |
|---|---|---|---|---|---|---|---|
| C-W legacy branch | AES-CBC-128 / SHA-1 / MODP-1024 | MODP-1024 | PASS | FAIL | FAIL | FAIL | FAIL |
| C-M common default | AES-CBC-256 / SHA2-256 / MODP-2048 | MODP-2048 | PASS | FAIL | FAIL | PASS | PASS |
| C-S hardened | AES-GCM-256 / PRF SHA2-384 / ECP-384 | ECP-384 | PASS | PASS | UNKNOWN | PASS | PASS |
| C-V1 IKEv1 | (IKEv1: not extracted) | — | **FAIL** | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| A-START cloud initiates | AES-CBC-256 / SHA2-256 / MODP-2048 | 12 groups incl. 2 and 22 | PASS | FAIL | FAIL | PASS | **FAIL** |

## Verification
129/129 unit tests (9 new), 69/69 E2E, dataset PASS (87 pcaps), findings differential vs `HEAD`:
171 changes, all allowed and all intended: the two new findings on every IKE capture (167), and the
two EXP-13 captures' fixed values (4). **No existing finding changed on any of the other 134
captures.**

## What this does and doesn't let us claim
- **Can claim:** TunnelScope correctly assesses tunnels negotiated against a cloud provider's default
  proposal set, flags weak selections by the standard they break, and reports when an initiating
  endpoint *offers* groups RFC 8247 forbids.
- **Cannot claim:** tested against AWS itself (C2), Azure or GCP; IKEv1 suite analysis (still
  version-only); the responder's acceptable set from passive capture (not on the wire).
