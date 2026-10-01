# EXP-40 — Read the negotiated suite of an IKEv1 session — RESULT (2026-10-02)

Pre-registration `9d95710`. The lab, the eight captures, the scorer and the before-snapshot (`results/before.json`) were
committed in `04a8a27`, before any extractor existed. Scores in `results/summary.json`. Decision: DEC-051.

## 1. Scores

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P40-1 | Every established arm: OBSERVED `ike_encr`, `ike_prf`, `ike_dh_group` equal pluto's own log | **8 of 8** | held |
| P40-2 | Two-offer arm reports the selected suite, not the offer | **1 of 1**: reports `AES-CBC-128 / PRF-HMAC-SHA1 / MODP-1536`, the second offer; the first was `AES-CBC-256 / SHA2-256 / MODP-2048` | held |
| P40-3 | With only the initiator's offer (no responder SA), all three UNKNOWN | **8 of 8** (7 initiator packets each, the first message and its six retransmissions) | held, see 3 |
| P40-4 | No IKEv2 capture changes in any finding | findings differential against `main`: 701 captures, 27 changed findings, all on IKEv1 captures, **0 on IKEv2** | held |
| P40-5 | `V-207193` FAIL except the ECP-256 arm (PASS); `V-207205` FAIL everywhere; no `RFC8247-*` verdict on any IKEv1 arm | **8 of 8**: V-207193 FAIL on 7 and PASS on `e40-m-aes128-sha256-g19`; V-207205 FAIL on 8; 0 RFC 8247 verdicts | held |
| P40-6 | Nothing else on these arms changes | **8 of 8** (status and value of every other finding identical to the before-snapshot) | held |

## 2. Beyond the pre-registered arms

- **A second implementation agrees.** `cloud/c-v1.pcap`, an IKEv1 session between two strongSwan peers that existed before
  this experiment, now reads `AES-CBC-128 / PRF-HMAC-SHA1 / MODP-1024`; strongSwan's own `swanctl --list-sas` for it says
  `AES_CBC-128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024`. Libreswan was the lab; this is a different stack.
- **Mutation checks** (named in the PREREG): reading the initiator's SA instead of the responder's, dropping the key length,
  accepting a multi-transform payload as a selection, dropping the RFC 8247 scoping, and losing the "offer is not used" note:
  all five caught. One mutation first survived (the multi-transform guard is unreachable from the real captures, because the
  responder-SPI filter removes initiator packets first), so two tests that feed the reader crafted rows were added; it is now
  caught. 18 tests in `tests/test_ikev1_suite.py`.
- The third-party Wireshark captures stage of the full check passes.

## 3. Limits and deviations, stated plainly

1. **The failed-negotiation arm was never run.** All eight arms established, so the second clause of P40-3 ("and in any arm that
   failed to negotiate") had no instance. Only the initiator-only cut was exercised. The code path for a response that carries no
   SA is the same one, but it is not independently tested on a real failed IKEv1 negotiation.
2. **A lab fix before analysis.** The first capture of the multi-offer arm selected the first offer, which cannot tell selection from
   offer. The responder was given its own config that accepts only the second offer and the arms were recaptured, before any
   extractor existed (`ipsec.conf.b`).
3. **A lab quirk.** In every arm the initiator's message 1 is sent seven times (retransmitted at 0.5, 1, 2, 4, 8 and 16 s) before the
   responder answers; I did not find why. It is a usable test that the reader ignores repeated initiator messages, but the captures
   are not typical of timing in the field.
4. Same implementation at both ends in the lab (Libreswan 5.4), pre-shared key, one run per arm.
5. IKEv1's **authentication method** is also in the clear in the same payload; `peer_auth_method` is unchanged and still
   NOT_OBSERVABLE. `ike_integ` stays UNKNOWN by design (IKEv1 has no separate integrity transform). Follow-ups, not done.

## 4. What it cost: earlier pinned expectations that changed (owner-approved 2026-10-02)

- `tests/test_nist80077_profile.py`: the `cloud/c-v1` row, pre-registered in EXP-35 as `F U U U U U N P U U N` because the IKEv1 suite
  was unreadable, is now `F P F U F F N P U U N`. The PREREG table is untouched; the test comment points here.
- `tests/test_cloud_vpn.py`: no longer reads an `RFC8247-DH-MUST` verdict on an IKEv1 session; it asserts none exists. The "never
  PASS" assertions on the DISA rules are unchanged.
- The `build/guard_diff.py` rule that flags removed `assert` lines was overridden for these two edits (`ALLOW_TEST_EDITS=1`) with the owner's approval.
- The ipsec.conf reader gained the `aggrmode` keyword (found by the existing "every lab config parses with nothing unknown" test),
  and `exp40/` is registered as a sub-dataset with ground truth beside each pcap, like `exp26/27/29`, because `MANIFEST.csv` is immutable.
