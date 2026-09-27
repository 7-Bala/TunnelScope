# EXP-29 — IKE implementation fingerprinting from plaintext — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (commit b3460d7, split fixed before any feature was looked at). Rules written from
the train split only and frozen in commit 271ad83 before the test set was scored. Code: `extract_implementation`
/ `IMPL_RULES` in `tunnelscope/evidence/extract.py` (new finding `implementation`, one value per end).
Scoring: `analyze.py` → `results/score.json`. New held-out Libreswan session: `testbed/captures/exp29/`
(runner `testbed/scripts/run_exp29_libreswan.sh`, own hashed `manifest.csv`). Tests: `tests/test_implementation.py`.

## Headline
On the held-out set TunnelScope named the implementation correctly at **200 of 218 ends it could have known
(91.7%) and never named the wrong one**. strongSwan 6.1.0, a major version absent from training, was recognised
at all 74 of its ends; a Libreswan session captured after the rules were frozen at 16 of 20; the OpenBSD `iked`
end, never trained on, came out UNKNOWN as it must.

## The fingerprints (from the train split; none of the captures carries a Vendor ID)
| Implementation | Signal in the sender's own IKE_SA_INIT |
|---|---|
| strongSwan | notifies start NAT_D, NAT_D, FRAGMENTATION_SUPPORTED, SIGNATURE_HASH_ALGORITHMS |
| Libreswan | notifies start FRAGMENTATION_SUPPORTED, NAT_D, NAT_D |
| MikroTik RouterOS | notifies exactly NAT_D, NAT_D, FRAGMENTATION_SUPPORTED, **and** that end pads its empty encrypted messages beyond the RFC 7296 minimum (the T-135 signal) |
An end matching none, or more than one, is UNKNOWN. Error-only responses (no proposal selected) are not fingerprinted.

## Hypotheses
| | Bar | Result |
|---|---|---|
| H1 | zero wrong labels on the test set | **PASS** (0) |
| H2 | ≥ 80% of test ends whose implementation was trained get a correct label | **PASS** (200/218 = 91.7%) |
| H3 | OpenBSD `iked` end UNKNOWN | **PASS** (2/2 records) |
| H4 | strongSwan 6.1.0 recognised (reported separately) | 74/74 |

By group: strongSwan 5.9.8 94 correct / 10 unknown · strongSwan 6.1.0 74 / 0 · Libreswan EXP-07 held-out arms
6 / 4 · Libreswan new session 16 / 4 · MikroTik M5–M8 8 / 0 · EXP-10 strongSwan initiator 2 / 0, `iked` 0 / 2 (correct).

## The 18 unknown known-implementation ends
- **10 strongSwan responders** (EXP-06r2 failure arms f01/f06): the responder never sent a proposal-bearing
  IKE_SA_INIT response, so there was nothing to fingerprint.
- **8 Libreswan ends** (the `e7-classical` and `e7-pq` arms, both sessions): Libreswan inserts
  INTERMEDIATE_EXCHANGE_SUPPORTED (16438) right after FRAGMENTATION_SUPPORTED when IKE_INTERMEDIATE is enabled, so
  the frozen rule (FRAG, NAT_D, NAT_D) does not match. Generalising the rule is easy but was **not** done here:
  changing rules after seeing the test set would contaminate this result. Follow-up, to be validated on new data.

## Disclosed scorer fix
The first scoring run put EXP-10 under "strongSwan on both ends" because its `dataset/MANIFEST.csv`
implementation value starts with `strongswan` (`strongswan-6.1.0+openbsd-iked-7.9`) and my script matched that
before the OpenBSD case, giving the `iked` end the wrong truth (and H3 no rows). The scorer now handles EXP-10
first with a truth per end. The tool's output did not change: it had labelled the `iked` end UNKNOWN both times.

## Limits
Three implementations only. An implementation that copies another's notify order would be mislabeled; the finding
says so in its note, and it is informational only (it changes no verdict). Wider coverage needs the multi-vendor
lab (T-118 steps 2–3) and real-world captures (T-119).
