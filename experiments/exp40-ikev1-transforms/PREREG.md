# EXP-40 — Read the negotiated suite of an IKEv1 session — PRE-REGISTRATION (2026-10-02, before any capture and any code)

## Why
For IKEv1 the product says "IKEv2 suite extraction not applicable" and reports the IKE cipher, hash and DH group as
UNKNOWN. That is honest but incomplete: in an IKEv1 Main Mode or Aggressive Mode exchange the responder's chosen
transform (cipher, hash, DH group, authentication method) travels in the clear in its first SA payload
(RFC 2409 sections 5.1, 5.4). EXP-37 saw this on another lab's IKEv1 sessions: the version was OBSERVED and everything
else UNKNOWN. IKEv1 is still found on real gateways, and its weak suites (3DES, SHA-1, MODP-1024/1536) are exactly
what an assessor must report. This experiment adds that extraction and tests it against sessions whose configuration
we set and whose negotiated result the endpoint itself logged.

## Lab (fixed here)
Libreswan 5.4-5.fc46 <-> Libreswan 5.4-5.fc46 (image `testbed-libreswan`), pre-shared key, through the keyless
router (the vantage of EXP-07). Per arm its own address pair, one `ipsec.conf` for both peers, `keyexchange=ikev1`.
Ground truth = the arm as configured **and** pluto's own "ISAKMP SA established {... cipher= integ= group=}" line.
Seven arms are planned; each is run once:

| Arm | Mode | `ike=` |
|---|---|---|
| e40-m-aes256-sha256-g14 | main | aes256-sha2_256-modp2048 |
| e40-m-aes128-sha1-g5 | main | aes128-sha1-modp1536 |
| e40-m-3des-sha1-g5 | main | 3des-sha1-modp1536 |
| e40-m-aes256-sha384-g15 | main | aes256-sha2_384-modp3072 |
| e40-m-aes128-sha256-g19 | main | aes128-sha2_256-dh19 |
| e40-a-aes256-sha256-g14 | aggressive (`aggrmode=yes`) | aes256-sha2_256-modp2048 |
| e40-a-aes128-sha1-g5 | aggressive | aes128-sha1-modp1536 |
| e40-m-multi | main | aes256-sha2_256-modp2048,aes128-sha1-modp1536 (two offered) |

An arm that Libreswan refuses to run (3DES or a small group may be disabled) is kept as a negotiation-failed arm
with its own pluto log; it is scored under P40-3 only.

## What has been seen before this was written
tshark exposes `isakmp.ike.attr.encryption_algorithm / hash_algorithm / group_description / key_length /
authentication_method`. EXP-37 showed IKEv1 sessions from another lab giving `ike_version` OBSERVED and the
suite UNKNOWN. No IKEv1 capture of ours exists, no extraction code is written, no capture of these arms is taken.

## The change under test (fixed here)
- A reader returns, per IKEv1 phase-1 session, the **responder's** SA payload from Main Mode message 2 or Aggressive
  Mode message 2 (responder SPI non-zero, exchange type 2 or 4). Quick Mode (exchange 32) is encrypted and is not read.
- `ike_encr` (name plus key length, e.g. `AES-CBC-256`), `ike_dh_group` (e.g. `MODP-1536`) and `ike_prf`
  (the IKEv1 hash named as its PRF, e.g. `PRF-HMAC-SHA1`) become OBSERVED with a pointer to the responder frame.
  `ike_integ` stays UNKNOWN for IKEv1 (the single hash algorithm is the PRF and the HMAC; there is no separate
  integrity transform), with a note saying so. With no responder SA in the file, all stay UNKNOWN.
- RFC 8247 is an IKEv2 document. Its rules gain `applies_to_ike_version: IKEv2` and produce no verdict for a session
  whose `ike_version` is OBSERVED as IKEv1, the same way an AH rule produces none for an ESP-only SA. The DISA rules
  are not scoped.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P40-1 | In every arm that establishes, OBSERVED `ike_encr`, `ike_prf`, `ike_dh_group` equal the pluto-log suite (cipher with key length, hash, group) | any mismatch or any UNKNOWN |
| P40-2 | In the two-offer arm the value reported is the one the responder selected (per the pluto log), not the first offer and not both | it is the offer |
| P40-3 | Cut after the initiator's first message (no responder SA), and in any arm that failed to negotiate: `ike_encr`, `ike_prf`, `ike_dh_group` are all UNKNOWN | any value asserted |
| P40-4 | IKEv2 sessions are unaffected: findings and verdicts identical to before on every IKEv2 capture of the corpus (the findings-diff stage of the full check, 695 captures) | any difference on an IKEv2 capture |
| P40-5 | Verdicts on the established IKEv1 arms: `V-207193` (DH group >= 16) FAIL on every arm except `e40-m-aes128-sha256-g19` where it PASSes; `V-207205` (IKEv2 required) FAIL on every arm as today; **no `RFC8247-*` verdict at all** on any IKEv1 arm | any other verdict, or any RFC8247 verdict |
| P40-6 | `peer_auth_method` and every other finding on these arms is unchanged by the change | any other finding differs |
Exploratory, not scored: the same extraction on the third-party IKEv1 captures in `build/validate_external.py`'s set
compared with the sample's own description, and on the two IKEv1 sessions of the other lab seen in EXP-37.

## Method and bars (fixed here)
Capture harness `testbed/scripts/run_exp40.sh` (modelled on `run_exp07.sh`); captures `testbed/captures/exp40/`
(small, as the others); ground truth JSON per arm. `analyze.py` scores P40-1..P40-3, P40-5, P40-6 against the
ground-truth files. Tests: new unit tests on a cut and an intact capture of an IKEv1 arm; **each of these mutations
must be caught by a test**: read the initiator's SA instead of the responder's, read the cipher but drop the key
length, assert a value when no responder SA exists, drop the RFC 8247 scoping. Behaviour decision recorded as DEC-051.
Reported whether or not each prediction holds.
