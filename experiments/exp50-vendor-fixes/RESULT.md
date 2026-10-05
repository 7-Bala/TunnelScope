# EXP-50 RESULT — Per-vendor fix templates: Libreswan and MikroTik RouterOS (T-123), 2026-10-05

Numbers are quoted from `results/summary-libreswan.json` (harness `6fcef04`, committed before the scored lab run), `results/summary-mikrotik.json` (third and scored RouterOS run; the first two are kept as
`summary-mikrotik-first-run.json` and `summary-mikrotik-second-run.json`) and the tests. Bars and predictions: `PREREG.md` with addenda A-E.

## What shipped
`tunnelscope/remediate/vendors.py` and `plan_for(rule, ..., vendor=None)`; the API route takes `vendor`. `vendor=None` or `strongswan` returns exactly what it returned before. `libreswan` and `mikrotik` return advice in that
vendor's syntax with `commands`, a `verify` command, `source`, and `verification` (`lab`, `lab-device-state` or `docs-only`); a rule with no honest template returns `template: false` and a `reason`. Always advice only: `automated_fix_available` is
false (the dry-run/rollback pipeline stays strongSwan-lab-only). 12 config rules x 2 vendors decided; the five patch/investigation rules get no template and no fixed-version claim (T-161 owns CVE facts).

## Results by rule
| Rule | Libreswan 5.4 closed loop (TunnelScope verdict before → after) | Libreswan label | RouterOS 7.24.4 one-device check (setting before → after) | RouterOS label |
|---|---|---|---|---|
| V-207205 IKEv2 | FAIL → PASS | lab | `main` → `ike2` | lab-device-state |
| V-207193 DH group | FAIL → PASS | lab | `modp2048` → `ecp384` | lab-device-state |
| V-207223 integrity | FAIL → PASS | lab | `sha256` → `sha512` | lab-device-state |
| RFC8247-DH-MUST | FAIL → PASS | lab | `modp1024` → `ecp384` | lab-device-state |
| RFC8247-DH-OFFER | FAIL → PASS | lab | `modp2048,modp1024` → `ecp384` | lab-device-state |
| RFC8247-ENCR | FAIL → PASS | lab | `3des` → `aes-256` | lab-device-state |
| DST-PQ-KE | FAIL → PASS | lab | no template (no post-quantum key exchange on this version) | `template: null` |
| DST-PQ-DOWNGRADE | FAIL → PASS | lab | no template (same) | `template: null` |
| RFC4301-CONFIDENTIALITY AH→ESP | FAIL → PASS | lab | `ah` → `esp` | lab-device-state |
| RFC8221-AH-INTEG | UNKNOWN → PASS, device report `HMAC_MD5_96` → `HMAC_SHA2_256_128` | lab-device-state | `md5` → `sha256` | lab-device-state |
| RFC8221-AH-LEGACY | FAIL → PASS | lab | `sha1` → `sha256` | lab-device-state |
| RFC8221-ESP-3DES | UNKNOWN → PASS, device report `3DES_CBC` → `AES_GCM_16_256` | lab-device-state | `3des` → `aes-256-gcm` + empty auth | lab-device-state |

## Bars
- **H1 every keyword is documented: PASS** (tests; 105 in `tests/test_vendor_fixes.py`). Every RouterOS setting name and value of every command is in the vendor page's setting tables or in the committed list of values the device
  accepted although the page omits them; every Libreswan keyword is in `ipsec.conf(5)` or the lab-verified list (`addke1`). The page itself is not committed; its two keyword tables are, with source URL, byte size and SHA-256.
- **H2 Libreswan closed loop: PASS for all 12** (24 arms, 5 pings at each of three sizes per arm, no capture retries, `ipsec replace` returned 0 on every established arm). 10 rules: the weak state FAILed on the wire before, the template's lines were applied as
  written, the tunnel came up and passed traffic, the rule PASSed after, and no rule that passed before FAILed after. 2 rules (AH-INTEG, ESP-3DES) are `lab-device-state`: the wire cannot decide the weak state (AH HMAC-MD5-96 and HMAC-SHA1-96 look the same;
  the ESP 3DES family stays UNKNOWN), which is TunnelScope's honest answer, so Libreswan's own algorithm report is the evidence (addendum A, fixed before the scored run).
  "Applied as written" means the template's lines replaced the weak lines of a new connection that was then added and brought up; the reload line `ipsec replace <conn>` was run on the established connections, not used to change a live one.
- **H3 RouterOS: 10 of 10 on the third run** (8 of 10 on the first, 9 of 10 on the second). One device (CHR 7.24.4, QEMU emulated Cortex-A72), no tunnel negotiated: each template's command text was run unchanged, the setting read back, the `verify` command's output contained the new value.
  Label `lab-device-state`, never `lab`. The failures were template faults, which is what the check is for (below).
- **H4 strongSwan untouched: PASS.** The 34 JSON hashes of `plan_for` for all 17 rules (default call and `detailed` + `include_exec`) with `vendor=None` and with `"strongswan"` equal hashes pinned from the base code (`78c9a16`, a git archive of the unmodified tree),
  and the existing remediation tests pass unedited.
- **H5 nothing invented: PASS** (tests): every template has `source` and `verification`, every `null` has a reason, the five patch rules make no version claim.
- **H6 API: PASS** (test): unknown, empty or non-string vendor is a 400 naming `strongswan, libreswan, mikrotik`; no vendor gives the old answer.
- Mutation check: 11 mutants (an undocumented RouterOS value, a wrong keyword, a deprecated reload line, `auto_applicable` true, a changed label, a version number in a patch reason, a dropped PQ reason, the default routed to the vendor path, the vendor check removed, the API ignoring `vendor`), each failed a test.

## What the labs found that the documentation did not say
1. **RouterOS accepts `hash-algorithm=sha384`; the page does not list it** (`md5 | sha1 | sha256 | sha512`). EXP-26 negotiated HMAC-SHA2-384-192 on this version and this experiment set it through REST and the CLI. I had written "RouterOS has no SHA-384" from the page; the test of that claim is why it is no longer in the product.
2. **RouterOS refuses AES-GCM next to any `auth-algorithms` value, including the documented `null`** ("AEAD already provides authentication"); an empty value works. My first fix (add `auth-algorithms=null`) was also wrong and was caught by the second run.
3. **Libreswan 5.4:** `ipsec auto` is deprecated (the reload line is `ipsec replace <conn>`), `keyexchange=ikev1|ikev2` replaces `ikev2=`, IKEv1 is off by default (`ikev1-policy=drop`) so the V-207205 fix only matters where an operator turned it on, and `addke1=` (ML-KEM) is not in the older man page but works in 5.4.
4. **RouterOS has no post-quantum key exchange** on 7.24.4: all six ML-KEM name probes for `dh-group` and `pfs-group` were refused ("invalid value"), so DST-PQ-KE and DST-PQ-DOWNGRADE return `template: null` with that reason, for this version only.

## Predictions
P1 at least 8 of 12 Libreswan templates pass H2: **held** (12 of 12, 10 as `lab`). P2 RouterOS null for both PQ rules and SHA-512 not SHA-384 for V-207223: **held for the first part; the second part was wrong** (the device accepts sha384; the page omits it;
the template keeps the documented sha512 as primary advice and says so). P3 the AH rules are the hardest on Libreswan: **not held** (the AH arms ran like the others; two rules needed the device report because TunnelScope cannot see the weak state on the wire).
P4 at least one template differs from a literal translation of the strongSwan fix, forced by the lab or the documentation: **held** (items 1-3 above).

## Disclosed
An exploratory run of all 24 Libreswan arms came first (its harness faults are in addendum A; its files are in commit `6fcef04`, overwritten by the scored run). Two RouterOS runs failed before the third passed (addenda C-E). The RouterOS REST `execute` endpoint
accepts a `find` that matches nothing without an error, so pass means the read-back value changed, never the absence of an error. The `verify` commands are run through `/rest/execute` with `as-string`, which returns the console text; they were not typed at the console.

## Not shown
Negotiation on RouterOS (no tunnel was built between two routers), any RouterOS or Libreswan version other than 7.24.4 and 5.4, applying a template to a production device (advice only; the dry-run and rollback pipeline is not extended), IKEv1 on RouterOS beyond `exchange-mode`,
Cisco, Fortinet, Juniper, PAN-OS or VyOS templates, a Libreswan before/after on a live connection edited in place.
