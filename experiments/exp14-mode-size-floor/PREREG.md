# EXP-14 — Transport mode from the tunnel-mode size floor — PRE-REGISTRATION (2026-09-20, before capture)

Found during the PS validation (`research/14-PS-VALIDATION.md`), revisiting EXP-08.

**Claim under test.** A tunnel-mode ESP packet carries a whole inner IP header, so its ESP content
(after SPI + sequence) has a floor:
`floor(c) = IV(c) + align(20 + 8 + 2, block(c)) + ICV(c)`, i.e. a 20-byte inner IPv4 header, the
smallest real upper-layer header (8 bytes: ICMP or UDP), the 2 trailer bytes, padded to the cipher's
alignment. The usable floor is the minimum over every cipher family still possible for the SA
(EXP-01 sieve). Any ESP packet whose content is below that floor cannot be tunnel mode, so the SA is
transport mode. The rule is one-way: packets at or above the floor prove nothing.

**Caveat, stated before testing:** TFC dummy packets (RFC 4303 §2.6, next header 59) can be small in
either mode. The rule is not applied when TFC padding is detected, and every finding names this.

**Predictions**
| # | Prediction | Falsified if |
|---|---|---|
| P14-1 | Zero false positives: no capture whose ground truth is tunnel mode is ever called transport (all tracked captures with `gt_mode` + all EXP-15 tunnel sessions) | any tunnel capture is called transport |
| P14-2 | The existing transport captures (`cs-transport-*`, `a7-cs-transport-*`) are called transport | either is not |
| P14-3 | Coverage depends on traffic: transport is provable for ICMP, VoIP-shaped UDP, interactive (small TCP segments) and messaging in ≥ 90% of sessions; for bulk and video (large segments, ACKs with TCP options) it may not fire | reported per class either way; no pass/fail |
| P14-4 | TFC-padded tunnel sessions never fire (every packet is MTU-sized) | any fires |

**Verdict rule:** if P14-1 and P14-2 hold, ship as `mode` = transport, status INFERRED (basis: size
floor), else UNKNOWN "not provable from this capture". Tunnel mode is never claimed from traffic alone.
