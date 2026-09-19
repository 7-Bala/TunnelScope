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

## Addendum A (2026-09-20, written while EXP-15 part A was still capturing, before any of its data was read)
Working through the arithmetic for real traffic before the data exists: the floor rule needs an
upper-layer packet under ~26 bytes. A default ping (56-byte payload) and a TCP pure ACK with
timestamps (32-byte header) both sit above the GCM floor in transport mode, so **P14-3 is expected
to fail on realistic traffic**; the rule will mostly fire on tiny packets (size sweeps, empty UDP).

**Exploratory (not confirmatory) follow-up, declared now:** a mode classifier trained on EXP-15's
tunnel vs transport sessions (same 8 classes, same cipher). Basis: the commonest small packet in a
TCP-carrying SA is the pure ACK, whose inner length is 52 or 40 bytes in tunnel mode (IPv4 + TCP
with/without timestamps) and 32 or 20 in transport mode; where the cipher overhead is unambiguous
(all surviving sieve families share IV/ICV/alignment), the observer can compute that length.
Evaluated leave-one-repetition-out; reported with calibrated confidence and an abstain rule. Because
it is exploratory it ships only as INFERRED with its confidence and the stated basis, and only if its
held-out accuracy is ≥ 0.95 with zero tunnel sessions called transport at the chosen threshold.

## Addendum B (2026-09-20, AFTER analysis — a post-hoc fix, stated as such)
The first shipped mode model called the tunnel capture `cs-aes256gcm16` "transport". Its ping size
sweep spreads packets over BOTH modes' ACK buckets (purity 0.56), a pattern absent from the training
sessions. Fix: abstain unless ≥ 80% of ACK-bucket packets sit on one mode's side (`MIN_PURITY`), and
every tracked capture with a ground-truth mode is now an out-of-domain check in `analyze.py`. Because
the guard was chosen after seeing that failure, the held-out numbers below are not a clean test of it.
