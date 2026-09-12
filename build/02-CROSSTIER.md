# TunnelScope — Stage 3: Cross-Tier Consistency (C5)

Stage 3 of the build order (`00-ARCHITECTURE.md` §8). It ingests **T2 endpoint
telemetry** — what the box itself reports via `swanctl --list-sas`, the pluto
log, or its config — and reconciles it against the T0/T1 passive findings
already in an `EvidenceRecord`. Traceability: DEC-005 constraint 4; NOTES #13.

## Why it exists
The vantage ladder (T0→T4) is only worth building if a higher tier can actually
*change* a lower-tier answer. Stage 3 is where that happens, and it is where the
project's core discipline pays off: because every passive finding already
carries a status and a vantage, a T2 report either **raises the tier** of a
finding or **exposes a divergence** — it never silently overwrites.

## Three outcomes, per attribute
| Outcome | When | Effect on the finding |
|---|---|---|
| **Escalation** ↑ | passive was UNKNOWN / NOT_OBSERVABLE | T2 supplies the value → `OBSERVED @ T2` |
| **Confirmation** = | T2 agrees, or refines within the passive candidate set | passive finding kept, note stamped "confirmed by T2" |
| **Contradiction** ✗ | T2 disagrees | finding becomes `CONTRADICTORY` (value cleared) |

Reconciliation is per-attribute, not a naive dump, because the semantics differ:
- **`mode`** — invisible on the wire (EXP-08 proved NOT-OBSERVABLE at T0). T2 config
  resolves it. The canonical escalation.
- **`ike_dh_group`** — scalar equality.
- **`pq_key_exchange`** — `offered-but-not-used` (T0/T1 inference) and
  `classical-only` (installed) are treated as **consistent** (both = no PQ in
  effect); a T2 report of an *installed* ML-KEM against a passive
  `offered-but-not-used` is a true contradiction (the analyzer missed live PQ).
- **`esp_cipher`** — the T0 sieve yields a cipher-*family* candidate set (it cannot
  see key length, F-05). T2's exact cipher is consistent iff it shares a mode
  family (CBC / CTR / GCM / CCM / ChaCha) with a set member; otherwise conflict.
- **`tfc_padding_active`** — the **NOTES #13** case: config requested IP-TFS/TFC
  padding, but the kernel (missing `CONFIG_XFRM_IPTFS`) never applied it, so T2
  says "padding on" while T0 *measures* "padding off". A real, documented
  divergence — exactly the kind of thing a single-tier tool would report as a
  compliant tunnel.

## Direction of trust (invariant)
Ground truth is **causal** — the endpoint's own report. The analyzer's passive
inference is checked *against* T2, never the reverse. Stage 3 therefore only ever
raises a passive finding's authority or flags a divergence; a passive guess can
never overrule the endpoint. This is the same rule the whole dataset is built on
(`dataset/DATASHEET.md`): T2 is the label, T0/T1 is the prediction.

## Interface
```bash
tunnelscope crosstier <pcap> <telemetry.json>          # human-readable reconciliation
tunnelscope crosstier <pcap> <telemetry.json> --json   # machine-readable cross-checks
```
Telemetry is JSON (or trivial `key: value`). A flat block applies to the sole
IKE-bearing SA; a block keyed by initiator SPI targets a specific SA. Examples:
`testbed/telemetry/pq-downgrade.t2.json` (confirm + escalate) and
`testbed/telemetry/iptfs-contradiction.t2.json` (the NOTES #13 contradiction).

Implementation: `tunnelscope/crosstier/crosstier.py`; the CONTRADICTORY status
and cross-vantage merge live in `EvidenceRecord.add()` (`evidence/record.py`).
Tests: `tests/test_crosstier.py` (8, covering all three outcomes both ways).
