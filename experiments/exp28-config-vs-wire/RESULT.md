# EXP-28 — Config vs wire — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (commit c72c867, before `reconcile` was built). Code:
`tunnelscope/config/reconcile.py`, `tunnelscope reconcile <pcap> <config> [--conn] [--json]` (exit 3 on any
mismatch). Scoring: `analyze.py`. Results: `results/score_as_preregistered.json` (the code exactly as first built)
and `results/score.json` (after the disclosed label fix below). Tests: `tests/test_config_reconcile.py`.

## Headline
**Zero false alarms on 94 real config/capture pairs**, and every drift in a field the wire observes exactly
(IKE group, IKE cipher, PFS where a rekey shows it, PPK, ML-KEM) was caught: **161 of 161**. ESP cipher drift
was caught in 26 of 45 cases; the other 19 cannot be caught by packet geometry at all (the configured family is
one of the wire's candidates). The pre-registered H2 bar (100% of observable changes) therefore **failed**.
The experiment also exposed a labelling flaw: those 19 were reported as "match"; they are now "consistent"
(not ruled out), which is the honest word.

## Hypotheses
| | Bar | As pre-registered (first build) | After the label fix |
|---|---|---|---|
| H1 | zero mismatches on the controls | **PASS**: 94 pairs (52 initiator, 42 responder configs), 0 | PASS, 0 |
| H2 | 100% of observable drift detected | **FAIL**: 187 / 207 | **FAIL**: 187 / 206 |
| H3 | ESP key length change always "not comparable" | PASS: 47 / 47 | PASS: 47 / 47 |
| H4 | no UNKNOWN wire field ever "match" | PASS | PASS |

Drift by arm (after the fix; each arm is a copy of a control connection with one field changed):
| Arm | Field | Observable | Detected | Other outcomes |
|---|---|---|---|---|
| D1 | IKE key-exchange group | 49 | 49 | 3 not comparable (no IKE suite on the wire) |
| D2 | IKE encryption | 49 | 49 | 3 not comparable |
| D3 | ESP cipher family | 45 | **26** | **19 consistent** (inside the sieve's candidate set), 2 not comparable |
| D4 | PFS | 9 | 9 | 38 not comparable (no rekey in the capture) |
| D5 | PPK | 6 | 6 | — |
| D6 | ML-KEM additional key exchange | 48 | 48 | 4 not comparable |
| K | ESP key length only | 0 | — | 47 not comparable (as required) |

## What changed after the first run, and why (disclosed)
1. **Scoring error, mine:** `a-start` (EXP-13) is a capture where the cloud side initiates, so alice's config
   is the *responder* there. `reconcile` correctly answered "not comparable" for the ML-KEM offer (a responder
   config offering ML-KEM may still accept a classical proposal); `analyze.py` had wrongly assumed an alice file
   is always the initiator and counted it as a miss. The scorer now treats offer-type fields (ML-KEM offer,
   PPK) as observable only when the config is the capture's initiator (207 → 206 observable changes).
2. **Label fix in `reconcile`:** when the wire finding is only INFERRED — the ESP sieve's candidate set or the
   size-based PFS inference — agreement is now **"consistent"**, never "match". Detection is unchanged (the same
   187 mismatches); only the word for agreement changed. A fifth outcome, `consistent`, was therefore added to
   the four pre-registered ones.

## Why 19 ESP changes cannot be caught
The T0 sieve (EXP-01) is one-directional: packet lengths exclude cipher families whose IV/ICV/alignment cannot
produce them, but a CBC+HMAC tunnel's lengths are also possible under GCM, CCM, CTR and ChaCha20. So "the config
says GCM, the traffic is CBC" is not contradicted by the wire. Catching it needs T2 (the endpoint's SA state,
`crosstier`) or decryption keys; the tool says "consistent" and explains that.

## Limits
- Connections are matched by address, or by `--conn` when several share the capture's addresses (common in
  labs). A connection with several children is reported as not comparable per child (not yet supported).
- Only strongSwan and Libreswan configs so far (T-120 part 1).
