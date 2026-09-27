# EXP-27 — RFC 8784 PPK: negotiation is visible, use is not — RESULT (2026-09-27)

Pre-registration: `PREREG.md` (commit 2970224, before any capture). Captures and ground truth:
`testbed/captures/exp27/` (own hashed `manifest.csv`). Runner: `testbed/scripts/run_exp27_ppk.py`
(configs written to `testbed/configs/exp27/`). Scoring: `analyze.py` → `results/score.json`.
Finding: `pq_ppk` (`extract_ppk` in `tunnelscope/evidence/extract.py`), tests `tests/test_ppk.py`.

## Headline
TunnelScope now reads RFC 8784 PPK negotiation from the plaintext `USE_PPK` notify (IANA 16435) and
**never claims the PPK was used**. The fallback arm K5 proves why that matters: both peers announced
`USE_PPK`, the tunnel came up, and strongSwan's own log says the PPK was **not** used
(`no PPK available, using NO_PPK_AUTH notify`). A tool that equated "negotiated" with "protected" would
have been wrong there. All pre-registered hypotheses passed.

## Arms and ground truth (strongSwan 6.1.0 logs, both peers)
| Arm | USE_PPK request / response | Tunnel | PPK used (log) | TunnelScope `pq_ppk` |
|---|---|---|---|---|
| K0 no PPK | no / no | up | no | `not-offered` |
| K1 optional, same PPK | yes / yes | up | **yes** ("using PPK for PPK_ID 'ppk27'") | `negotiated` |
| K2 required, same PPK | yes / yes | up | **yes** | `negotiated` |
| K3 responder without PPK | yes / no | up | no | `offered-not-negotiated` |
| K4 responder PPK under another id | yes / yes | **failed** | no | `negotiated` (+ `negotiation_outcome` = auth failure) |
| K5 decoy (deviation, below) | yes / yes | up | **no** ("using NO_PPK_AUTH") | `negotiated` |

## Hypotheses
| | Bar | Result |
|---|---|---|
| H1 | K0 not-offered, K1/K2 negotiated, K3 offered-not-negotiated | PASS (4/4) |
| H2 | fallback arm: `negotiated` without any claim of use | PASS (K5; no arm claims use) |
| H3 | no wrong IKE suite field K0–K5 | PASS (0 wrong) |
| H4 | findings differential: only the new `pq_ppk` finding appears | PASS (683 captures: 636 changes, all the new `pq_ppk` finding appearing where there was none; 0 existing findings changed) |

## Deviations, stated
- **K4 did not behave as predicted.** The RFC allows a responder that lacks the initiator's PPK to fall
  back to `NO_PPK_AUTH`; strongSwan instead rejects a PPK_ID it does not expect when the connection names a
  different one (`received PPK_ID 'ppk27', but require 'other27'` → `AUTHENTICATION_FAILED`). Scored
  against what happened, as the pre-registration says: still `negotiated` on the wire, no PPK used, and
  TunnelScope reports the failure through `negotiation_outcome`.
- **K5 was added after K4** to produce the silent fallback K4 was meant to show. The responder's matching
  connection has no PPK, but a decoy connection of its own does, so it still answers `USE_PPK`. It took
  three runs because of my setup errors, each caught by the ground truth: run 1 and 2 left the
  initiator's PPK (`ppk27`) in the responder's secrets, and strongSwan uses any PPK it holds for the
  received id even when the selected connection names none, so the PPK *was* used. Run 3 (decoy holds only
  `other27`) produced the fallback; only run 3's capture and ground truth are kept.

## Other observations
- strongSwan's responder answers `USE_PPK` in IKE_SA_INIT when **any** connection it has loaded carries a
  PPK, before it knows which connection applies (identities arrive in IKE_AUTH). So `negotiated` is really
  "both implementations support PPK and have one configured somewhere", which is exactly why it cannot
  mean "this tunnel uses a PPK".
- Nothing credits PPK as post-quantum protection: the DST rules, the threat matrix and the risk score are
  unchanged, as pre-registered. A tunnel whose PPK use is confirmed by T2 telemetry would be the way to
  credit it (roadmap T-121, config/telemetry reconciliation).

## Clean-up
The three lab containers were stopped after capture; the lab's standing configs were reloaded before that.
