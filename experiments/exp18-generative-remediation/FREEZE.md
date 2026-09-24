# EXP-18 — prompt freeze (2026-09-24, before any test-set or safety run)

frozen prompt: P0

Selection rule (PREREG.md): the variant with the most dev items confirmed fixed; ties go to the earlier variant.

| Variant | Dev result (A1, from results/raw.jsonl) |
|---|---|
| P0 (committed SYSTEM_PROMPT + leave-one-out few-shot) | 0 confirmed of 3 included; stopped at: D5 V4, D6 V4, D7 V4 |
| P1 (no examples; accepted values that satisfy the rule listed in the prompt) | 0 confirmed of 3 included; stopped at: D5 V5, D6 V5, D7 V5 |
| P2 (examples and the accepted values) | 0 confirmed of 3 included; stopped at: D5 V5, D6 V5, D7 V5 |

All three confirmed 0 of 3 included dev items, so the rule selects **P0**. Recorded, not acted on:
P1 and P2 got further (to V5): with the value list in the prompt the model drafted the correct edit
(`append ke1_mlkem768`, the hand-written fix) but restated the resulting line wrongly (a space or a
missing hyphen before `ke1_mlkem768`), which V5 refuses by design. Dev items D1-D4 were excluded for
every variant: D1, D2 `baseline_no_sa` (IKEv1 did not establish in the lab); D3, D4 `baseline_UNKNOWN`
(the AH integrity algorithm is not visible on a handshake-only capture).

Frozen identifiers:
- SYSTEM_PROMPT sha256: 3f70f2a5fbb10c1f371a56df82d77970fec1e9ec7fcc57003d317a3c01fd3691
- FEW_SHOT sha256: 54bd0904e65e79b37d193fbfd8e74985bfd576b605e492e433f3d8e75307deec
- tunnelscope/remediate/generate.py sha256: 06e0048a271e7fec9d966f124f27c6c56f8244dc3fb63d79dd7e8a03913a1f03
- strongswan_keywords.json sha256: 1443149ef1ecf8c8281556ea9418331950346e14b940612898e6e32ee98a9c26
- model: openbmb/MiniCPM5-2B-MLX @ 8a9ad7539ac86281d0ac2b017ba04a5de53fe9a3
