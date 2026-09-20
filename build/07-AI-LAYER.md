# 07 — The AI layer (T-082, 2026-09-20)

Three features, each with a stated limit. **Every model is trained by the project on its own data;
no pretrained or third-party AI model is used anywhere (decision 2026-09-20).**
Code: `tunnelscope/leakage/attacker.py`, `tunnelscope/anomaly/`, `tunnelscope/explain/`.
Tests: `tests/test_ai_layer.py` (18).

## Which model, and did we build it?

"Built by us" means trained by us on our own data. scikit-learn supplies the algorithms (Random
Forest, Isolation Forest), the way numpy supplies arithmetic; it ships no trained model.

| Feature | Model | Built by us? | Why this model |
|---|---|---|---|
| Traffic type + attacker view | Random Forest (scikit-learn), 200 trees | **Yes**: trained on our EXP-05 + EXP-15 lab traffic (1,375 windows, 152 sessions, 8 classes) | Already validated in EXP-05 as the attacker model; small, explainable, runs offline in ~0.6 s |
| Tunnel/transport mode (ESP) | Random Forest on ACK-size buckets (EXP-14) | **Yes**: trained on EXP-15 tunnel vs transport sessions | Ships only because it met a bar declared before the data; abstains outside TCP-over-AEAD |
| Anomaly detection | Rules + robust z-score + Isolation Forest (scikit-learn) | **Yes**: learns each organisation's own tunnels from their own history | No pretrained model exists for IPsec posture, and "normal" differs per network, so it must learn on site; unsupervised, so no labelled attacks are needed |
| Plain-English explanations | None: generated from the verdicts and a glossary we wrote | Yes, fully | Explaining a verdict needs no model; any language model would have to be someone else's, and could add facts |

## 1. Random Forest attacker (`attacker_exposure` finding)
- Features per 2-second window: sizes, timing and direction (identical to EXP-05, test-enforced).
- Output: an exposure score of 0–100, calculated as confidence × consistency across windows, plus
  high/medium/low. It **never** outputs the traffic type (DEC-021: on mixed traffic it is confidently
  wrong).
- Out-of-distribution gate: if most windows are farther from the training data than 99% of training
  windows are from each other, the result is "outside the training data" and gets no score. EXP-05's
  mixed-traffic sessions correctly fall here.
- Held-out check (train without one repetition, test on it): accuracy 0.99 / 1.0 / 1.0 / 1.0.
- Limit: it knows five lab traffic types. Most lab IKE captures carry only a few pings, so they read
  "insufficient" (fewer than 3 windows).
- No pickled model ships. The training windows ship as `tunnelscope/models/exp05_windows.npz` and the
  forest is trained on first use. Rebuild with `build/models/make_attacker_data.py`.

## 2. Anomaly detection (`tunnelscope watch`, `serve --history`)
- Tunnel identity is the endpoint pair, because SPIs change at every rekey.
- **Posture layer.** Compares the tunnel's usual crypto (the most common value it has shown) with
  today's:
  - A weaker DH group, cipher, integrity or IKE version, a lost post-quantum key exchange, or a rule
    that fails for the first time is flagged **high**.
  - A change of equal strength is **medium**.
  - An upgrade is informational.
- **Traffic layer** (from 5 observations): robust z-score on packet rate, mean size and the
  size/timing bits; |z| > 3.5 is flagged.
- **Model layer:**
  - Isolation Forest on the tunnel's own history, from 8 observations.
  - A fleet-peer Isolation Forest, once there are 6 or more tunnels.
- Below 2 observations a tunnel is reported as "learning", never "normal".
- Stored: posture profiles only (no packets, no payload, no keys) in `<dir>/history.jsonl`. It is off
  unless `--history` is given; `./start.sh` turns it on (`.tunnelscope-history/`).
- Verified on EXP-13 captures: three normal runs of `c-m`, then `c-w` flags three downgrades
  (cipher, integrity, DH group) plus two rules failing for the first time.

## 3. Plain-English explanations (`tunnelscope explain`, dashboard "Explained" tab)
- The template states every FAIL with what the rule means, why it matters and what to do (a glossary
  of all 9 rules, test-enforced), plus everything the capture could not show.
- No language model. An optional LLM rewrite (Claude or a local Ollama model) was built and then
  removed the same day, at the user's decision: every model in TunnelScope must be trained by us.
  Training our own language model is not realistic (it needs vast text and compute) and would
  risk inventing facts. `tests/test_ai_layer.py::test_no_outside_model_is_used` fails if an LLM
  client, a model download or a network call appears in the package.

## 4. Update T-083 (2026-09-20): the traffic TYPE is now shown (DEC-027)
The classifier's prediction is an INFERRED `traffic_type` finding with its probability and the next
alternatives, shown only when windows agree (≥ 70%) and the probability is ≥ 60%; otherwise
"uncertain". EXP-15: macro-F1 0.995 (tunnel), 0.958 (TFC padding), 0.986 across ciphers, calibration
error 0.049. Pre-registered failure kept: mixed traffic is abstained on in only 29% of sessions; the
dominant type is named in 20 of 28 and video+interactive reads as web 8 of 8, which every such
answer now states.

## 5. Update EXP-16 (2026-09-20): generalisation, and a second model
- The classifier now trains on **1,964 windows / 216 sessions**: synthetic shapes, **real lab
  applications**, and **Libreswan**-carried traffic. Held-out repetition macro-F1 **0.986**.
- **Cross-implementation:** 1.000 on Libreswan (trained on strongSwan only).
- **Synthetic-only → real applications: 0.461.** Stated in the product next to every prediction.
- **Mixed-traffic detector** (second stage, Random Forest on the first model's probability pattern):
  92.9% of mixed sessions caught, 8.3% of single sessions wrongly flagged, video+interactive 100%.
  Ships only because it met the bar pre-registered in EXP-16.
