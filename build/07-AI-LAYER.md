# 07 — The AI layer (T-082, 2026-09-20)

Three features, each using the kind of AI that fits its job, each with a stated limit.
Code: `tunnelscope/leakage/attacker.py`, `tunnelscope/anomaly/`, `tunnelscope/explain/`.
Tests: `tests/test_ai_layer.py` (18).

## Which model, and did we build it?

| Feature | Model | Built by us? | Why this model |
|---|---|---|---|
| Attacker view | Random Forest (scikit-learn), 200 trees | **Yes**: trained on our EXP-05 lab traffic (380 windows, 40 sessions) | Already validated in EXP-05 as the attacker model; small, explainable, runs offline in ~0.6 s |
| Anomaly detection | Rules + robust z-score + Isolation Forest (scikit-learn) | **Yes**: learns each organisation's own tunnels from their own history | No pretrained model exists for IPsec posture, and "normal" differs per network, so it must learn on site; unsupervised, so no labelled attacks are needed |
| Plain-English explanations | Template from the verdicts, optionally rewritten by an LLM: **Claude Opus 5** (online) or a **local open-weight model via Ollama** (air-gapped) | Template: yes. LLM: **no, we use an existing one** | Training an LLM is neither possible nor needed; the LLM only rewords text we generate, and a fact check rejects any new rule, algorithm or number |

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
- The LLM rewrite is off by default (I9, offline). `--llm ollama` needs `ollama serve` and a pulled
  model (`TUNNELSCOPE_OLLAMA_MODEL`, default `llama3.2`). `--llm claude` needs `pip install
  tunnelscope[llm]` and Anthropic credentials, and sends only the explanation text (never the
  capture) to the API.
- **Fact check:** every rule ID, algorithm name and number in the rewrite must already appear in the
  template text, and "compliant" is banned. On failure, the template is shown with the reason.
- Not verified live here: no Anthropic credentials and no Ollama model on this machine. Both paths
  are tested with stand-in providers, and the unavailable case falls back correctly.
