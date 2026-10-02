# EXP-43 — Lab D, the final untouched test — RESULT (2026-10-02)

Pre-registration `31c3bc5` (after EXP-42's selection, before any lab-D capture); scorer `1206770`; lab-D data `45d1d48`
(32 captures, all committed before scoring); artifact check `304ae58`, run once. Scores in `results/summary.json`,
`results/sessions.csv`, `results/artifact_check.json`.

## 1. Scores (32 captures, all with at least 3 windows)

| | Shipped model (S) | K4 |
|---|---|---|
| Ungated macro-F1 | 0.417 | **0.833** |
| ChaCha20-Poly1305 suite | 0.542 | 0.833 |
| AES-256-CBC + HMAC-SHA-384 suite | 0.208 | 0.833 |
| Gated: answered / correct | 9 / 7 (78%) | 11 / **11** (100%) |
| Gated stages (answered, abstained, out of distribution) | 9, 19, 4 | 11, 17, 4 |
| Per class (K4) | | bulk 1.0, email 1.0, icmp 1.0, **interactive 0.0**, messaging 1.0, video 1.0, voip 0.67, web 1.0 |
| Per class (S) | bulk 0.0, email 0.67, icmp 1.0, interactive 0.0, messaging 0.67, video 0.0, voip 0.67, web 0.33 | |

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P43-1 | The shipped model does not generalise to lab D (< 0.60) | 0.417 | held |
| P43-2 | K4 beats it by >= 0.10 | **+0.417** | held |
| P43-3 | K4's gated answers >= 90% right and at least as many correct as S | 11/11, 11 vs 7 | held |
| P43-4 | K4 >= S on each suite | 0.833 vs 0.542; 0.833 vs 0.208 | held |

**Ship rule: met.** The shipped artifact (`tunnelscope/models/traffic_windows_v2.npz`, 30 windows per session, 3 significant
digits, 5,004,853 bytes, trains in about 2 s) was checked once on lab D through the product path: macro-F1 0.833 (equal to
K4), 11 of 11 gated answers right; the product's v2 features equal the experiment's on all 64 lab-C and lab-D sessions.

## 2. Reading it

- The gain on lab D (+0.42) is much larger than K4's average gain over held-out families in EXP-42 (+0.04). Lab D is a lab of
  real tools on a tunnel, the kind of family where K4 gained most in EXP-42 (lab C +0.17, lab A +0.15); the families where it
  did not help (USBVPN's scripted web visits, WireGuard's home traffic) are a different kind. So the honest summary is: **better on
  lab-style tunnel traffic it has never seen, roughly unchanged on very different real-world sources.**
- Interactive sessions are still missed (0 of 4: mosh's UDP keystrokes look like none of the training families' interactive
  traffic), and voip is 0.67. The model abstained on 21 of 32 sessions and was right every time it answered.

## 3. Limits, stated plainly

1. **Small:** 4 captures per class; one wrong capture moves a class's F1 by up to 0.33.
2. **Not fully independent:** lab D was built by us, on the same strongSwan gateways and topology as lab C (which is in K4's
   training). Its tools, ESP suites and network conditions are new; its vantage and gateways are not.
3. The tools needed fixes during the smoke test before the PREREG (lighttpd index, OpenSMTPD recipient, IRC newlines, mosh TERM,
   locale, terminal size and quoting); all are in the committed generator, none touched a scored capture.
4. The reduced artifact (cap 30, 3 digits) was chosen from file size alone and measured on lab D once, as the PREREG allows.

## 4. What changed (DEC-054)

`tunnelscope/leakage/attacker.py`: `window_features_v2`, `balanced_weights`, training from `traffic_windows_v2.npz` with the
weights; abstain thresholds unchanged. `build/models/make_traffic_data_v2.py` rebuilds the file. Tests: `tests/test_attacker_v2.py`
(v2 equals the frozen experiment code, the file stays plain arrays under 5 MB, training uses the weights, lab-D accuracy is kept);
6 mutations, all caught after one test was added. README and the classifier's reference numbers updated.
