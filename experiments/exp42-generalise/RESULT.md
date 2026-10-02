# EXP-42 — Make the traffic classifier generalise to generators it has never seen — RESULT (2026-10-02)

Pre-registration `bad8196` (before any leave-one-family-out number); corpus, features and scorer `b45016c`; the scorer was
fixed once at `b623468` (section 3). Scores in `results/summary.json`. 2,262 sessions scored across eight families
(sessions with fewer than three 2-second windows are not scored: lab-tgen 49, usbvpn 124, wireguard 809, lab-a 22, lab-b 108).

## 1. Leave-one-family-out, session-level macro-F1

| Candidate | Mean | Worst | Grouped by session | lab-tgen | lab-real-apps | vnat | usbvpn | wireguard | lab-a | lab-b | lab-c |
|---|---|---|---|---|---|---|---|---|---|---|---|
| K0 (shipped recipe) | 0.412 | 0.084 | 0.983 | 0.635 | 0.583 | 0.440 | 0.084 | 0.268 | 0.297 | 0.500 | 0.487 |
| K1 balanced | 0.426 | 0.045 | 0.976 | 0.629 | 0.726 | 0.462 | 0.045 | 0.301 | 0.345 | 0.500 | 0.402 |
| K2 + augmentation | 0.403 | 0.028 | 0.976 | 0.602 | 0.633 | 0.450 | 0.028 | 0.210 | 0.327 | 0.500 | 0.475 |
| K3 v2 features | 0.452 | 0.025 | 0.978 | 0.658 | 0.718 | 0.420 | 0.025 | 0.284 | 0.417 | 0.500 | 0.596 |
| **K4 v2 + both** | **0.455** | 0.043 | 0.977 | 0.587 | 0.664 | 0.536 | 0.043 | 0.203 | 0.451 | 0.500 | 0.658 |
| K5 ExtraTrees | 0.449 | 0.101 | 0.988 | 0.535 | 0.597 | 0.450 | 0.101 | 0.272 | 0.453 | 0.500 | 0.683 |
| K6 HistGradientBoosting | 0.437 | 0.057 | 0.984 | 0.616 | 0.670 | 0.621 | 0.057 | 0.254 | 0.312 | 0.500 | 0.469 |

**Chosen by the pre-registered rule: K4** (highest mean among candidates whose worst family is within 0.05 of K0's and whose
grouped score is within 0.02; K2 and K3 were not eligible because their worst family, USBVPN, fell below 0.034).

## 2. Predictions

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P42-1 | Today's recipe generalises poorly (< 0.60) | 0.412 | held |
| P42-2 | Balancing adds >= 0.03 | +0.014 | falsified |
| P42-3 | Augmentation adds >= 0.03 | -0.023 | falsified |
| P42-4 | v2 features add >= 0.03 | +0.026 | falsified (narrowly) |
| P42-5 | The chosen candidate beats K0 by >= 0.10 | K4, **+0.043** | **falsified** |
| P42-6 | No harm on known generators (within 0.02) | 0.977 vs 0.983 | held |

## 3. What it shows

- **Generalising to a generator family it has never seen is hard, and these levers move it only a little.** The best mean is
  0.455 against 0.412. On new sessions from generators it has seen, every candidate scores 0.976-0.988: the gap is not
  noise in the model, it is that each family's generators put each class into a different shape.
- **Where it helped and where it hurt (K4 vs K0):** lab C 0.49 -> 0.66 (icmp 0 -> 1.0, web 0.5 -> 1.0, interactive 0 -> 0.67),
  lab A 0.30 -> 0.45 (web 0.93, video 0.68), VNAT 0.44 -> 0.54; but lab-tgen 0.64 -> 0.59 and WireGuard 0.27 -> 0.20.
- **USBVPN stays near zero for every candidate (0.03-0.10).** 894 of its 994 scored sessions are scripted website visits of
  6-10 s through L2TP-over-IPsec; held out, nothing in the other families looks like them. This is a property of that data set
  (one source makes a whole class), not something a model setting fixes.
- The top three candidates sit within 0.01 of each other while families differ by 0.6: the choice between them is weak
  evidence. That is why the decision rests on lab D (EXP-43), not on this table.

## 4. Deviations

1. The scorer crashed at K2: one session has no packets, and the augmentation step read its first timestamp. Such a session
   has no windows and is never scored, so it was skipped; K0 and K1 (already scored by the same code) were reused from
   `results/partial.json`. Committed at `b623468` before K2 was scored.
2. None other. Labs A and B were read at the pinned commits (`c0cf256`, `ef0ffe9`) and deleted afterwards.

## 5. Next

K4, trained on all eight families, goes to lab D (EXP-43, pre-registered next, before any lab-D capture). It ships only if it
beats the shipped model there by the margin EXP-43 fixes. Lab D's tools were fixed in this PREREG.
