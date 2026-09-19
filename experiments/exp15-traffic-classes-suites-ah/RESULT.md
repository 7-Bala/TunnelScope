# EXP-15 — Eight traffic classes, IKE/DH suites, AH — RESULT (2026-09-20)

Pre-registration: `PREREG.md` (commit d18e663, before capture). Numbers: `results/exp15_results.json`.

## Part A — traffic classifier (152 sessions, 1,375 windows, leave-one-repetition-out)
| # | Prediction | Result |
|---|---|---|
| P15-1 | tunnel macro-F1 ≥ 0.90 | **Held: 0.995** (per class 0.97–1.00; e-mail 0.971, messaging 0.986, ICMP 1.00) |
| P15-2 | e-mail / messaging / ICMP F1 ≥ 0.80 | **Held** |
| P15-3 | TFC-padded macro-F1 ≥ 0.80 | **Held: 0.958** (padding hides sizes, timing still gives it away; EXP-05 repeated at 8 classes) |
| P15-4 | mixed sessions abstained in ≥ 80% | **Failed: 29%.** Most mixed sessions are named after their dominant type (20 of 28); **video+interactive is read as web in 8 of 8**, confidently and consistently, so no abstain rule based on confidence catches it |
| P15-5 | calibration error ≤ 0.10 | **Held: 0.049** (session level) |
| P15-6 | GCM-trained model on CBC traffic ≥ 0.80 | **Held: 0.986** |
Also: transport-mode sessions 0.996; single-class session accuracy 100% on held-out repetitions.

**Consequence for the product (DEC-027):** the prediction is shown with its probability, the next
alternatives, the sentence "if several kinds of traffic share this tunnel, this names the dominant
one", and, for "web", the measured video+interactive confusion. The failed prediction is kept as a
failure, not re-tuned away.

**Scope:** classes are traffic *shapes* from our generator (`tgen.py`), not real applications;
"WhatsApp-like" is a shape model. One implementation (strongSwan 6.1), lab network, no WAN jitter.

## Part B — IKE/DH suites (9 arms)
IKE encryption, integrity, DH group and ML-KEM were read exactly as the endpoints' swanctl reports on
all 9 arms (`build/validate_e2e.py` check_exp15): MODP-1024/1536/3072/4096, ECP-256/384, Curve25519,
3DES/SHA-1/MODP-1024, Curve25519+ML-KEM-768. The weak arms fail the rules that name them. Found and
fixed: the ESP cipher sieve lacked 3DES and SHA-384/512 families, so a 3DES tunnel read "CBC
excluded" without its true family.

## Part C — AH (5 arms)
P15-8 held: Docker Desktop's kernel negotiates AH. P15-9 held: mode read exactly from AH's next
header (5/5). P15-10 held: ICV length → integrity (12 B → the 96-bit family, 16/24/32 B → SHA-2
256/384/512; a 12-byte ICV cannot tell MD5 from SHA-1, so that rule says UNKNOWN, never FAIL).
P15-11 held: every AH SA fails RFC4301-CONFIDENTIALITY (authenticated, not encrypted).
