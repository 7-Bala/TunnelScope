# 08 — Problem-statement gap closure: plan, failure points, tests (T-083, 2026-09-20)

Source of the gaps: `research/14-PS-VALIDATION.md`. Rule kept from day one: nothing may claim more
than the evidence shows. Every new output is either OBSERVED, INFERRED with its basis, or says
UNKNOWN. Where the PS asks for something the wire cannot show, we build the closest honest thing
and state the limit on screen.

## Decisions this plan needs (recorded as DEC-024/025 in research/registers/DECISIONS.md)
- **DEC-024 supersedes DEC-021:** the traffic type inside ESP IS shown, but only with a calibrated
  confidence, only for in-distribution traffic, and only above an abstain threshold; otherwise the
  answer is "uncertain" (mixed or unfamiliar traffic). The failure DEC-021 was about (confidently
  wrong on mixtures) becomes a tested abstain case.
- **DEC-025 amends DEC-007:** one overall risk score is shown, derived from the threat matrix, always
  with its breakdown (threats, baselines, coverage) underneath. It is a risk score, not a compliance
  score, and it shows how much of the assessment was possible (coverage).

## Workstreams

| # | PS line | Build | Needs Docker |
|---|---|---|---|
| W1 | c) Predict type of traffic; AI classification engine | 8-class classifier (voip, web, file transfer, interactive/SSH, video, e-mail, messaging, ICMP), calibrated probabilities, abstain rule, out-of-distribution gate | yes (new captures) |
| W2 | e) AI confidence score | per-finding confidence shown everywhere; the classifier's calibrated confidence; an assessment-coverage figure | no |
| W3 | e) Threat matrix | threat catalogue mapped from findings/verdicts, likelihood × impact grid | no |
| W4 | e) Risk score, comprehensive security score | overall 0–100 risk from the matrix, with breakdown and coverage | no |
| W5 | d) Replay protection | ESP/AH sequence-number analysis per SPI: duplicates, resets, out-of-order, wrap risk; rule citing RFC 4303 §3.3.3 | no (synthetic replay capture) |
| W6 | c) Tunnel/Transport | EXP-14: size-floor proof of transport mode; AH next-header gives mode directly | partly |
| W7 | Description: live network streams | `tunnelscope live`: interface ring buffer (dumpcap) or follow a sensor's rotating files; dashboard Live view | yes (for the E2E) |
| W8 | b) AH packets | AH testbed arm; AH parsing (SPI, seq, ICV length → integrity algorithm, next header → mode); "AH gives no confidentiality" rule (RFC 4301 §3.2) | yes |
| W9 | a) Different DH groups | testbed arms with MODP-1536/2048/3072/4096, ECP-256/384, Curve25519, and IKE-suite variation (fixes the demo trap) | yes |
| W10 | c) Encryption algorithm | label "handshake (IKE SA) cipher" vs "data (ESP) cipher candidates" in reports and dashboard | no |
| W11 | a) Traffic types | tgen: add e-mail (SMTP-shaped), messaging (WhatsApp-shaped), ICMP (ping) | yes |
| W12 | e) Reports | executive + technical reports gain risk score, threat matrix, traffic analysis, confidence, replay, mode | no |
| W13 | Deliverables: dataset, docs, demo | manifest + datasheet for new captures; DECISIONS, README, RESULTS, 07-AI-LAYER; demo script | no |

## Failure points and how each is tested

### W1 traffic classifier
| Failure point | Test |
|---|---|
| Train/test leakage (windows of one session in both) | leave-one-repetition-out only (DEC-009), asserted in the training script |
| Accuracy only on memorised sessions | held-out repetition macro-F1 reported per class; unit test: each held-out rep > 0.8 macro-F1 |
| Confidently wrong on mixtures (the DEC-021 case) | mux sessions must abstain or be flagged low-confidence in ≥ 90% of windows-sessions; test asserts |
| Overconfident probabilities | expected calibration error (ECE) on held-out; isotonic calibration if ECE > 0.05 |
| Unfamiliar traffic gets a label | OOD gate (nearest-neighbour distance); test on IKE-only / ping-only lab captures → "uncertain"/insufficient |
| Class set not matching PS | classes named after PS terms; WhatsApp is "messaging (WhatsApp-like)", stated as a shape model, not the app |
| Feature drift vs extractor | features computed by one function used for training and live (test-enforced) |
| TFC padding hides sizes | padded arm in training; accuracy reported separately for padded traffic |
| Model file safety | no pickle: training arrays ship as .npz; model trained on first use (< 2 s) |

### W2 confidence
| Status shown as 100% when inferred | confidence = 1.0 only for OBSERVED; INFERRED carries its basis; UNKNOWN has none; test |
| "AI confidence" used for non-AI outputs | label reads "confidence"; the classifier's is the only "model confidence" |

### W3/W4 threat matrix and risk score
| A threat marked present without evidence | every threat lists the rule IDs/findings that raised it; test: removing the evidence removes the threat |
| Unknown treated as safe | threats whose evidence is UNKNOWN are "not assessable", shown, and lower the coverage figure; never counted as mitigated |
| Score hides the reason | score always rendered with its top contributing threats; test |
| Score unstable/arbitrary | formula documented; monotonic test (adding a FAIL never lowers risk); bounds 0–100 |

### W5 replay
| Capture-duplicated frames (span port, two taps) flagged as replay | duplicates with identical bytes within 1 ms are reported as "capture duplicate", not replay |
| Rekey (new SPI) mistaken for reset | analysis is per SPI |
| Enforcement claimed | finding says what the wire shows; receiver-side enforcement (V-207212) stays NOT_OBSERVABLE |
| No real replay capture | synthetic capture made by re-injecting a captured ESP frame later (marked synthetic in the dataset) + a clean control |

### W6 mode
| False "transport" on a tunnel capture | floor computed as the minimum over every still-possible cipher family; validated on all captures with `gt_mode`: zero false transport |
| TFC dummy packets (next header 59) are small in either mode | stated in the finding; not claimed when TFC padding is detected |
| Never fires on real traffic | EXP-14 reports, per traffic class, how often transport is provable (coverage), pre-registered |
| IPv6 inner header | floor uses the smaller (IPv4) inner header, so it stays safe for v6 |

### W7 live
| Needs root / capture permission | clear error with the fix (ChmodBPF on macOS, `setcap` on Linux); `--follow DIR` mode needs none |
| Half-written file analysed | only files closed by the ring buffer are read (the newest is skipped) |
| Unbounded disk | ring buffer (`-b files:N`), analysed files deleted unless `--keep` |
| Dashboard stale | Live view polls `/api/live` and shows the age of the last window |
| E2E | Docker lab: router writes rotating pcaps, `tunnelscope live --follow` picks them up, dashboard Live view updates; a mid-run downgrade is flagged |

### W8 AH, W9 DH, W11 traffic
| Kernel in Docker Desktop lacks AH | test first; if it fails, recorded honestly and AH parsing is tested on a synthetic AH capture |
| Arms don't negotiate what the config says | ground truth from `swanctl --list-sas` per capture (T2), compared by the E2E validator |

## End-to-end test plan (run after the build, all must pass)
**Code:** pytest (all), `build/validate_e2e.py` (ground truth incl. new arms, mode, traffic class),
`dataset/validate.py`, `build/findings_diff.py` (only allowed changes), every CLI command incl.
`live --follow`, API incl. bad inputs, air-gap test (`build/offline/airgap_test.sh`), CI green.

**Browser:** intro → upload set (tunnel, transport, AH, weak DH, replay, traffic of each class) →
per tunnel: Explained, Traffic & exposure (predicted type + confidence or "uncertain"), Threat matrix,
Changes, Verdicts, Evidence (handshake vs data cipher labels) → fleet: risk score KPI, threat matrix
card, AI insights → Live view during a Docker run with a mid-run downgrade → reports → 375 px layout,
engine-offline banner, 0 console errors.
