# EXP-16 — Real applications, cross-implementation transfer, mixed-traffic detector — PRE-REGISTRATION (2026-09-20, before capture)

Answers the four limits named in `research/14-PS-VALIDATION.md` and the EXP-15 result: the classifier
has only ever seen one traffic generator, one IPsec stack, four repetitions, and it fails on mixed
traffic.

## What is recorded (decided before capturing)
Real client and server software, but **only inside the lab**: a real browser (headless Chromium), a
real mail client and server (swaks → Postfix/mailpit), a real SSH session and SFTP transfer
(OpenSSH), real RTP media (ffmpeg), real XMPP messaging, real video playback over HTTP, and real
ping. **No third-party service, no account, no credential, no personal data.** Capture stays at the
keyless router, headers only (`-s 96`); ESP payloads are encrypted regardless.

## Parts
- **A — real applications** through the strongSwan tunnel (`t-tun`, AES-GCM-256), 8 classes matched to
  the synthetic ones: web (browser), video (browser playing an MP4 over HTTP), bulk (SFTP), interactive
  (SSH), email (SMTP submission with attachments), messaging (XMPP), voip (RTP via ffmpeg), icmp (ping).
- **B — cross-implementation**: the same synthetic generator classes through **Libreswan 5.4**
  (`sih26-lsw-a/b`, AES-GCM-256), never used for training.
- **C — more repetitions** of the synthetic set (reps 5–6) on strongSwan.
- **D — mixed-traffic detector**: a second-stage classifier (single vs mixed) over the per-window
  probability pattern of the 8-class model, trained on the existing mux sessions.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P16-1 | The synthetic-trained classifier keeps **macro-F1 ≥ 0.60** on real application traffic (degradation expected: shape models are not applications) | < 0.60 |
| P16-2 | A classifier trained on the real sessions reaches **macro-F1 ≥ 0.85** leave-one-repetition-out | < 0.85 |
| P16-3 | Cross-implementation: the strongSwan-trained classifier keeps **macro-F1 ≥ 0.90** on Libreswan-carried synthetic traffic (same protocols, same cipher; only the IPsec stack differs) | < 0.90 |
| P16-4 | The EXP-14 ACK-size mode model on Libreswan TCP sessions: **accuracy ≥ 0.95 and zero tunnel sessions called transport** | either fails |
| P16-5 | The mixed detector flags **≥ 80%** of mixed sessions with **≤ 10%** of single-class sessions wrongly flagged (leave-one-repetition-out), and catches video+interactive specifically | either fails |
| P16-6 | Adding repetitions 5–6 moves the held-out macro-F1 by **≤ 0.02** (the existing number was not a small-sample artefact) | moves more |

Whatever fails is reported as failed, as P15-4 was. Anything that ships states its measured limit.
