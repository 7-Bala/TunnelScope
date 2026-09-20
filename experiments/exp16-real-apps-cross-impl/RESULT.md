# EXP-16 — Real applications, cross-implementation, mixed detector — RESULT (2026-09-20)

Pre-registration: `PREREG.md` (before capture). Numbers: `results/exp16_results.json`,
`results/exp16_mixed.json`. Captures: `testbed/captures/exp16/` (64 sessions: 32 real-application,
32 Libreswan) plus 56 extra synthetic repetitions in `testbed/captures/exp15/traffic/`.

## The headline: synthetic traffic shapes do NOT transfer to real applications
| # | Prediction | Result |
|---|---|---|
| P16-1 | synthetic-trained classifier keeps macro-F1 ≥ 0.60 on real applications | **FAILED: 0.461** (session accuracy 53%). Per class: e-mail 0.98, VoIP 0.96, ping 0.71, web 0.45, video 0.22, interactive 0.19, messaging 0.18, **file transfer 0.00** |
| P16-2 | a classifier trained on the real sessions reaches ≥ 0.85 leave-one-repetition-out | **Held: 0.995** |
| P16-3 | strongSwan-trained model keeps ≥ 0.90 on **Libreswan**-carried traffic | **Held: 1.000** (session accuracy 100%) |
| P16-6 | adding repetitions 5–6 moves the held-out score by ≤ 0.02 | **Held: 0.000** (0.983 both ways) |

**What this means.** The lab number was never the model's limit — it was the data's. Change the
*implementation* (Libreswan) and nothing moves. Add two more repetitions and nothing moves. Swap the
*traffic source* from our generator to real Chromium / OpenSSH / Postfix / XMPP / ffmpeg sessions and
more than half the accuracy disappears, because a real SSH session, a real chat client and a real
SFTP transfer do not have the shapes our generator imagined. Train on the real sessions and it comes
straight back (0.995). This is the honest generalisation story, and it is the argument for training
on captures from the network a deployment actually runs on.

**What ships:** one model trained on everything (1,964 windows, 216 sessions: synthetic + real +
Libreswan), leave-one-repetition-out macro-F1 **0.986**. Every prediction states that traffic unlike
the training set can be misread, and names the 0.46 figure.

## Part D — mixed-traffic detector (fixes EXP-15's failed P15-4)
A second stage reads the *shape* of the first model's per-window probabilities (spread, agreement,
second-place mass, divergence between windows) and decides single vs mixed. Leave-one-repetition-out:
| # | Prediction | Result |
|---|---|---|
| P16-5 | catches ≥ 80% of mixed sessions, wrongly flags ≤ 10% of single ones, catches video+interactive | **Held: 92.9% caught, 8.3% wrongly flagged, video+interactive 100%** |
So the case that defeated confidence in EXP-15 (video+interactive read as "web browsing", 8 of 8) is
now caught. About 7% of mixed sessions still slip through; when the label that slips through is a
measured confusion, the finding says so.

## Sanity check of the shipped model (not a held-out number)
Run over all 64 EXP-16 sessions, which are part of its training data: **62 answered correctly, 0
answered wrongly, 2 abstained** — both real Chromium sessions, flagged as "mixed traffic". A page
load does fetch many assets at once, so the flag is arguable, but by our labels it is a false flag
(the detector's measured rate is 8.3%). The honest accuracy figures are the leave-one-repetition-out
ones above, not this.

## Scope and limits
- "Real applications" means real software against **lab servers**: no third-party service, account,
  credential or personal data (decided before capturing). Lab LAN, no WAN loss or jitter.
- Two IPsec implementations (strongSwan 6.1, Libreswan 5.4), one kernel, IPv4, AES-GCM-256.
- Real e-mail is SMTP submission with attachments (no IMAP sync); messaging is XMPP (not WhatsApp's
  own protocol, which is closed); VoIP is RTP/Opus without a signalling exchange.
- The first capture attempt produced no usable file-transfer or video sessions (a browser flag
  fast-forwarded playback; a 50 MB SFTP finished in under 2 s on a LAN). Fixed by playing in real
  time and rate-limiting SFTP to 12 Mbit/s, then re-captured — the numbers above are from the fix.
