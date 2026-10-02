# EXP-45 — Raise accuracy by adding the one thing that worked: many more kinds of real traffic — PRE-REGISTRATION (2026-10-02, before any lab-E or lab-F capture)

## Why
EXP-37 to EXP-44 found one lever that moved accuracy on traffic the model has not seen: **more different generators per class**
(adding lab C to the training families lifted lab D from 0.42 to 0.83; model settings, balancing and augmentation each moved
the leave-one-family-out mean by less than 0.03). The shipped model (K4, DEC-054) is still weak on **interactive** sessions
(0/4 on lab D), on USBVPN-style scripted web visits, and its **mixed-traffic check** wrongly flags most lab-D singles (EXP-44
recalibration fell one session short because only 28 mixed training sessions exist). This experiment adds, in bulk, what those
three failures lack.

## Lab E, a new training family (fixed here)
Hosts behind the strongSwan 6.1.0 gateways as in labs C and D (gateways never send ICMP redirects); capture at the keyless router,
ESP headers only; per-packet tables committed, pcaps hashed. Eight classes, several tool variants each, **none used in labs A to D
or in the shipped training sets**; each variant 2 repetitions x 45 s. Two ESP suites alternate (AES-128-GCM; AES-128-CBC with
HMAC-SHA-256) and the router adds `netem delay 8ms 3ms loss 0.1%`:

| Class | Variants |
|---|---|
| bulk | `rsync` over ssh; `lftp` from `vsftpd`; `curl` of a 400 MB file from `nginx` |
| web | `curl --parallel` page-plus-assets fetches with think time from `nginx`; `siege` (delay 1-4 s); `lynx -dump` page walks |
| interactive | `ssh` + `expect` typing at 3 paces (40-120, 150-350, 400-900 ms per key); `ssh` running `top` (server-pushed refresh every 1, 3 s); `ssh` + `vim` editing a file; `tmux` over ssh |
| video | `ffmpeg` SRT, 300 kbit/s and 2.5 Mbit/s; `ffmpeg` HLS segments pulled by `curl` at playback pace; `ffmpeg` UDP MPEG-TS VBR 6 Mbit/s |
| voip | `ffmpeg` G.722 RTP both ways; GStreamer Opus 40 ms with talk spurts (1-3 s talk, 1-3 s silence); GStreamer Speex 20 ms |
| messaging | `redis` pub/sub both ways; MQTT QoS 2 with retained messages; `nc` line chat with typing bursts |
| email | IMAP fetches with `curl imap://` from `dovecot`; POP3 with `curl pop3://`; SMTP with attachments via `swaks` |
| icmp | `hping3 --icmp` with random sizes; `nping --icmp`; `ping` with a random size per run (56-1400) and interval (0.2-2 s) |
| **mixed** | two classes at once, one tool of each, 45 s: video+interactive, web+voip, bulk+interactive, bulk+voip, web+video, messaging+email, voip+interactive, bulk+web, each with 2 variant pairings and 2 repetitions, i.e. **64 mixed sessions** (EXP-05/15 gave 28) |

Singles: about 26 variants x 2 repetitions = **about 52 single sessions, plus the mixed 64**. If a tool cannot be made to run, it is
dropped and listed in the RESULT before any scored capture of that class.

## Lab F, the final untouched test (fixed here)
Same topology and capture; **ESP ChaCha20-Poly1305 and AES-256-GCM**, `netem delay 25ms 10ms loss 0.5%` (a worse path than any
training family). Tools in none of labs A to E: bulk `nc | pv` raw TCP push and `rsync` in daemon mode (no ssh); web `nghttp` (HTTP/2 over
TLS) from `nghttpd`, page-plus-assets with think time; interactive `ssh` + `nano` editing, `ssh` + `watch -n 0.5`, `ssh` + `cmatrix`
(screen-scroll stream); video GStreamer VP8 RTP, GStreamer MPEG-TS over TCP; voip GStreamer Opus 60 ms and iLBC 30 ms RTP both ways;
messaging `zeromq` (Python) pub/sub both ways, MQTT QoS 0 high-rate small payloads; email `mailx` through a `postfix` relay, `curl` SMTP over TLS (`smtps`); icmp `traceroute -I` and `ping -s` fixed 1000 at 0.3 s; plus 16 **mixed** sessions (video+interactive, web+voip, bulk+interactive,
messaging+email, 2 repetitions, two pairings). **48 single captures (8 classes x 3 variants x 2 repetitions) and 16 mixed**, 45 s each.
Lab F trains nothing and chooses nothing.

## Candidates (fixed here)
Corpus of **nine** families = EXP-42's eight plus lab E (singles). Same code as EXP-42 (`analyze.py` there), v2 features, balanced weights,
augmentation, RandomForest 200 trees, unless stated.
| ID | What |
|---|---|
| K4 | the shipped model (eight families) |
| K7 | K4's recipe on nine families |
| K8 | K7 with ExtraTrees and RandomForest soft-voted (equal weight) |
| K9 | K7 with per-family weight proportional to the square root of its sessions instead of equal (so the big real sources count for more) |
Selection: highest mean leave-one-family-out macro-F1 over the **nine** families, subject to EXP-42's two guards (worst family within
0.05 of K4's, grouped-by-session within 0.02); ties within 0.01 go to the earlier row. The mixed check is retrained in a second step with
all mixed sessions (EXP-05/15 and lab E), probabilities from leave-one-family-out models, EXP-16's rule for tau, at **catch >= 80% and
false flags <= 10%**.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P45-1 | More families help the held-out average: best of K7/K8/K9 >= K4 + 0.03 on the original eight families' leave-one-family-out mean | < +0.03 |
| P45-2 | On lab F the chosen model beats the shipped K4: ungated macro-F1 >= K4 + 0.05 | < +0.05 |
| P45-3 | Interactive is no longer lost: chosen model's lab-F interactive F1 >= 0.5 (K4's lab-D value was 0.0) | < 0.5 |
| P45-4 | The mixed check meets EXP-16's bar in cross-validation with 92 mixed sessions | no tau reaches 80% / 10% |
| P45-5 | With the new check, lab F singles are not over-flagged: <= 25% of lab-F single sessions flagged mixed (K4 today: 66% on lab D) | > 25% |
| P45-6 | Gated answers stay trustworthy and useful on lab F: >= 90% of gated answers right and >= 50% of the 48 singles answered | either fails |
| P45-7 | Lab-F mixed sessions are still not answered with a confident single label: >= 80% of the 16 mixed are flagged or abstained | < 80% |

## Ship rule (decided now)
The chosen model replaces K4 only if **P45-2 and P45-6 hold**; the new mixed check replaces the current one only if **P45-4, P45-5 and
P45-7 hold**. Otherwise nothing of that part ships and the RESULT says what was learned. The artifact must stay under 5 MB and train in
under 5 s (cap and rounding chosen from size alone as in DEC-054). No sample from lab F is ever added to training in this experiment.
Every prediction is reported whether or not it holds.
