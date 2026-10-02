# EXP-41 — A third lab with sustained traffic and new generators — PRE-REGISTRATION (2026-10-02, before any scored capture)

## Why
EXP-37 found the shipped traffic-type model does not transfer to another team's lab. EXP-38 found the gates abstain
correctly and our features can separate that lab's classes when trained inside it. EXP-39 could not tell whether training on
one public lab helps on another, because one of the two (lab B) has no scorable window for three of its five classes (a flaw in
that pre-registration). This experiment removes that flaw: it builds **lab C**, ours, with sustained traffic (60 s per capture, so
every class yields about 30 two-second windows) from generators that differ from our shipped ones and from both public labs, and
uses it as the test for models trained on the public labs. It measures; it ships nothing.

## Lab C (fixed here)
Two hosts behind the strongSwan 6.1.0 gateways (`alice-pq`, `bob-pq`), so their traffic crosses the tunnel; the keyless router
captures `ip proto 50`, headers only (`-s 96`); the capture is reduced to a per-packet table (t, direction, IP length) kept in the
repository, the pcaps are not. Eight classes, our own class list, each a real tool that is **not** in our shipped generators
(`tgen.py`, the EXP-16 apps) and not in lab A (Python servers, ffmpeg HLS and RTP, aiosmtpd, websockets) or lab B (curl, scp, ffmpeg
range requests, SIPp, ping):

| Class | Client -> server | Tool |
|---|---|---|
| bulk | labc-a -> labc-b | `iperf3` TCP at 5 Mbit/s |
| web | labc-a -> labc-b | `wget -r -l3` with random waits against `busybox httpd` (45 pages, 70 images of 4-150 KB) |
| messaging | both ways | MQTT (`mosquitto`), 20-180 byte payloads at 0.6-4.6 s gaps, one publisher per side |
| interactive | labc-a -> labc-b | `telnet` over a pty shell (`socat`), human-paced typing via `expect` (80-340 ms per key, 1.2-4.7 s between commands) |
| video | labc-b -> labc-a | `ffmpeg` testsrc2 640x360 25 fps, x264 900 kbit/s, MPEG-TS over UDP |
| voip | both ways | `ffmpeg` Opus 24 kbit/s, 20 ms frames, RTP, one stream each way |
| email | labc-a -> labc-b | `curl` SMTP submission to Python's `smtpd`, 0.3-2 MB messages at 1.5-6.5 s gaps |
| icmp | labc-a -> labc-b | `ping -i 0.7 -s 200` |

Two tunnel configurations, loaded one at a time: **gcm** (IKE `aes256-sha256-modp3072`, ESP `aes256gcm16`) and **cbc**
(IKE `aes128-sha256-modp2048`, ESP `aes128-sha256`). Two repetitions per class and configuration, 60 s each: **32 captures**.
Ground truth for the class is the generator that ran; for the cryptography it is `swanctl --list-sas` saved per configuration.

## Other labs' data (permission relayed verbally by the project owner for both; neither repository has a licence file)
Lab A `ipsec-pcap-lab` commit `c0cf25647b88c1cdb0649a43049e192e269f4cc6` (`pcaps/known`, 175 captures, `metadata.csv` SHA-256
`81234b73e338a6945af19711e1303ffa0f1b174c0b33d0f139fd5e3e145d8a8c`); lab B `ashwin02-cyber/SIH_2026` commit
`ef0ffe9926ec44e78bb963d55f21f856369d2ba2` (`real_captures`, 180 traffic captures, `manifest.csv` SHA-256
`244a5e5e49b9ecc8b5d938e9269994b41b0d763e300c237caafba2989fb970fa`). Kept outside the repository, deleted afterwards. Lab B
yields windows only for icmp and web (EXP-39), and is used as such.

## What has been seen before this was written
EXP-37, 38 and 39 on labs A and B. For lab C: an 8-second smoke test of each class for packet counts, directions and sizes
(for example bulk 15,455 packets with a median length of 1,500; video one-way b to a at 1,400; voip 401 packets each way at about
200 bytes), to confirm each generator works. No window feature, no prediction, no model score has been computed on lab C.

## Method (fixed here)
`analyze.py` converts each lab-C table with the shipped `window_features` (2-second windows) and calls the shipped
`assess_exposure` for the gated path. Models are the shipped forest and gates retrained on other windows by pointing
`attacker.DATA` at a temporary `.npz` (as in EXP-39; no shipped file is edited): **M0** shipped; **M1** shipped + all lab-A
windows; **M3** shipped + lab A + lab B; **M4** shipped + lab C (used only against lab A). `file_transfer` is renamed `bulk`.
Capture-level label = argmax of the mean window probability. Metric: macro-F1 over lab C's eight classes (`f1_score`,
`average="macro"`, `labels=<8 classes>`, `zero_division=0`); coverage = answered / captures with at least `MIN_WINDOWS` (3) windows.

## Predictions
| # | Prediction | Falsified if |
|---|---|---|
| P41-1 | The shipped model does not transfer to lab C: M0 ungated macro-F1 < 0.70 | >= 0.70 |
| P41-2 | Lab C's classes are separable by our features: train on repetition 1 (both configurations), test on repetition 2, macro-F1 >= 0.90 | < 0.90 |
| P41-3 | Training on lab A helps on a fresh lab: M1 ungated macro-F1 on C >= M0 + 0.10 | gain < 0.10 |
| P41-4 | Adding lab B as well helps: M3 ungated macro-F1 on C >= M0 + 0.10 | gain < 0.10 |
| P41-5 | M3 through the shipped gates on C: coverage >= 50% and accuracy among answered >= 0.90 | either fails |
| P41-6 | The reverse direction: M4 (shipped + C) ungated macro-F1 on lab A >= 0.362 (the shipped 0.262 + 0.10) | < 0.362 |
| P41-7 | No harm to our own data: grouped 5-fold CV on the shipped windows loses <= 0.02 when lab A, B and C windows are all added | loses > 0.02 |
Exploratory, not scored: per-class F1 for each model; the stage census (answered, abstained, out-of-distribution, insufficient) for
M0 and M3 on C; results split by tunnel configuration; M3's score on lab A and B (it has seen both, so not a test).

## Reading the result (decided now)
- P41-3 or P41-4 holds -> training on other labs helps on a lab it has never seen: recommend, as a separate task with the owner's
  decision, its own pre-registration and the golden/DEC updates, retraining the shipped windows with the helpful lab(s).
  EXP-41 cannot grade a model it was part of training; the evidence for the retrained model is these held-out numbers, quoted as such.
- Neither holds, P41-2 holds -> other labs' data does not help here although the classes are learnable: do not retrain; the gap is
  specific to each lab's generators; say so in the README.
- P41-2 fails -> lab C is not a usable test bed; fix lab C before concluding anything.
- P41-7 failing blocks any retraining regardless.
Every prediction is reported whether or not it holds. Other labs' captures are deleted after RESULT.md is written.

## Erratum (2026-10-02, before any scored capture)
The table above says email messages are "0.3-2 MB". The generator (`testbed/scripts/labc_gen.sh`) draws `300 + RANDOM * n` bytes with n in 1..6
before base64, i.e. about 0.4 KB to 260 KB per message, and the messaging payloads are 20-179 random bytes before base64 (28-240 characters).
The script is what ran; this line corrects the description. No prediction depends on these sizes.
