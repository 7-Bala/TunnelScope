# EXP-33 — Headers-only capture: same findings without storing ESP payload? (T-141) — PRE-REGISTRATION (2026-09-28, before the code and any run)

## Why
A site sensor's capture files exist on disk for up to one window (longer with `--keep`). ESP/AH payload is
ciphertext TunnelScope never decrypts; it only uses the ESP/AH headers (SPI, sequence number) and each packet's
ORIGINAL length, which a capture file records even when the stored bytes are truncated. The IKE handshake, in
contrast, is analysed in full. If findings do not change, the sensor should store no more of each ESP/AH packet
than its headers.

## Design fixed here
Capture split by BPF, one dumpcap, the same interface opened twice (checked feasible 2026-09-28, no data kept):
- IKE: `udp port 500 or (udp port 4500 and udp[8:4] = 0)` (IKE on 4500 carries the 4-byte zero non-ESP marker),
  full length.
- ESP/AH: `ip proto 50 or ip proto 51 or ip6 proto 50 or ip6 proto 51 or (udp port 4500 and udp[8:4] != 0)`,
  stored length **80 bytes**: enough for Ethernet + IPv6 + UDP + the 8-byte ESP header (78). On IPv4 that keeps at
  most 38 bytes past the ESP header: IV / ciphertext, never plaintext. NAT-T keepalives (1 byte) match neither
  filter and are not stored (they carry no findings).

## Lab protocol
Router (sees alice <-> bob), W = 10 s. Two dumpcap processes run at the same time on the same interface for the
whole run: REFERENCE = today's live filter at full length; HEADERS = the split capture above. Both rotate every
10 s. Continuous pings through t-tun. 10 handshakes, alternating state A (`aes256-sha384-ecp384-ke1_mlkem768`) and
B (`aes256-sha384-ecp384`), 15 s apart (EXP-18's seeding). Afterwards every file pair is analysed (`analyze()`),
windows paired by index.

## Hypotheses and bars
- **H1 same findings:** for every SA (matched by addresses and IKE SPIs) in every window: identical finding status
  and value for every attribute, and identical verdict per rule. Bar: **0 differences**. A window whose REFERENCE has
  no packets is excluded (listed).
- **H2 nothing more than headers stored:** in HEADERS files, every ESP/AH record stores <= 80 bytes and every IKE
  record stores its full length. Bar: **100%**.
- **H3 size (reported, no bar):** total bytes REFERENCE vs HEADERS.
Not covered and stated: NAT-T (ESP-in-UDP), AH and IPv6 do not occur in this lab run.

## Decision rule
If H1 and H2 hold, the sensor's `--interface` capture stores headers only by default (`--full-packets` opts out),
recorded as a decision. `--follow` reads files another capture process writes; the docs give the same split
command for it.

## Rules
Scored by `analyze.py` -> `results/summary.json`; RESULT.md quotes it only; addenda before the runs they govern.

## ADDENDUM A (2026-09-28, after the code, before any run)
Nothing above is removed. Each capture is ONE file for the whole run instead of 10-second ring files: two
independent ring buffers never rotate at the same instant, so paired windows would hold different packets for
reasons unrelated to truncation, and per-window counts would differ. SAs are matched by addresses and SPIs as
stated in H1; every SA in either file must have a partner. Truncation does not depend on file rotation.
Both dumpcap commands come from `tunnelscope.live.live.capture_command` (window 0 = no ring), so the measured
command is the shipped one. Captures stay local (git-ignored subfolder); their SHA-256 is in the results.
