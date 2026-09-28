# EXP-33 — Headers-only capture (T-141) — RESULT (2026-09-28)

Pre-registration `PREREG.md` (85d1615) + ADDENDUM A (0f69776, one file per capture) and B (e8de654, a harness crash
before any data), both before the run. Scored by `analyze.py` -> `results/summary.json`.

## Headline
**Both bars hold.** Storing ESP/AH packets to 80 bytes (IKE whole) changed nothing TunnelScope reports.

| Hypothesis | Bar | Result |
|---|---|---|
| H1 same findings and verdicts | 0 differences | **0** over 11 SAs (10 handshakes, A/B alternating, plus the initial SA), 11 in each capture |
| H2 headers only | 100% | **732/732** ESP records stored <= 80 bytes (max 80); **75/75** IKE records stored whole |
| H3 size (no bar) | — | ESP bytes stored 112,728 -> 58,560; file 171,064 -> 115,668 bytes (807 packets each) |

Both captures ran at the same time on the router with the shipped `capture_command` (SHA-256 of both files in
`results/raw.jsonl`; the files stay local, git-ignored).

## What this does and does not show
- Traffic was 84-byte pings; with full-size traffic (about 1,400 bytes per ESP packet) the saving is much larger,
  since each ESP packet is stored as 80 bytes whatever its size. Not measured here.
- On IPv4, 80 bytes keeps up to 38 bytes past the ESP header (IV / start of the ciphertext), never plaintext.
- Not covered (stated in the PREREG): NAT-T ESP-in-UDP, AH, IPv6; the filters handle them but this lab run did not
  contain them.

## Decision
DEC-044: the site sensor's `--interface` capture stores ESP/AH headers only by default (`--full-packets` opts out);
`live --interface` offers it as `--headers-only`.
