# EXP-48 — Zeek and Suricata bridge (T-128) — PRE-REGISTRATION (2026-10-04, before any code and any scored run)

## Why
T-128 asks that TunnelScope "run inside existing SOC stacks" and be "tested against the same captures". Two probes (not scored, disclosed) fixed the facts:
Suricata 8.0.7 parses IKE and writes `event_type: "ike"` EVE records (IKE_SA_INIT algorithms, SPIs, payload and notify lists; nothing about ESP, rekeys or later
exchanges, which are encrypted or not parsed). Zeek 9.0.0 (official image, arm64) has no IKE analyzer: on the same capture `conn.log` shows UDP/500 with an empty
`service` and ESP as `unknown_transport`. Both ran in Docker on the same Mac as the other experiments. So there is nothing for TunnelScope to plug into on the
detection side; the useful bridge is the other direction: TunnelScope's verdicts as log lines a Zeek or Suricata stack already collects, plus a measured comparison with
what each sensor can and cannot see.

## What is built (fixed here)
`tunnelscope export CAPTURE --format zeek|eve` (same options as the other formats: `--profile`, `--only-fail`, `--at`, `-o`), one line per verdict, in `tunnelscope/siem/`.
No plugin, no script installed into a sensor, no connection: files and stdout only (DEC-055).
- **`zeek`**: a Zeek TSV log in the standard header format (`#separator \x09`, `#set_separator ,`, `#empty_field (empty)`, `#unset_field -`, `#path tunnelscope`,
  `#open`, `#fields`, `#types`, rows, `#close`). Columns: `ts` (time; the assessment time, `--at` for replays, NOT the time of the traffic: evidence records carry no
  absolute time), `id.orig_h` and `id.resp_h` (addr; unset when the tunnel end is not a plain IP), `ike_spi_i`, `ike_spi_r` (string; unset when unknown), `baseline`,
  `rule_id`, `attribute`, `verdict`, `severity` (string), `title`, `observed` (string; JSON text for non-strings, cut at 1000 characters like the ECS export), `message`.
  Escaping exactly as Zeek's ASCII writer: tab, newline and any byte outside printable ASCII as `\xNN`, backslash as `\x5c`, a value equal to `-` as `\x2d`,
  an empty string as `(empty)`, no value as `-`.
- **`eve`**: JSON lines shaped like Suricata's EVE: `timestamp` (`%Y-%m-%dT%H:%M:%S.%f+0000`), `event_type: "tunnelscope"` (a custom type, like Suricata's own
  `anomaly`), `src_ip`, `dest_ip` (only when a plain IP; the verdict has no ports, protocol or flow id, so none are invented), and one `tunnelscope` object with
  `ike_spi_i`, `ike_spi_r`, `baseline`, `rule_id`, `attribute`, `verdict`, `severity`, `title`, `observed`, `message`, `file`. It is deliberately NOT an `alert` event:
  Suricata did not raise it, it has no signature id, and a `FAIL` here must never be counted as a Suricata detection.

## Inputs (fixed here)
- **Corpus:** every `.pcap` under `testbed/captures/` in the work tree that yields at least one IKE record (`analyze.py` writes the count and the list hash).
- **Sensors:** `jasonish/suricata` (8.0.7 at probe time) and `zeek/zeek` (9.0.0), pulled once, digests recorded in RESULT; run offline on each pcap (`-r`), default
  configuration, rules disabled (`-S /dev/null` is not used; EVE `ike` events do not need rules), `-k none` for checksums, `-C` for Zeek. Containers and both images are
  removed after the run.
- **Mapping for the cross-check (fixed in `analyze.py` before the scored run, committed):** names of Suricata's `alg_enc`, `alg_auth`, `alg_prf`, `alg_dh` and
  TunnelScope's `ike_encr`, `ike_integ`, `ike_prf`, `ike_dh_group` are both normalised to an IANA-transform family (cipher family without key length, hash family,
  group number). A name outside the mapping is "unmapped" (counted and listed, never matched).

## Bars
- **H1 (Zeek reads it back):** Zeek's own input framework (ASCII reader, a script that declares the same record) and `zeek-cut` read every exported file with no
  reader error, and every field of every row read back equals the value TunnelScope wrote (compared to the in-memory verdicts), over the whole corpus and over a set
  of hostile values (tab, newline, backslash, `-`, `(empty)`, non-ASCII, 3000-character observed text, non-IP tunnel end). One mismatch fails H1.
- **H2 (EVE has Suricata's envelope):** every `eve` line parses as JSON; `timestamp` matches the format of the timestamps in Suricata's own EVE output for the same
  captures; `event_type`, `src_ip`, `dest_ip` have the same JSON types as in Suricata's `ike` events; the line is a single physical line. One violation fails H2.
- **H3 (join keys):** for every tunnel with an IKE SA, the pair (`id.orig_h`, `id.resp_h`) occurs in Zeek's `conn.log` of that capture (either direction), and, where
  Suricata logged an `ike` event for that capture, the (`ike_spi_i`, `ike_spi_r`) of the TunnelScope row equals the (`init_spi`, `resp_spi`) of some Suricata event.
  Reported as counts per capture, no pass mark invented: the bar is that **a miss is explained by one of the three causes below and unexplained misses are 0**:
  (a) IKE_SA_INIT not in the capture (SPI pair incomplete), (b) Suricata did not log an `ike` event, (c) the tunnel end is not an IP.
- **H4 (cross-check, the honesty bar):** for every SA where Suricata logged the responder's IKE_SA_INIT algorithms and TunnelScope has a value (not UNKNOWN /
  NOT_OBSERVABLE) for the same attribute, the two agree at the family level. Every disagreement is listed with both values and diagnosed in RESULT; the bar is **0
  undiagnosed disagreements**. Cases where one side has no value are reported as counts (Suricata silent, TunnelScope UNKNOWN), not as disagreements.
- **H5 (what the sensors cannot see):** reported, not a pass/fail: the number of tunnels in the corpus that carry ESP/AH or a rekey (CREATE_CHILD_SA) and that
  Suricata logged nothing for beyond IKE_SA_INIT and Zeek's `service` column left empty; i.e. what TunnelScope adds. Prediction (to be checked, not assumed): Zeek's
  `service` is empty on 100% of UDP/500 and UDP/4500 connections; ESP flows are `unknown_transport`; Suricata's `ike` events carry no ESP data.
- **H6 (no side effects):** no module under `tunnelscope/siem/` imports `socket`, `ssl`, `urllib`, `http` or `tunnelscope.net`; existing tests pass without edits;
  `tunnelscope export --format ecs|syslog` output is byte-identical to the base branch on the ten EXP-35 captures with the same `--at`.

## Not claimed (fixed here)
No Zeek package or Suricata plugin is shipped or tested. Not tested: Filebeat's Suricata/Zeek modules, Splunk, Security Onion, a live interface, rules that react to
`tunnelscope` events. The `ts` of a row is the assessment time, so rows join to sensor logs by IP pair and SPI pair only, never by time window.
