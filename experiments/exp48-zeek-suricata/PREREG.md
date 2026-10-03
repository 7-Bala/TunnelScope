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

## ADDENDUM A (2026-10-04, before the scored run): empty strings are written as unset
A probe of Zeek 9.0.0's input framework (ASCII reader, `Input::add_event`, not scored) on a file with hostile values showed that an empty string written as `(empty)`
comes back as the literal text `(empty)`, while `-` (unset) comes back as a missing optional field and the escaped forms `\x2d` and `\x28empty)` come back as the
literal values `-` and `(empty)`. So the text above ("an empty string as `(empty)`") is replaced by: **an empty string is written as `-` (unset)**; empty and missing mean
the same for every column here. H1 compares by hexadecimal dump of the bytes the reader returns, because `print` re-escapes strings and cannot show what was read.
`exit_only_after_terminate` is needed in the reader script, otherwise Zeek exits before the input thread delivers anything.

## ADDENDUM B (2026-10-04, after the sensor output existed and before the scored run): what the probe of the sensor logs showed
Over the 145 captures of the work tree Suricata 8.0.7 wrote 494 `ike` events (IKEv2 and also IKEv1: `alg_enc`, `alg_hash`, `alg_auth` (an authentication method in IKEv1),
`alg_dh`, `sa_key_length`), 50 `anomaly` events, 500 `flow` events. Consequences for the bars, fixed here:
- **H4 covers IKEv1 as well.** For IKEv1 the compared event is the first one with a non-zero responder SPI that carries `alg_enc` (the responder's selection; the
  initiator's offer has responder SPI zero). Attributes compared: cipher family (and key length where both sides give one), DH group number, and hash: IKEv2 `alg_prf` against
  TunnelScope's `ike_prf`, IKEv1 `alg_hash` against `ike_prf` (TunnelScope reports the IKEv1 hash as the PRF, DEC-051). IKEv2 `alg_auth` against `ike_integ`. IKEv1
  `alg_auth` is an authentication method and is not compared. IKEv2: the responder's IKE_SA_INIT event (`exchange_type` 34, `role` "responder") of the same SPI pair.
- **The SA key is the SPI pair.** A tunnel whose SPI pair is incomplete (no IKE_SA_INIT) is not compared and is counted under H3's explained misses.
- **Mapping:** done by IANA group numbers for the DH group, by (family, key length) for ciphers (Suricata's IKEv2 events give no key length, so only the family is compared
  there), by hash name for PRF and integrity. A value outside the mapping is "unmapped", listed, never matched. The functions are in `analyze.py`, committed with this addendum.
- **H5 additions to report:** how many of Suricata's IKEv2 CREATE_CHILD_SA events list any inner payload (prediction: none, they are encrypted); Suricata `flow` events
  with protocol ESP/AH; Suricata `anomaly` event kinds.
- **H6 byte-identity** is checked against the commit this branch started from (`b242551`) with `git archive`, for `ecs` and `syslog`, on the ten EXP-35 captures.
- Sensor run: `sensors.sh` (committed) in the official images; the first two attempts were discarded (the first lost most captures because `suricata` read the loop's stdin;
  the second ran concurrently with a leftover process) and the third is the one scored.

## ADDENDUM C (2026-10-04, after a dry run of `analyze.py` and before the scored run): three scorer corrections, disclosed
The first execution of the scorer (not the scored run; its output was overwritten) showed three faults in the scorer, not in the product:
(1) the Zeek reader script declared a function parameter `&optional`, which Zeek rejects, so H1 read 0 rows: fixed;
(2) the IKEv1 hash names were mapped to `SHA1` etc. while the IKEv2/TunnelScope side maps to `HMAC-SHA1`, so nine agreeing IKEv1 captures were counted as
disagreements: the mapping now gives `HMAC-SHA1`, same as the other side (the bar is unchanged: the family must be equal);
(3) the H5 metric "CREATE_CHILD_SA events listing inner payloads" was ill-defined (Suricata lists `EncryptedAndAuthenticated`, `Notify`); it is replaced by the
distribution of payload lists of those events and the count of events listing `KeyExchange` (the payload that shows PFS). Prediction kept: 0 such events.
The dry run also showed one real disagreement, `cloud/a-start.pcap` (4 attributes, one SA); it is not hidden by any change here and is diagnosed in RESULT.
