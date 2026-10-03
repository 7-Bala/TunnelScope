# EXP-48 RESULT — Zeek and Suricata bridge (T-128), 2026-10-04

Numbers below are quoted from `results/summary.json` (written by `analyze.py` at commit `68afdb0`, the scored run). Bars: `PREREG.md` and addenda A-C.

## Setup
`tunnelscope export CAPTURE --format zeek|eve` (`tunnelscope/siem/zeek.py`, `eve.py`). Sensors in Docker on this Mac (Apple M4, arm64 images), offline, default configuration:
Suricata `jasonish/suricata` 8.0.7 (`sha256:7ca2546f7f2735f621b981b6a5ec84fb962984636f7629a1a2fa6a324d4b6840`) and Zeek `zeek/zeek` 9.0.0
(`sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5`) over the 145 captures of the work tree (list hash `ea55b21864e7...`). Sensor run:
`sensors.sh`. Disclosed: two earlier sensor runs were discarded (stdin swallowed by `suricata` inside the loop; a concurrent leftover process) and the scorer was executed once
as a dry run before the scored run (addendum C: three scorer faults, none in the product; the dry run's output was overwritten).

## Results
| Bar | Result |
|---|---|
| **H1** Zeek reads it back | PASS. 2,259 rows written (2,246 corpus verdicts + 13 hostile values: tab, newline, backslash, `-`, `(empty)`, non-ASCII, a 3,000-character value, a list, control bytes, a non-IP address), Zeek's input framework returned 2,259 rows, 0 problems; every field equal to the in-memory value by hexadecimal comparison of the bytes read. `zeek-cut` returned all 2,259 lines. CLI output equals the module's output on 23/23 captures. |
| **H2** EVE has Suricata's envelope | PASS. 2,246 lines, 0 violations. Suricata's 494 `ike` events all have the timestamp pattern `%Y-%m-%dT%H:%M:%S.%f+0000` and `event_type`, `src_ip`, `dest_ip` as strings; ours the same. No line is an `alert`, none carries a port, protocol or flow id. |
| **H3** join keys | PASS. 150 IKE tunnels. The address pair is in Zeek's `conn.log` for 150/150. The SPI pair is in a Suricata `ike` event for 130/150; the other 20 are both explained: 10 have no IKE_SA_INIT in the capture (SPI pair incomplete), 10 are in captures where Suricata logged no `ike` event. Unexplained misses: 0. |
| **H4** cross-check with Suricata | 125 of 126 SAs agree on all four attributes; **one SA disagrees on all four, diagnosed below**; 0 undiagnosed. Compared: cipher 126 (125 agree), DH group 126 (125), PRF/hash 126 (125), integrity (IKEv2) 114 (113). Suricata silent for 8 SAs (no event with the responder's selection), TunnelScope UNKNOWN for 6-9 per attribute, unmapped names 0. |
| **H5** what the sensors cannot see | Reported, see below. |
| **H6** no side effects | PASS. No banned import in `tunnelscope/siem/`; `--format ecs` and `--format syslog` output byte-identical to the base commit (`b242551`) on the ten EXP-35 captures, 20/20 (capture, format) pairs; existing SIEM tests pass unedited. |

### H4 disagreement, diagnosed: `cloud/a-start.pcap`
The initiator's first IKE_SA_INIT is answered with INVALID_KE_PAYLOAD (frame 2); it retries with a two-proposal offer (frame 3); the responder's selection in frame 4 (checked with
`tshark -V`) is AES-CBC-256, AUTH_HMAC_SHA2_256_128, PRF_HMAC_SHA2_256, 2048-bit MODP (group 14), which is what TunnelScope reports. Suricata 8.0.7 logs for that response
ENCR_AES_GCM_16, AUTH_HMAC_SHA2_512_256, PRF_HMAC_SHA2_512, Modp2048s256 (group 24): exactly the **last transform of each type in the initiator's offer in frame 3**
(`tshark` on frame 3: last ENCR = AES-GCM-16 of proposal 2, last INTEG = HMAC_SHA2_512_256 of proposal 1, last PRF = 7, last DH = 24). So after a retried IKE_SA_INIT,
Suricata's `alg_*` fields describe the offer, not the selection. We have one capture of this; the cause is inferred from the matching values, not from Suricata's source, and
it was not reported upstream. TunnelScope's values were never the ones in question here.
Not compared: the key length for IKEv1 (Suricata gives `sa_key_length`; the scorer compared the cipher family only, so the comparison is weaker than the pre-registration's
"where both sides give one"); IKEv1 `alg_auth` (an authentication method, by design). In 123 of the 125 agreeing cipher comparisons TunnelScope also states a key length
that Suricata's IKEv2 event does not carry.

### H5 (reported, not pass/fail)
- **Zeek 9.0.0:** `service` is empty on 235/235 UDP connections on port 500 or 4500 (prediction held). 105 connections are `unknown_transport`; 105 of the 112 captures in
  which TunnelScope found ESP or AH have one. (The other 7: not examined; likely NAT-T encapsulated ESP, which is UDP; not claimed.)
- **Suricata 8.0.7:** 494 `ike` events (IKEv2 and IKEv1), 232 `flow` events with protocol ESP: these carry the SPI and packet/byte counts, no cipher, integrity or mode
  (one event inspected in full, `exp15/s-ecp256.pcap`; the field set was not enumerated over all 232). Joining Suricata's ESP flow `spi` (decimal) to TunnelScope's ESP SPI was
  not tested. 18 IKEv2 CREATE_CHILD_SA events across the corpus; none lists a `KeyExchange` payload (prediction held), so PFS is not visible to Suricata, where TunnelScope
  infers it from rekey size (30 tunnels in the corpus carry a rekey). 50 `anomaly` events (weak_crypto_dh 16, unknown_proposal 14, weak_crypto_prf 10, weak_crypto_auth 8,
  weak_crypto_enc 2): Suricata's own weak-algorithm checks, not compared here.

## What this means for T-128
- A Zeek or Suricata stack can collect TunnelScope's verdicts today as `tunnelscope.log` or EVE-shaped JSON, verified with the real Zeek reader and against the real Suricata
  output. They join to the sensors' own logs by address pair, and to Suricata's `ike` events by SPI pair (130 of 150 tunnels; the other 20 explained).
- There is no plugin: neither sensor has anything for TunnelScope to extend on the IKE side beyond what is above, and none was built.
- The sensors see the IKE_SA_INIT suite (Suricata only) and the existence of ESP; they do not see ESP ciphers, rekey/PFS content or the verdicts.

## Not shown
Filebeat's Suricata or Zeek modules, Splunk, Security Onion, a live interface, rules reacting to `tunnelscope` events, a Zeek package or Suricata plugin. `ts` is the assessment
time, so there is no time-window join. Corpus captures are our own plus the public sets already in the work tree; behaviour on other Suricata versions is untested.
