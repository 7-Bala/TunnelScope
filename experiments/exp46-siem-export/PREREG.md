# EXP-46 — SIEM export: Elastic ECS JSON and RFC 5424 syslog (T-129) — PRE-REGISTRATION (2026-10-02, before any code and any run)

## Why
TunnelScope can already append alert lines (`jsonl`, RFC 5424 `syslog`, T-134), but (a) no real SIEM has ever parsed
them, and (b) the per-tunnel verdicts of an analysed capture cannot be exported at all. T-129 asks for syslog/JSON
export "verified by ingesting into a local Elastic". This experiment fixes what is exported and what counts as verified.

## What is built (fixed here)
- `tunnelscope export CAPTURE --format ecs|syslog [--profile P] [--only-fail] [--at TIME] [--out FILE] [--bulk-index NAME]`:
  one document (ecs, newline-delimited JSON) or one line (syslog) **per verdict**. With `--bulk-index NAME` the ecs output
  is Elasticsearch `_bulk` NDJSON (`{"create":{"_index":NAME}}` + document), ready for a data stream.
- `--alert-format ecs` for `live`, `watch` and `collect`: the existing alert dicts as ECS documents (`event.kind: alert`).
- New package `tunnelscope/siem/` (ECS mapping + RFC 5424 verdict formatter). It writes strings and files only. It
  opens no connection: shipping is the operator's choice (Filebeat, rsyslog, curl), as in T-134.

### ECS mapping (verdict event)
`@timestamp` (the time of the assessment, UTC; `--at` overrides it for replays: it is NOT the time the traffic happened),
`ecs.version` (`9.5.0`), `event.{kind,category,type,dataset,module,provider,outcome,severity,id,reason}`,
`message`, `observer.{vendor,product,version}`, `file.name` (capture file name, no path), `rule.{id,name,ruleset,description}`,
`source.{ip,address}`, `destination.{ip,address}` (only when the tunnel end parses as an IP address), and everything
TunnelScope-specific under the custom namespace `tunnelscope.*` (`verdict`, `severity`, `attribute`, `observed` as JSON
text so its varying type cannot cause a mapping conflict, `baseline`, `authority`, `tunnel`, `posture`).
`event.kind` = `alert` for FAIL and `state` otherwise; `event.outcome` = `failure` (FAIL), `success` (PASS), `unknown`
(UNKNOWN, NOT_OBSERVABLE, CONTRADICTORY) -- an unknown is never reported as success. `event.severity` uses Elastic's
rule scale (informational 21, medium 47, high 73). Alert events: `event.kind: alert`, `event.action` = the alert kind,
`observer.name` = the site (collector), `tunnelscope.alert.{kind,attribute,usual,now,tunnel}`.

### Syslog (verdict line)
RFC 5424: `<PRI>1 TIMESTAMP HOST tunnelscope - VERDICT [tunnelscope@32473 rule=".." baseline=".." verdict=".." severity=".."
attribute=".." observed=".." tunnel=".." file=".."] MESSAGE`, facility 13 (log audit) as for alerts; syslog severity
FAIL high -> 3 (error), FAIL medium -> 4 (warning), FAIL informational -> 5 (notice), all other verdicts 6 (info).

## Inputs (fixed here)
- **Corpus:** every capture file under `testbed/captures/` in the work tree (`analyze.py` records the count and the list
  hash); default baselines. In addition the opt-in `nist-sp800-77r1` profile on the ten captures of EXP-35 H3.
- **Alerts:** the T-134 replay (`pq-mlkem768` x2, `pq-downgrade`, `classical-baseline`) -> alert documents and alert syslog.
- **SIEM:** Elasticsearch 9.5.4 and Filebeat 9.5.4 (official images `docker.elastic.co/...`, digests recorded in RESULT),
  single node, security off, bound to 127.0.0.1, 1 GB heap, data stream `logs-tunnelscope-default` (built-in `ecs@mappings`
  component template). **ECS reference:** `ecs_flat.yml` of elastic/ecs tag v9.5.0 (Apache-2.0, vendored unmodified in
  `tests/fixtures/ecs/`, SHA-256 `70557ba53e2bda966688f8255193d36f2dcfa5bce2fb4a1a460bcccfd328ed5c`).
- All containers, volumes and both images are removed after the run.

## Bars
- **H1 (schema):** every field of every emitted ECS document that is not under `tunnelscope.*` exists in ECS v9.5.0
  `ecs_flat.yml`, its value has that field's type (keyword/ip/date/long/match_only_text; arrays only where ECS says
  `normalize: array`), and `event.kind`, `event.category`, `event.type`, `event.outcome` take only ECS-allowed values.
  One violation fails H1. (Unit test over the corpus plus `analyze.py`.)
- **H2 (Elasticsearch accepts):** the `_bulk` response reports 0 item errors; **0 documents carry an `_ignored`
  marker** (a field Elasticsearch silently dropped); `GET _mapping` shows `@timestamp` date, `source.ip` and
  `destination.ip` ip, `rule.id` keyword, `event.severity` long, `event.kind` keyword; document count in Elasticsearch
  equals documents sent.
- **H3 (counts agree):** per rule id and per verdict value, the counts from an Elasticsearch terms aggregation equal the
  counts computed independently from `tunnelscope assess --json` over the same captures. Any difference fails H3.
- **H4 (syslog is real RFC 5424):** every exported syslog line (verdicts and alerts) passes a strict RFC 5424 parser in the
  unit tests AND is parsed by Filebeat 9.5.4's `syslog` processor with no `error.message`; Filebeat's event count equals the
  line count; `log.syslog.{priority,severity.code,facility.code,hostname,appname,msgid,structured_data}` are populated and
  the structured-data parameters equal what was written.
- **H5 (no network, no side effects):** no module under `tunnelscope/siem/` imports `socket`, `ssl`, `urllib`, `http` or
  `tunnelscope.net`; existing tests pass without edits; `tunnelscope assess --json` output is byte-identical to `origin/main`
  on the ten H3 captures.
- **H6 (deterministic):** the same capture with the same `--at` gives byte-identical output twice, in both formats.

## Predictions (stated before the run)
All six bars hold. Where it is most likely to fail, and what I will report if it does: (a) a tunnel end that is not an IP
(`unknown`, IPv6 with scope id) -- the mapping omits `source.ip` instead of emitting a bad value, so H2 should hold; (b)
Filebeat's syslog processor rejecting structured data the strict parser accepts -- reported as a finding, not hidden by
changing the processor config; (c) the existing T-134 alert syslog line having never been parsed by a real tool, a defect
there would be a finding about T-134, fixed separately and disclosed.

## Not claimed
Splunk is not tested (HEC JSON is not produced). Kibana, Elastic Security detection rules and dashboards are not tested.
ECS validity covers the fields TunnelScope emits, not the semantics of Elastic's detection content. `@timestamp` is the
assessment time. A fail-open case (Elasticsearch down) is the shipper's concern; TunnelScope only writes files.

## Rules of this experiment
No bar, mapping or prediction above changes after this commit. RESULT.md quotes `results/summary.json` only. Addenda go
below this line, dated, before the run they govern.

## ADDENDUM A (2026-10-02, after the code and a 25-capture rehearsal, before the run that counts)
Nothing above is removed or loosened; the run gets stronger in two ways, and the rehearsals were not scored.
1. **Corpus.** The work tree holds only the 145 captures that git tracks. The run uses the full local capture directory of
   the main checkout (`testbed/captures`, 767 files at this point, including every lab) via `analyze.py --captures`, plus the
   ten EXP-35 captures again under the `nist-sp800-77r1` profile. `summary.json` records the count, the directory and a
   SHA-256 of the sorted name list. Every capture is exported; any capture that cannot be read is reported as an error and
   fails the run (none is skipped).
2. **Negative controls (they test the test; they do not replace any bar).** A scorer that cannot fail proves nothing, so the
   run also sends (a) one document whose `source.ip` is `not-an-ip` into a separate `logs-tunnelscope-control` data stream:
   Elasticsearch must accept it without an error and the `_ignored` check must still see the dropped field (this is the
   case the H2 check exists for), and the schema checker must flag it; and (b) one malformed syslog line that Filebeat
   must mark with `error.message` and the strict parser must reject. If either control does not trip, the run fails.
