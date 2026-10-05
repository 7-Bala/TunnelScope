# EXP-46 — SIEM export: Elastic ECS JSON and RFC 5424 syslog (T-129) — RESULT (2026-10-02)

Pre-registration `PREREG.md` (991e939) + ADDENDUM A (cb1c69f, full corpus and negative controls), both before the run that
counts; the code and the scorer were committed (89622f5) before it too. Scored by `analyze.py` -> `results/summary.json`;
every number below is from that file.

## What was built
`tunnelscope export CAPTURE --format ecs|syslog [--profile P] [--only-fail] [--at TIME] [--bulk-index NAME] [-o FILE]`:
one event per verdict, as an Elastic Common Schema (ECS 9.5.0) JSON document, an Elasticsearch `_bulk` pair, or an RFC 5424
syslog line. `--alert-format ecs` for `live`, `watch` and `collect` turns the T-134 alerts into ECS documents. New package
`tunnelscope/siem/` writes strings and files only; shipping them (Filebeat, rsyslog, curl) is the operator's choice.
A FAIL verdict is `event.kind: alert`, `event.outcome: failure`; PASS is `state` / `success`; UNKNOWN, NOT_OBSERVABLE and
CONTRADICTORY are `state` / `unknown`, never success. TunnelScope-specific fields live under `tunnelscope.*`; values whose
type varies (`observed`) are JSON text, so an index mapping can never conflict.

## The run
Corpus: **767 capture files** (the full local `testbed/captures`, name-list SHA-256 `fd2367f5...b69c`) plus the ten EXP-35
captures again under the `nist-sp800-77r1` profile = 777 export jobs; **0 capture errors**; **11,290 verdict documents**,
11,290 syslog lines, and 3 alert documents/lines from the T-134 replay. SIEM: Elasticsearch **9.5.4**
(`sha256:82ac14f4...df4026`) and Filebeat **9.5.4** (`sha256:2dd1d525...149d`), single node, security off, bound to 127.0.0.1.

| Bar | Result |
|---|---|
| H1 schema (every non-`tunnelscope.*` field exists in ECS v9.5.0 with the right type and allowed values) | **0 violations in 11,293 documents** |
| H2 Elasticsearch accepts | 11,293 sent, **11,293 stored, 0 bulk item errors, 0 documents with an `_ignored` field**; `@timestamp` date, `source.ip` / `destination.ip` ip, `rule.id` keyword, `event.severity` long, `event.kind` keyword |
| H3 counts agree | **0 differences** over 73 (rule, verdict) pairs: 11,290 events in Elasticsearch = 11,290 from the CLI's own `assess --json` |
| H4 syslog is real RFC 5424 | strict parser rejected **0 of 11,293** lines; Filebeat's `syslog` processor: **11,293 events, 0 with `error.message`, 0 ignored; 0 differences** in priority, facility, severity, host, app name, message id, time and every structured-data parameter |
| H5 no network, no side effects | **0** network imports in `tunnelscope/siem/`; `assess --json` byte-identical to `origin/main` (7539ca3) on the ten H3 captures |
| H6 deterministic | 20 captures x 2 runs x 2 formats: **0 differences** |
| Negative controls (ADDENDUM A) | both tripped (below) |

Negative controls: a document with `source.ip: "not-an-ip"` was **accepted without any error** and stored with the field
silently dropped; only the `_ignored` check shows it (1 document), and the schema checker flags it. A malformed syslog line
got `error.message` from Filebeat and was rejected by the strict parser. So the checks above can fail.

Tests: `tests/test_siem_ecs.py` (50, with `tests/ecs_check.py`, which reads the official `ecs_flat.yml`), 16 mutation checks
all caught (unknown reported as success, FAIL not an alert, `source.ip` always set, `observed` as an object, severity scale,
timestamp zone dropped / naive time read as local, `--at` ignored, wrong alert category, `]` unescaped, control characters kept,
FAIL logged as info, a parser that accepts an unescaped quote, hostname with spaces, ECS alert format missing, bulk action
line dropped). Fast check: 695 passed, 1 skipped, guard clean.

## Disclosures
- Two unscored rehearsals (25 and 12 captures) preceded the run; the second added the negative controls and the full corpus
  (ADDENDUM A). Nothing was tuned on their results: they passed.
- My own pre-registered bar caught a flaw before the run: `siem/syslog.py` imported `socket` for the host name, which H5
  forbids; it now uses `platform.node()`. In the tests: one assertion ended in `or True` (made exact), the ECS category/type
  check was too lenient (made strict, so a type must be valid for every listed category), and one mutation that survived was
  an equivalent mutant, which exposed a real gap (no test of time-zone conversion) that now has one.
- The run took 4,181 s only because the scorer started 8 workers whose `assess` processes are multi-threaded (load above 58);
  this says nothing about the exporter's speed (T-125 measures throughput).

## What this does and does not show
- It shows that what TunnelScope exports is accepted by the real Elasticsearch 9.5.4 and parsed by the real Filebeat 9.5.4
  without loss, on every capture we have, and that the counts agree with the independent CLI path.
- Elasticsearch `logs-*` data streams drop malformed ECS values silently (the control above). TunnelScope sends none, but
  anyone feeding the index from another tool should alert on `_ignored`.
- `@timestamp` is the assessment time (`--at` for replays), not the time of the traffic. All 11,290 events carried one fixed
  time, so time-based dashboards were not exercised.
- Not tested: Splunk (no HEC JSON is produced), Kibana, Elastic Security detection rules, rsyslog / syslog-ng. The alert path
  was exercised with 3 alerts only. Whether an ECS event is useful to a SOC analyst is not measured here.

## Decision
DEC-059: the SIEM export ships (`tunnelscope export`, `--alert-format ecs`); files and stdout only.
