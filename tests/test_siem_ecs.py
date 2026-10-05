"""T-129 / EXP-46: SIEM export as Elastic ECS JSON and RFC 5424 syslog.
Schema checks run against the official ECS v9.5.0 field reference (tests/fixtures/ecs/, vendored unmodified)."""
import ast
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from ecs_check import ecs, problems

from tunnelscope.anomaly.alerts import alerts_from, format_alert
from tunnelscope.cli import main
from tunnelscope.siem import ecs as E
from tunnelscope.siem import export
from tunnelscope.siem import syslog as S

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
AT = "2026-10-02T12:00:00Z"
# the ten captures of EXP-35's H3 table: handshakes of every kind, an IKEv1 SA, an AH tunnel, an ESP-only SA
SAMPLE = ["exp15/s-ecp256.pcap", "exp15/s-3des.pcap", "exp15/s-x25519.pcap", "exp15/s-modp1536.pcap",
          "exp15/s-modp4096.pcap", "cloud/c-v1.pcap", "cloud/c-w.pcap", "exp15/a-tra-sha1.pcap",
          "exp07/e7-pfs-on.pcap", "a7-cs-aes256gcm16.pcap", "pq-downgrade.pcap"]


def _docs(name, **kw):
    return export.ecs_documents(str(CAP / name), at=AT, **kw)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


# ------------------------------------------------------------------ ECS documents
@pytest.mark.parametrize("name", SAMPLE)
def test_every_field_is_an_ecs_field_of_the_right_type(name):
    docs = _docs(name)
    assert docs
    for d in docs:
        assert problems(d) == [], (d["rule"]["id"], problems(d))


def test_the_checker_itself_rejects_bad_documents():
    good = _docs("pq-downgrade.pcap")[0]
    assert problems(good) == []
    for path, bad in (("source.ip", "not-an-ip"), ("event.kind", "problem"), ("event.severity", "73"),
                      ("@timestamp", "yesterday"), ("event.type", ["change"]), ("rule.nonsense", "x")):
        d = json.loads(json.dumps(good))
        cur = d
        *head, last = path.split(".")
        for h in head:
            cur = cur.setdefault(h, {})
        cur[last] = bad
        assert problems(d), path
    d = json.loads(json.dumps(good)); d["event"].pop("category"); d["event"]["category"] = "network"
    assert problems(d), "a string where ECS wants an array"
    d = json.loads(json.dumps(good)); del d["@timestamp"]
    assert problems(d)


def test_fail_is_an_alert_and_failure_pass_is_success_and_unknown_is_never_success():
    seen = {}
    every = [d for name in SAMPLE for d in _docs(name)]
    every += _docs("exp15/s-ecp256.pcap", profiles=["nist-sp800-77r1"])      # the profile adds a NOT_OBSERVABLE rule (peer auth)
    for d in every:
        v = d["tunnelscope"]["verdict"]
        seen.setdefault(v, d)
        kind, outcome = d["event"]["kind"], d["event"]["outcome"]
        if v == "FAIL":
            assert (kind, outcome) == ("alert", "failure")
        elif v == "PASS":
            assert (kind, outcome) == ("state", "success")
        else:
            assert (kind, outcome) == ("state", "unknown"), (v, outcome)
    assert {"FAIL", "PASS", "UNKNOWN", "NOT_OBSERVABLE"} <= set(seen)


def test_an_esp_only_capture_is_unknown_not_a_pass():
    docs = _docs("a7-cs-aes256gcm16.pcap")
    ike = [d for d in docs if d["tunnelscope"]["attribute"] in ("ike_version", "ike_dh_group", "ike_encr")]
    assert ike and all(d["event"]["outcome"] == "unknown" for d in ike)


def test_severity_uses_elastics_scale_and_follows_the_rule():
    for d in _docs("cloud/c-w.pcap"):
        assert d["event"]["severity"] == {"high": 73, "medium": 47, "informational": 21}[d["tunnelscope"]["severity"]]


def test_tunnel_ends_become_ip_fields_only_when_they_are_ips():
    d = _docs("pq-downgrade.pcap")[0]
    assert d["source"] == {"address": "10.10.1.20", "ip": "10.10.1.20"}
    assert d["destination"]["ip"] == "10.10.2.20"
    assert E.as_ip("fe80::1%eth0") is None and E.as_ip("unknown") is None and E.as_ip(None) is None
    assert E.as_ip("2001:db8::1") == "2001:db8::1"
    doc = E.verdict_event({"verdict": "PASS", "rule_id": "R", "title": "t", "baseline": "B", "authority": "a",
                           "attribute": "x", "observed": 1, "message": "", "severity": "medium"},
                          file="f.pcap", src="host-a", dst="fe80::1%eth0", sa="s", at=AT)
    assert "ip" not in doc["source"] and "ip" not in doc["destination"] and problems(doc) == []


def test_observed_is_always_text_so_the_index_mapping_cannot_conflict():
    kinds = set()
    for name in SAMPLE:
        for d in _docs(name):
            kinds.add(type(d["tunnelscope"]["observed"]))
    assert kinds == {str}
    long_value = ["x" * 40] * 60
    doc = E.verdict_event({"verdict": "FAIL", "rule_id": "R", "title": "t", "baseline": "B", "authority": "a",
                           "attribute": "x", "observed": long_value, "message": "m", "severity": "high"},
                          file="f", src="1.1.1.1", dst="2.2.2.2", sa="s", at=AT)
    assert len(doc["tunnelscope"]["observed"]) <= E.MAX_TEXT and doc["tunnelscope"]["observed_truncated"] is True


def test_timestamps_are_utc_whatever_zone_they_came_in():
    assert E.timestamp("2026-10-02T17:30:00+05:30") == AT              # an offset is converted, not dropped
    assert E.timestamp("2026-10-02T12:00:00") == AT                    # no zone = UTC (never the machine's local time)
    assert E.timestamp(1759406400) == "2025-10-02T12:00:00Z" == E.timestamp("1759406400.7")
    now = E.timestamp(None)
    from datetime import datetime, timezone
    assert now.endswith("Z") and abs((datetime.fromisoformat(now.replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds()) < 5
    with pytest.raises(ValueError):
        E.timestamp("yesterday")


def test_event_ids_are_stable_and_unique_per_verdict():
    a = [d["event"]["id"] for d in _docs("pq-downgrade.pcap")]
    assert a == [d["event"]["id"] for d in _docs("pq-downgrade.pcap")] and len(set(a)) == len(a)


def test_profile_rules_are_exported_with_their_ruleset():
    docs = _docs("exp15/s-3des.pcap", profiles=["nist-sp800-77r1"])
    assert {d["rule"]["ruleset"] for d in docs} >= {"NIST-SP-800-77r1", "RFC-8247"}
    assert all(problems(d) == [] for d in docs)


def test_only_fail_exports_failures_only():
    docs = _docs("cloud/c-w.pcap", only_fail=True)
    assert docs and {d["tunnelscope"]["verdict"] for d in docs} == {"FAIL"}
    assert len(docs) < len(_docs("cloud/c-w.pcap"))


# ------------------------------------------------------------------ syslog
@pytest.mark.parametrize("name", SAMPLE)
def test_every_syslog_line_is_valid_rfc5424_and_says_the_same_as_the_ecs_document(name):
    lines = export.syslog_lines(str(CAP / name), at=AT, hostname="h1")
    docs = _docs(name)
    assert len(lines) == len(docs) > 0
    for ln, d in zip(lines, docs):
        p = S.parse(ln)
        sd = p["sd"][f"tunnelscope@{S.PEN}"]
        assert p["version"] == 1 and p["facility"] == 13 and p["app"] == "tunnelscope" and p["hostname"] == "h1"
        assert sd["rule"] == d["rule"]["id"] and sd["verdict"] == d["tunnelscope"]["verdict"]
        assert sd["observed"] == d["tunnelscope"]["observed"] and sd["attribute"] == d["tunnelscope"]["attribute"]
        assert p["msgid"] == d["tunnelscope"]["verdict"] and p["timestamp"] == AT


def test_syslog_severity_follows_the_verdict():
    base = {"rule_id": "R", "title": "t", "baseline": "B", "attribute": "a", "observed": None, "message": ""}
    pri = lambda verdict, sev: S.parse(S.verdict_line({**base, "verdict": verdict, "severity": sev},
                                                      file="f", src=None, dst=None, sa="s", at=AT))["severity"]
    assert (pri("FAIL", "high"), pri("FAIL", "medium"), pri("FAIL", "informational")) == (3, 4, 5)
    assert {pri(v, "high") for v in ("PASS", "UNKNOWN", "NOT_OBSERVABLE", "CONTRADICTORY")} == {6}


def test_hostile_values_cannot_break_the_line():
    nasty = 'a"b\\c]d\ne\r\tf ] "] \\'
    v = {"verdict": "FAIL", "rule_id": "R", "title": nasty, "baseline": nasty, "attribute": nasty, "observed": nasty,
         "message": nasty, "severity": "high"}
    line = S.verdict_line(v, file=nasty, src=nasty, dst="x", sa=nasty, at=AT, hostname="bad host\nname")
    assert "\n" not in line and "\r" not in line
    p = S.parse(line)
    assert p["hostname"] == "badhostname"
    sd = p["sd"][f"tunnelscope@{S.PEN}"]
    expected = 'a"b\\c]d e f ] "] \\'            # line breaks and tabs become one space; quote, backslash, ] survive escaping
    assert sd["observed"] == sd["attribute"] == sd["baseline"] == sd["sa"] == sd["file"] == expected
    assert p["msg"] == f"R: FAIL - {expected} ({expected})"


@pytest.mark.parametrize("bad", [
    "no pri 1 2026-10-02T12:00:00Z h a - - - m",
    "<192>1 2026-10-02T12:00:00Z h a - - - m",                                   # PRI above 191
    "<14>0 2026-10-02T12:00:00Z h a - - - m",                                    # version 0
    "<14>1 2026-10-02 12:00:00 h a - - - m",                                     # not RFC 3339
    "<14>1 2026-10-02T12:00:00Z h a - - m",                                      # a header field missing
    '<14>1 2026-10-02T12:00:00Z h a - - [x@1 k="un"escaped"] m',                 # unescaped quote
    '<14>1 2026-10-02T12:00:00Z h a - - [x@1 k="v"]m',                           # no space before the message
    "<14>1 2026-10-02T12:00:00Z h a - - - m\nsecond line",
])
def test_the_strict_parser_rejects_malformed_lines(bad):
    with pytest.raises(ValueError):
        S.parse(bad)


def test_the_strict_parser_accepts_the_alert_lines_t134_already_wrote():
    (al,) = alerts_from([{"tunnel": "a <-> b", "status": "anomalous", "anomalies": [
        {"layer": "posture", "kind": "downgrade", "severity": "high", "attribute": "pq", "usual": "ML-KEM-768",
         "now": "classical-only", "message": "m"}]}], "s", 0)
    p = S.parse(format_alert(al, "syslog", hostname="h1"))
    assert p["msgid"] == "DOWNGRADE" and p["sd"][f"tunnelscope@{S.PEN}"]["kind"] == "downgrade"


# ------------------------------------------------------------------ alerts as ECS
def _alert(**extra):
    (al,) = alerts_from([{"tunnel": "10.10.1.20 <-> 10.10.2.20", "status": "anomalous", "anomalies": [
        {"layer": "posture", "kind": "downgrade", "severity": "high", "attribute": "pq", "usual": "ML-KEM-768",
         "now": "offered-but-not-used", "message": "PQ key exchange lost"}]}], "pq-downgrade.pcap", 1759406400.0)
    return {**al, **extra}


def test_alert_documents_are_valid_ecs_and_carry_the_site():
    d = json.loads(format_alert(_alert(site="plant-7"), "ecs"))
    assert problems(d) == []
    assert (d["event"]["kind"], d["event"]["action"], d["event"]["severity"]) == ("alert", "downgrade", 73)
    assert d["observer"]["name"] == "plant-7" and d["@timestamp"] == "2025-10-02T12:00:00Z"
    assert d["source"]["ip"] == "10.10.1.20" and d["destination"]["ip"] == "10.10.2.20"
    assert d["tunnelscope"]["alert"]["usual"] == "ML-KEM-768"
    assert "observer" in json.loads(format_alert(_alert(), "ecs")) and "name" not in json.loads(format_alert(_alert(), "ecs"))["observer"]


def test_the_ecs_alert_format_is_offered_by_live_watch_and_collect():
    for cmd in ("live", "watch", "collect"):
        out = io.StringIO()
        with redirect_stdout(out), pytest.raises(SystemExit):
            main([cmd, "--help"])
        assert "ecs" in out.getvalue(), cmd


# ------------------------------------------------------------------ command line
def test_cli_ecs_lines_and_bulk_format_and_syslog():
    rc, out, _ = _run(["export", str(CAP / "pq-downgrade.pcap"), "--at", AT])
    docs = [json.loads(x) for x in out.splitlines()]
    assert rc == 0 and len(docs) == len(_docs("pq-downgrade.pcap")) and all(problems(d) == [] for d in docs)
    rc, out, _ = _run(["export", str(CAP / "pq-downgrade.pcap"), "--at", AT, "--bulk-index", "logs-tunnelscope-default"])
    rows = [json.loads(x) for x in out.splitlines()]
    assert rows[0::2] == [{"create": {"_index": "logs-tunnelscope-default"}}] * len(docs) and rows[1::2] == docs
    rc, out, _ = _run(["export", str(CAP / "pq-downgrade.pcap"), "--at", AT, "--format", "syslog"])
    assert rc == 0 and len(out.splitlines()) == len(docs) and all(S.parse(x) for x in out.splitlines())


def test_cli_is_deterministic_with_at_in_both_formats():
    for fmt in ("ecs", "syslog"):
        a = _run(["export", str(CAP / "cloud/c-w.pcap"), "--at", AT, "--format", fmt])[1]
        b = _run(["export", str(CAP / "cloud/c-w.pcap"), "--at", AT, "--format", fmt])[1]
        assert a == b and a


def test_cli_errors_and_empty_exports_are_said_out_loud(tmp_path):
    assert _run(["export", str(CAP / "pq-downgrade.pcap"), "--format", "syslog", "--bulk-index", "x"])[0] == 2
    rc, out, err = _run(["export", str(CAP / "pq-downgrade.pcap"), "--at", "yesterday"])
    assert rc == 2 and "--at" in err and out == ""
    rc, out, err = _run(["export", str(CAP / "pq-downgrade.pcap"), "--only-fail", "--at", AT])
    assert rc == 0 and out.strip()        # this capture has failures
    target = tmp_path / "ev.jsonl"
    rc, out, err = _run(["export", str(CAP / "pq-downgrade.pcap"), "--at", AT, "-o", str(target)])
    assert rc == 0 and out == "" and "line(s)" in err and len(target.read_text().splitlines()) > 0


# ------------------------------------------------------------------ the rules of the experiment
def test_the_siem_package_has_no_network_or_socket_code():
    pkg = Path(export.__file__).parent
    banned = {"socket", "ssl", "urllib", "http", "requests", "smtplib", "ftplib"}
    for f in pkg.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [("." * node.level) + (node.module or "")]
            for n in names:
                assert n.split(".")[0] not in banned and "net" not in n.split("."), (f.name, n)


def test_the_vendored_ecs_reference_is_the_one_we_hashed():
    import hashlib
    h = hashlib.sha256((Path(__file__).parent / "fixtures" / "ecs" / "ecs_flat.yml").read_bytes()).hexdigest()
    assert h == "70557ba53e2bda966688f8255193d36f2dcfa5bce2fb4a1a460bcccfd328ed5c"
    assert ecs()["event.kind"]["type"] == "keyword" and E.ECS_VERSION == "9.5.0"
