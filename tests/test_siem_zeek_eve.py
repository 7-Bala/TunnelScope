"""T-128 / EXP-48: verdicts as a Zeek TSV log and as Suricata-EVE-shaped JSON lines. The check against the real Zeek reader and the
real Suricata output is experiments/exp48-zeek-suricata/analyze.py (needs Docker); these tests pin the format rules without Docker."""
import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from tunnelscope.cli import main
from tunnelscope.siem import ecs, eve, export, zeek

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
AT = "2026-10-04T10:00:00Z"
SAMPLE = ["exp15/s-ecp256.pcap", "cloud/c-v1.pcap", "exp15/a-tra-sha1.pcap", "a7-cs-aes256gcm16.pcap"]
VERDICT = dict(baseline="B", rule_id="R-1", attribute="a", verdict="FAIL", severity="high", title="t", observed="o", message="m")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def unescape(cell: str):
    """A model of Zeek's reader for a string column: `-` is no value, \\xNN is that byte, the rest is literal."""
    if cell == zeek.UNSET:
        return None
    return re.sub(r"\\x([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), cell).encode("latin-1").decode("utf-8")


def parse(text: str):
    lines = text.splitlines()
    meta = {l.split("\t")[0][1:]: l.split("\t")[1:] for l in lines if l.startswith("#") and "\t" in l}
    rows = [l.split("\t") for l in lines if not l.startswith("#")]
    return meta, rows


@pytest.mark.parametrize("value,written", [
    (None, "-"), ("", "-"), ("plain", "plain"), ("a\tb", "a\\x09b"), ("a\nb", "a\\x0ab"), ("a\\b", "a\\x5cb"), ("-", "\\x2d"),
    ("(empty)", "\\x28empty)"), ("é", "\\xc3\\xa9"), ("x\u2028y", "x\\xe2\\x80\\xa8y"), ("\r", "\\x0d"), ("-x", "-x"),
])
def test_escape_follows_zeeks_writer_and_never_leaves_a_separator_or_newline(value, written):
    assert zeek.escape(value) == written
    assert not re.search(r"[\t\n\r\x00-\x1f\x7f-\uffff]", zeek.escape(value))


@pytest.mark.parametrize("value", ["a\tb\nc\\d", "-", "(empty)", "héllo ☃ \u2028 end", "\\x09", "x\\"])
def test_every_hostile_value_survives_the_round_trip_and_stays_one_cell(value):
    row = zeek.row({**VERDICT, "observed": value}, src="10.0.0.1", dst="10.0.0.2", sa="aa_bb", at=ecs.timestamp(AT))
    cells = row.split("\t")
    assert len(cells) == len(zeek.COLUMNS)
    assert unescape(cells[zeek.COLUMNS.index(("observed", "string"))]) == value


def test_empty_and_missing_values_are_unset_because_only_that_marker_round_trips():
    row = zeek.row({**VERDICT, "observed": "", "message": None}, src=None, dst="fe80::1%eth0", sa="?_?", at=ecs.timestamp(AT))
    cells = dict(zip((n for n, _ in zeek.COLUMNS), row.split("\t")))
    assert [cells[k] for k in ("id.orig_h", "id.resp_h", "ike_spi_i", "ike_spi_r", "observed", "message")] == ["-"] * 6


def test_header_is_the_zeek_ascii_log_header():
    meta, rows = parse(zeek.document([zeek.row(VERDICT, src="10.0.0.1", dst="10.0.0.2", sa="aa_bb", at=ecs.timestamp(AT))], ecs.timestamp(AT)))
    assert zeek.document([], AT).startswith("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\ttunnelscope\n")
    assert meta["path"] == ["tunnelscope"] and meta["open"] == ["2026-10-04-10-00-00"] and meta["close"] == ["2026-10-04-10-00-00"]
    assert meta["fields"] == [n for n, _ in zeek.COLUMNS] and meta["types"] == [t for _, t in zeek.COLUMNS]
    assert len(rows) == 1 and len(rows[0]) == len(zeek.COLUMNS)
    assert rows[0][0] == "1791108000.000000"


@pytest.mark.parametrize("name", SAMPLE)
def test_zeek_log_has_one_row_per_verdict_and_the_values_of_the_assessment(name):
    text = export.zeek_log(str(CAP / name), at=AT)
    _, rows = parse(text)
    want = list(export.verdicts(str(CAP / name)))
    assert len(rows) == len(want) > 0
    for cells, (v, ctx) in zip(rows, want):
        d = dict(zip((n for n, _ in zeek.COLUMNS), cells))
        assert (unescape(d["rule_id"]), unescape(d["verdict"]), unescape(d["baseline"])) == (v["rule_id"], v["verdict"], v["baseline"])
        assert d["id.orig_h"] == ctx["src"] and d["id.resp_h"] == ctx["dst"]


def test_a_verdict_other_than_pass_is_never_reported_as_pass_in_either_format():
    name = str(CAP / "a7-cs-aes256gcm16.pcap")
    got = {(v["rule_id"], v["verdict"]) for v, _ in export.verdicts(name)}
    z = {(unescape(c[zeek.COLUMNS.index(("rule_id", "string"))]), unescape(c[zeek.COLUMNS.index(("verdict", "string"))]))
         for c in parse(export.zeek_log(name, at=AT))[1]}
    e = {(j["tunnelscope"]["rule_id"], j["tunnelscope"]["verdict"]) for j in map(json.loads, export.eve_lines(name, at=AT))}
    assert z == e == got
    assert any(v != "PASS" for _, v in got)


EVE_TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+0000$")


@pytest.mark.parametrize("name", SAMPLE)
def test_eve_lines_have_suricatas_envelope_and_are_never_alerts(name):
    lines = export.eve_lines(str(CAP / name), at=AT)
    assert lines
    for line in lines:
        assert "\n" not in line
        j = json.loads(line)
        assert EVE_TS.match(j["timestamp"]) and j["timestamp"] == "2026-10-04T10:00:00.000000+0000"
        assert j["event_type"] == "tunnelscope" != "alert" and "alert" not in j
        assert isinstance(j.get("src_ip"), str) and isinstance(j.get("dest_ip"), str)
        assert not {"src_port", "dest_port", "proto", "flow_id"} & set(j)        # nothing a verdict does not have is invented
        assert j["tunnelscope"]["verdict"] in {"PASS", "FAIL", "UNKNOWN", "NOT_OBSERVABLE", "CONTRADICTORY"}


def test_eve_leaves_out_addresses_that_are_not_plain_ips_and_values_it_does_not_have():
    j = json.loads(eve.verdict_line({**VERDICT, "message": None}, file="f.pcap", src="fe80::1%eth0", dst=None, sa="?_?", at=ecs.timestamp(AT)))
    assert "src_ip" not in j and "dest_ip" not in j
    assert set(j["tunnelscope"]) == {"baseline", "rule_id", "attribute", "verdict", "severity", "title", "observed", "file"}


def test_observed_text_is_cut_like_the_ecs_export_in_both_new_formats():
    long = {**VERDICT, "observed": "x" * 3000}
    z = zeek.row(long, src="10.0.0.1", dst="10.0.0.2", sa="aa_bb", at=ecs.timestamp(AT)).split("\t")
    assert len(unescape(z[zeek.COLUMNS.index(("observed", "string"))])) == ecs.MAX_TEXT
    assert len(json.loads(eve.verdict_line(long, file="f", src="10.0.0.1", dst="10.0.0.2", sa="a_b", at=ecs.timestamp(AT)))["tunnelscope"]["observed"]) == ecs.MAX_TEXT


def test_spi_pair_is_split_from_the_sa_key_and_unknown_halves_are_unset():
    assert zeek._spis("6a40351269c748e6_e52016fd8d3f5989") == ("6a40351269c748e6", "e52016fd8d3f5989")
    assert zeek._spis("?_?") == (None, None) and zeek._spis("aa_?") == ("aa", None) and zeek._spis("") == (None, None)


def test_cli_writes_the_same_text_as_the_module_and_is_deterministic(tmp_path):
    name = str(CAP / "exp15/s-ecp256.pcap")
    rc, out, _ = _run(["export", name, "--format", "zeek", "--at", AT])
    assert rc == 0 and out == export.zeek_log(name, at=AT) == _run(["export", name, "--format", "zeek", "--at", AT])[1]
    rc, out, _ = _run(["export", name, "--format", "eve", "--at", AT])
    assert rc == 0 and out.splitlines() == export.eve_lines(name, at=AT)
    target = tmp_path / "tunnelscope.log"
    assert _run(["export", name, "--format", "zeek", "--at", AT, "-o", str(target)])[0] == 0
    assert target.read_text() == export.zeek_log(name, at=AT)


def test_only_fail_and_profiles_work_in_the_new_formats():
    name = str(CAP / "exp15/s-3des.pcap")
    z = parse(_run(["export", name, "--format", "zeek", "--only-fail", "--at", AT])[1])[1]
    assert z and all(unescape(c[zeek.COLUMNS.index(("verdict", "string"))]) == "FAIL" for c in z)
    n = len(export.eve_lines(name, at=AT))
    assert len(export.eve_lines(name, profiles=["nist-sp800-77r1"], at=AT)) > n


def test_bulk_index_still_needs_ecs():
    rc, _, err = _run(["export", str(CAP / "exp15/s-ecp256.pcap"), "--format", "zeek", "--bulk-index", "x"])
    assert rc != 0 and "ecs" in err
