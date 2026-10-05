"""T-128 (EXP-48): TunnelScope verdicts as a Zeek TSV log (`tunnelscope.log`).

Zeek has no IKE analyzer (9.0.0: `conn.log` shows UDP/500 with an empty `service`, ESP as `unknown_transport`), so there is nothing to
plug into on the detection side. This writes the log format every Zeek tool reads (`zeek-cut`, the input framework, any shipper that parses
Zeek logs) so TunnelScope's verdicts sit next to `conn.log`. It writes strings only; no connection, no script installed into a sensor.

`ts` is the assessment time (evidence records carry no absolute time), so rows join to `conn.log` by address pair and to Suricata by SPI
pair, never by a time window.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import ecs

PATH = "tunnelscope"
COLUMNS = [("ts", "time"), ("id.orig_h", "addr"), ("id.resp_h", "addr"), ("ike_spi_i", "string"), ("ike_spi_r", "string"),
           ("baseline", "string"), ("rule_id", "string"), ("attribute", "string"), ("verdict", "string"), ("severity", "string"),
           ("title", "string"), ("observed", "string"), ("message", "string")]
UNSET, EMPTY = "-", "(empty)"


def escape(value) -> str:
    """One string field, the way Zeek's ASCII writer escapes it and its reader undoes it: every byte outside printable ASCII and the
    backslash as \\xNN (UTF-8 bytes for non-ASCII), and a value that looks like the unset or empty marker gets its first byte escaped.
    An empty string is written as unset: the two mean the same for every column here and only the unset marker round-trips."""
    if value is None:
        return UNSET
    s = str(value)
    if s == "":
        return UNSET          # EXP-48 addendum A: Zeek's reader hands "(empty)" back as that literal text for a string field
    out = "".join(chr(b) if 0x20 <= b < 0x7F and b != 0x5C else f"\\x{b:02x}" for b in s.encode("utf-8"))
    if out in (UNSET, EMPTY):
        out = f"\\x{ord(out[0]):02x}{out[1:]}"
    return out


def _epoch(at: str) -> float:
    return datetime.fromisoformat(at.replace("Z", "+00:00")).timestamp()


def header(at: str) -> list[str]:
    opened = datetime.fromtimestamp(_epoch(at), timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
    return ["#separator \\x09", "#set_separator\t,", f"#empty_field\t{EMPTY}", f"#unset_field\t{UNSET}", f"#path\t{PATH}",
            f"#open\t{opened}", "#fields\t" + "\t".join(n for n, _ in COLUMNS), "#types\t" + "\t".join(t for _, t in COLUMNS)]


def footer(at: str) -> str:
    return "#close\t" + datetime.fromtimestamp(_epoch(at), timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")


def _spis(sa: str) -> tuple[str | None, str | None]:
    i, _, r = (sa or "").partition("_")
    return (None if i in ("", "?") else i), (None if r in ("", "?") else r)


def row(v: dict, *, src, dst, sa: str, at: str) -> str:
    """One verdict (`Verdict.to_dict()` plus where it came from) as one TSV row."""
    spi_i, spi_r = _spis(sa)
    obs, _ = ecs.as_text(v.get("observed"))
    cells = [f"{_epoch(at):.6f}", ecs.as_ip(src) or UNSET, ecs.as_ip(dst) or UNSET, escape(spi_i), escape(spi_r), escape(v["baseline"]),
             escape(v["rule_id"]), escape(v["attribute"]), escape(v["verdict"]), escape(v.get("severity", "medium")), escape(v["title"]),
             escape(obs), escape(v.get("message") or None)]
    return "\t".join(cells)


def document(rows: list[str], at: str) -> str:
    """The whole log file: header, rows, close line. The close line is written even with no rows, as Zeek does."""
    return "".join(line + "\n" for line in header(at) + rows + [footer(at)])
