"""T-129 (EXP-46): TunnelScope verdicts as RFC 5424 syslog lines, and a strict RFC 5424 parser to check any line.

Same conventions as the T-134 alert lines (`anomaly/alerts.py`): facility 13 (log audit), structured-data id
`tunnelscope@32473` (32473 is the enterprise number reserved for documentation, RFC 5612). The severity follows the
verdict: a failed rule is error / warning / notice by its own severity, everything else is informational.
One line per verdict, no embedded line breaks.
"""
from __future__ import annotations

import platform
import re

from .ecs import as_text, timestamp

FACILITY, PEN = 13, 32473
FAIL_SEVERITY = {"high": 3, "medium": 4, "informational": 5, "low": 5, "critical": 2}   # RFC 5424 table 2
OTHER_SEVERITY = 6                                                                      # informational


def _clean(s: str) -> str:
    """No control characters: a syslog line is one line."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", s)


def _sd(v) -> str:
    """RFC 5424 PARAM-VALUE: UTF-8 with '"', '\\' and ']' escaped."""
    s = _clean(v if isinstance(v, str) else as_text(v)[0])
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def host(name: str | None = None) -> str:
    h = name or platform.node() or "-"
    h = "".join(c for c in h if 33 <= ord(c) <= 126)[:255]       # PRINTUSASCII only
    return h or "-"


def verdict_line(v: dict, *, file: str, src, dst, sa: str, at=None, hostname: str | None = None) -> str:
    verdict = v["verdict"]
    sev = FAIL_SEVERITY.get(v.get("severity", "medium"), 4) if verdict == "FAIL" else OTHER_SEVERITY
    params = {"rule": v["rule_id"], "baseline": v["baseline"], "verdict": verdict, "severity": v.get("severity", "medium"),
              "attribute": v["attribute"], "observed": as_text(v.get("observed"))[0], "sa": sa, "file": file}
    if src is not None and dst is not None:
        params["tunnel"] = f"{src} <-> {dst}"
    sd = " ".join(f'{k}="{_sd(val)}"' for k, val in params.items())
    msg = _clean(f"{v['rule_id']}: {verdict} - {v['title']}" + (f" ({v['message']})" if v.get("message") else ""))
    return f"<{FACILITY * 8 + sev}>1 {timestamp(at)} {host(hostname)} tunnelscope - {verdict[:32]} [tunnelscope@{PEN} {sd}] {msg}"


# ---------------------------------------------------------------- strict parser (RFC 5424 section 6)
_PU = r"[\x21-\x7e]"
_HEADER = re.compile(rf"<(\d{{1,3}})>([1-9]\d{{0,2}}) (-|\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d{{1,6}})?(?:Z|[+-]\d{{2}}:\d{{2}})) "
                     rf"(-|{_PU}{{1,255}}) (-|{_PU}{{1,48}}) (-|{_PU}{{1,128}}) (-|{_PU}{{1,32}}) ")
_SD_ID = r"[^\s=\]\"\x00-\x20\x7f-￿]{1,32}"
_SD_PARAM = re.compile(rf'({_SD_ID})="((?:[^"\\\]]|\\["\\\]])*)"')
_SD_EL = re.compile(rf"\[({_SD_ID})((?: {_SD_ID}=\"(?:[^\"\\\]]|\\[\"\\\]])*\")*)\]")


def parse(line: str) -> dict:
    """Parse one RFC 5424 line; raise ValueError naming what is wrong. Returns the parts, structured data decoded."""
    m = _HEADER.match(line)
    if not m:
        raise ValueError("header does not match RFC 5424 (PRI VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID)")
    pri, ver, ts, hostname, app, procid, msgid = m.groups()
    if int(pri) > 191:
        raise ValueError(f"PRI {pri} is above 191")
    if len(pri) > 1 and pri.startswith("0"):
        raise ValueError("PRI has a leading zero")
    rest = line[m.end():]
    sd: dict[str, dict[str, str]] = {}
    if rest.startswith("-"):
        rest = rest[1:]
    else:
        pos = 0
        while pos < len(rest) and rest[pos] == "[":
            e = _SD_EL.match(rest, pos)
            if not e:
                raise ValueError(f"malformed structured-data element at offset {pos}")
            sd.setdefault(e.group(1), {}).update(
                {k: re.sub(r'\\(["\\\]])', r"\1", val) for k, val in _SD_PARAM.findall(e.group(2))})
            pos = e.end()
        if not sd:
            raise ValueError("structured data is neither '-' nor an element")
        rest = rest[pos:]
    if rest and not rest.startswith(" "):
        raise ValueError("no space between structured data and message")
    msg = rest[1:]
    if re.search(r"[\r\n]", line):
        raise ValueError("embedded line break")
    return {"pri": int(pri), "facility": int(pri) // 8, "severity": int(pri) % 8, "version": int(ver), "timestamp": ts,
            "hostname": hostname, "app": app, "procid": procid, "msgid": msgid, "sd": sd, "msg": msg}
