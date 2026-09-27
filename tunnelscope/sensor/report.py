"""Site sensor reports (T-139): what a site sends to the central collector, and nothing else.

A report is built from one analysed live window by an explicit ALLOW-LIST: tunnel addresses and IKE SPIs, posture,
failed rule ids, findings (status and protocol-derived value), gaps, anomalies, alerts and the risk score. Packet
bytes, payloads, file paths and free text from the capture are never copied; `validate` rejects any key outside the
schema and any over-long string, so a report cannot grow a new field by accident.

Integrity: HMAC-SHA256 over the canonical JSON (sorted keys, no spaces) with a per-site key, plus a sequence number
that only increases, so the collector can reject a changed, foreign or replayed report. Python standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

SCHEMA = "tunnelscope.sensor-report/1"
MAX_STRING = 300          # longest string a report may carry (rule titles are not sent; ids are)
MAX_VALUE_JSON = 2000     # a finding value (algorithm names, counts) is small; anything bigger is refused

REPORT_KEYS = {"schema", "site", "seq", "kind", "window_s", "window_end", "sent_at", "tool_version", "ok",
               "error", "tunnels", "alerts", "sig"}
TUNNEL_KEYS = {"src", "dst", "ike_spi", "posture", "fails", "verdict_counts", "gaps", "findings", "anomaly", "risk"}
FAIL_KEYS = {"rule_id", "baseline", "severity"}
GAP_KEYS = {"attribute", "status"}
FINDING_KEYS = {"attribute", "status", "value", "confidence"}
ANOMALY_KEYS = {"status", "anomalies"}
ANOMALY_ITEM_KEYS = {"kind", "attribute", "severity", "usual", "now"}
RISK_KEYS = {"score", "band", "coverage"}
ALERT_KEYS = {"time", "tunnel", "kind", "attribute", "usual", "now", "severity"}
KINDS = ("window", "heartbeat")


class ReportError(ValueError):
    """A report that must not be accepted; the message says why (never the report's own text)."""


# ------------------------------------------------------------------ keys

def new_key() -> str:
    return secrets.token_hex(32)


def write_key(path: str | Path) -> Path:
    """Create a site key file readable by its owner only. Never printed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(new_key() + "\n")
    return p


def read_key(path: str | Path) -> bytes:
    k = Path(path).read_text().strip()
    if len(k) < 32:
        raise ReportError(f"key file {Path(path).name} is too short")
    return k.encode()


# ------------------------------------------------------------------ build (allow-list)

def _pick(d: dict, keys: set) -> dict:
    return {k: d.get(k) for k in keys if k in d}


def _tunnel(sa: dict) -> dict:
    counts: dict[str, int] = {}
    for v in sa.get("verdicts") or []:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    an = sa.get("anomaly")
    risk = (sa.get("risk") or {}).get("risk") or {}
    return {
        "src": sa.get("src"), "dst": sa.get("dst"), "ike_spi": sa.get("ike_spi"), "posture": sa.get("posture"),
        "fails": [_pick(f, FAIL_KEYS) for f in sa.get("fails") or []],
        "verdict_counts": counts,
        "gaps": [_pick(g, GAP_KEYS) for g in sa.get("gaps") or []],
        "findings": [_pick(f, FINDING_KEYS) for f in sa.get("findings") or []],
        "anomaly": None if an is None else {"status": an.get("status"),
                                            "anomalies": [_pick(a, ANOMALY_ITEM_KEYS) for a in an.get("anomalies") or []]},
        "risk": _pick(risk, RISK_KEYS),
    }


def build_report(site: str, seq: int, window_s: int, row: dict | None, tool_version: str,
                 now: float | None = None) -> dict:
    """One report from one live window row (LiveMonitor.process), or a heartbeat when row is None."""
    now = time.time() if now is None else now
    rep: dict[str, Any] = {"schema": SCHEMA, "site": site, "seq": seq, "window_s": window_s, "sent_at": now,
                           "tool_version": tool_version}
    if row is None:
        rep.update(kind="heartbeat", window_end=None, ok=True, error=None, tunnels=[], alerts=[])
    else:
        rep.update(kind="window", window_end=row.get("at"), ok=bool(row.get("ok")),
                   error=(row.get("error") or "")[:MAX_STRING] or None,
                   tunnels=[_tunnel(sa) for sa in row.get("sas") or []],
                   alerts=[_pick(a, ALERT_KEYS) for a in row.get("alert_items") or []])
    validate(rep, signed=False)
    return rep


# ------------------------------------------------------------------ validate

def _strings_ok(x: Any, where: str) -> None:
    if isinstance(x, str):
        if len(x) > MAX_STRING:
            raise ReportError(f"{where}: string longer than {MAX_STRING}")
    elif isinstance(x, dict):
        for k, v in x.items():
            _strings_ok(k, where)
            _strings_ok(v, f"{where}.{k}")
    elif isinstance(x, list):
        for i, v in enumerate(x):
            _strings_ok(v, f"{where}[{i}]")
    elif not (x is None or isinstance(x, (bool, int, float))):
        raise ReportError(f"{where}: unsupported type {type(x).__name__}")


def _only(d: Any, keys: set, where: str) -> None:
    if not isinstance(d, dict):
        raise ReportError(f"{where}: not an object")
    extra = set(d) - keys
    if extra:
        raise ReportError(f"{where}: field(s) not allowed: {', '.join(sorted(extra))}")


def validate(rep: Any, signed: bool = True) -> None:
    """Strict allow-list check. Raises ReportError."""
    _only(rep, REPORT_KEYS if signed else REPORT_KEYS - {"sig"}, "report")
    missing = (REPORT_KEYS - {"sig"} if not signed else REPORT_KEYS) - set(rep)
    if missing:
        raise ReportError(f"report: missing field(s): {', '.join(sorted(missing))}")
    if rep["schema"] != SCHEMA or rep["kind"] not in KINDS:
        raise ReportError("report: unknown schema or kind")
    if not isinstance(rep["seq"], int) or isinstance(rep["seq"], bool) or rep["seq"] < 1:
        raise ReportError("report: seq must be a positive integer")
    if not isinstance(rep["site"], str) or not rep["site"] or not all(c.isalnum() or c in "-_." for c in rep["site"]):
        raise ReportError("report: site must be letters, digits, '-', '_' or '.'")
    for i, t in enumerate(rep["tunnels"]):
        w = f"tunnels[{i}]"
        _only(t, TUNNEL_KEYS, w)
        for f in t.get("fails") or []:
            _only(f, FAIL_KEYS, f"{w}.fails")
        for g in t.get("gaps") or []:
            _only(g, GAP_KEYS, f"{w}.gaps")
        for f in t.get("findings") or []:
            _only(f, FINDING_KEYS, f"{w}.findings")
            if len(json.dumps(f.get("value"))) > MAX_VALUE_JSON:
                raise ReportError(f"{w}.findings: value too large")
        if t.get("anomaly") is not None:
            _only(t["anomaly"], ANOMALY_KEYS, f"{w}.anomaly")
            for a in t["anomaly"].get("anomalies") or []:
                _only(a, ANOMALY_ITEM_KEYS, f"{w}.anomaly.anomalies")
        _only(t.get("risk") or {}, RISK_KEYS, f"{w}.risk")
    for a in rep["alerts"]:
        _only(a, ALERT_KEYS, "alerts")
    _strings_ok({k: v for k, v in rep.items() if k != "sig"}, "report")


# ------------------------------------------------------------------ sign / verify

def canonical(rep: dict) -> bytes:
    return json.dumps({k: v for k, v in rep.items() if k != "sig"}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode()


def sign(rep: dict, key: bytes) -> dict:
    return {**rep, "sig": hmac.new(key, canonical(rep), hashlib.sha256).hexdigest()}


def verify(rep: dict, key: bytes) -> None:
    """Raises ReportError unless the signature matches (constant-time compare) and the report validates."""
    sig = rep.get("sig") if isinstance(rep, dict) else None
    if not isinstance(sig, str) or not hmac.compare_digest(sig, hmac.new(key, canonical(rep), hashlib.sha256).hexdigest()):
        raise ReportError("signature does not match (changed in transit, or signed with another key)")
    validate(rep, signed=True)
