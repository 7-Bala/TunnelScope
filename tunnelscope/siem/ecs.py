"""T-129 (EXP-46): TunnelScope results as Elastic Common Schema (ECS) JSON documents.

Pure functions that turn a verdict or an alert into a dict. Nothing here opens a connection or writes a file:
shipping the documents (Filebeat, curl against `_bulk`, a log shipper) is the operator's choice, as for T-134 alerts.

Every field outside the custom `tunnelscope.*` namespace is a field of ECS (version below) and is checked against the
official `ecs_flat.yml` by `tests/test_siem_ecs.py`. Values whose type varies (`observed`, `usual`, `now`) are written
as JSON text so they can never cause a mapping conflict in the index.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone

ECS_VERSION = "9.5.0"
# Elastic's own severity scale for rules (low 21, medium 47, high 73, critical 99); "informational" shares "low".
SEVERITY = {"informational": 21, "low": 21, "medium": 47, "high": 73, "critical": 99}
# Only PASS is "success" and only FAIL is "failure". Anything TunnelScope could not decide is "unknown": absence of
# evidence is never reported as a pass.
OUTCOME = {"PASS": "success", "FAIL": "failure"}
MAX_TEXT = 1000          # ECS keyword fields drop values over 1024 characters; never let that happen silently
OBSERVER = {"vendor": "TunnelScope", "product": "TunnelScope"}


def version() -> str:
    from importlib.metadata import PackageNotFoundError, version as _v
    try:
        return _v("tunnelscope")
    except PackageNotFoundError:
        return "unknown"


def timestamp(at: datetime | float | int | str | None = None) -> str:
    """UTC ISO 8601 with a Z suffix, to the second. None = now."""
    if at is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(at, datetime):
        dt = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
    elif isinstance(at, (int, float)):
        dt = datetime.fromtimestamp(at, timezone.utc)
    else:
        s = str(at).strip()
        try:
            dt = datetime.fromtimestamp(float(s), timezone.utc)
        except ValueError:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_ip(value) -> str | None:
    """The address as a string when it is a plain IP (the only thing an ECS `ip` field accepts), else None."""
    try:
        if isinstance(value, str) and "%" not in value:
            return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        pass
    return None


def as_text(value) -> tuple[str, bool]:
    """JSON text for any value, cut at MAX_TEXT. Returns (text, truncated)."""
    s = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    return (s[:MAX_TEXT], True) if len(s) > MAX_TEXT else (s, False)


def _ends(doc: dict, src, dst) -> None:
    for side, val in (("source", src), ("destination", dst)):
        if val in (None, ""):
            continue
        doc[side] = {"address": str(val)}
        ip = as_ip(val)
        if ip:
            doc[side]["ip"] = ip


def _event_id(*parts) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:32]


def verdict_event(v: dict, *, file: str, src, dst, sa: str, posture: str | None = None, at=None) -> dict:
    """One verdict of one tunnel (`Verdict.to_dict()` plus where it came from)."""
    verdict = v["verdict"]
    obs, cut = as_text(v.get("observed"))
    doc = {
        "@timestamp": timestamp(at),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert" if verdict == "FAIL" else "state",
            "category": ["network", "configuration"],
            "type": ["info"],
            "dataset": "tunnelscope.verdict",
            "module": "tunnelscope",
            "provider": "tunnelscope",
            "action": "assess",
            "outcome": OUTCOME.get(verdict, "unknown"),
            "severity": SEVERITY.get(v.get("severity", "medium"), 47),
            "id": _event_id(file, sa, v["baseline"], v["rule_id"]),
        },
        "message": f"{v['rule_id']}: {verdict} - {v['title']}" + (f" ({v['message']})" if v.get("message") else ""),
        "observer": {**OBSERVER, "version": version()},
        "file": {"name": file},
        "rule": {"id": v["rule_id"], "name": v["title"], "ruleset": v["baseline"], "description": v["authority"]},
        "tunnelscope": {"verdict": verdict, "severity": v.get("severity", "medium"), "attribute": v["attribute"],
                        "observed": obs, "baseline": v["baseline"], "sa": sa},
    }
    if v.get("message"):
        doc["event"]["reason"] = v["message"][:MAX_TEXT]
    if cut:
        doc["tunnelscope"]["observed_truncated"] = True
    if src is not None and dst is not None:
        doc["tunnelscope"]["tunnel"] = f"{src} <-> {dst}"
    if posture:
        doc["tunnelscope"]["posture"] = posture
    _ends(doc, src, dst)
    return doc


def alert_event(a: dict) -> dict:
    """One T-134 alert (`alerts_from()` output; the collector adds `site`)."""
    usual, _ = as_text(a.get("usual"))
    now, _ = as_text(a.get("now"))
    tun = str(a.get("tunnel", ""))
    doc = {
        "@timestamp": timestamp(a.get("time")),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert",
            "category": ["configuration"],          # ECS allows event.type "change" only with this category
            "type": ["change"],
            "dataset": "tunnelscope.alert",
            "module": "tunnelscope",
            "provider": "tunnelscope",
            "action": a["kind"],
            "severity": SEVERITY.get(a.get("severity", "high"), 73),
            "reason": str(a.get("message", ""))[:MAX_TEXT],
            "id": _event_id(a.get("site", ""), a.get("source", ""), tun, a["kind"], a.get("attribute"), a.get("time")),
        },
        "message": str(a.get("message", "")),
        "observer": {**OBSERVER, "version": version()},
        "tunnelscope": {"alert": {"kind": a["kind"], "attribute": a.get("attribute", ""), "usual": usual, "now": now,
                                  "tunnel": tun, "source": str(a.get("source", ""))}},
    }
    if a.get("site"):
        doc["observer"]["name"] = str(a["site"])
    if " <-> " in tun:
        _ends(doc, *tun.split(" <-> ", 1))
    return doc


def dumps(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
