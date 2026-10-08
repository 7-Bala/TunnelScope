"""T-134: continuous post-quantum / downgrade alerting on top of per-tunnel change detection (anomaly.py).

An alert is raised for a HIGH-severity posture change only: a downgrade (weaker key exchange, cipher, integrity
or IKE version, or a lost post-quantum key exchange) or a rule failing for the first time on that tunnel.
Medium changes, traffic shifts and model outliers stay in the analysis output; they are not alerts.

Formats, one alert per line, appended to a file a SIEM can tail:
- jsonl: one JSON object per line;
- ecs: Elastic Common Schema JSON (T-129, `siem/ecs.py`);
- syslog: RFC 5424, facility 13 (log audit), severity 3 (error), structured data under the enterprise number
  32473 reserved for documentation (RFC 5612) until the project has its own.
Nothing leaves the machine: TunnelScope writes the file; shipping it is the operator's choice.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone

ALERT_KINDS = ("downgrade", "new_failure")
FACILITY, SEVERITY, PEN = 13, 3, 32473


def alerts_from(results: list[dict], source: str, at: float | None = None) -> list[dict]:
    """observe() results -> alert dicts (high-severity posture changes only)."""
    ts = datetime.fromtimestamp(at, timezone.utc) if at is not None else datetime.now(timezone.utc)
    out = []
    for res in results:
        for a in res.get("anomalies", []):
            if a.get("kind") in ALERT_KINDS:     # posture-layer kinds; anomaly.py marks both "high"
                out.append({"time": ts.isoformat(timespec="seconds"), "tunnel": res["tunnel"], "source": source,
                            "kind": a["kind"], "attribute": a["attribute"], "usual": a.get("usual"),
                            "now": a.get("now"), "message": a["message"], "severity": "high"})
    return out


def _sd_value(v) -> str:
    """RFC 5424 PARAM-VALUE: escape '"', '\\' and ']'."""
    s = v if isinstance(v, str) else json.dumps(v, default=str)
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_alert(alert: dict, fmt: str = "jsonl", hostname: str | None = None) -> str:
    if fmt == "jsonl":
        return json.dumps(alert, default=str, sort_keys=True)
    if fmt == "syslog":
        host = (hostname or socket.gethostname() or "-").replace(" ", "_")[:255]
        sd = " ".join(f'{k}="{_sd_value(alert[k])}"' for k in ("tunnel", "kind", "attribute", "usual", "now"))
        return (f"<{FACILITY * 8 + SEVERITY}>1 {alert['time']} {host} tunnelscope - {alert['kind'].upper()} "
                f"[tunnelscope@{PEN} {sd}] {alert['message']}")
    if fmt == "ecs":                           # T-129: Elastic Common Schema JSON, one document per line
        from ..siem import ecs
        return ecs.dumps(ecs.alert_event(alert))
    raise ValueError(f"unknown alert format {fmt!r} (jsonl, syslog or ecs)")


def write_alerts(alerts: list[dict], path: str, fmt: str = "jsonl") -> int:
    if not alerts:
        return 0
    with open(path, "a", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(format_alert(a, fmt) + "\n")
    return len(alerts)
