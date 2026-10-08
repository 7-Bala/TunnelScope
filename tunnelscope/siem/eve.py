"""T-128 (EXP-48): TunnelScope verdicts as EVE-shaped JSON lines, for a stack that already collects Suricata's `eve.json`.

`event_type` is "tunnelscope", a custom type like Suricata's own "anomaly". It is deliberately NOT an `alert` event: Suricata did not
raise it, it has no signature id, and a FAIL here must never be counted as a Suricata detection. Only the common EVE fields that a verdict
really has are written (`timestamp`, `event_type`, `src_ip`, `dest_ip`); no port, protocol or flow id is invented. Join to Suricata's
`ike` events by the SPI pair (`init_spi`, `resp_spi`), to anything else by address pair.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import ecs, zeek

EVENT_TYPE = "tunnelscope"


def timestamp(at: str) -> str:
    """EVE's own format: %Y-%m-%dT%H:%M:%S.%f+0000 (UTC)."""
    return datetime.fromtimestamp(zeek._epoch(at), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


def verdict_line(v: dict, *, file: str, src, dst, sa: str, at: str) -> str:
    spi_i, spi_r = zeek._spis(sa)
    obs, _ = ecs.as_text(v.get("observed"))
    body = {"ike_spi_i": spi_i, "ike_spi_r": spi_r, "baseline": v["baseline"], "rule_id": v["rule_id"], "attribute": v["attribute"],
            "verdict": v["verdict"], "severity": v.get("severity", "medium"), "title": v["title"], "observed": obs,
            "message": v.get("message") or None, "file": file}
    doc = {"timestamp": timestamp(at), "event_type": EVENT_TYPE}
    if ecs.as_ip(src):
        doc["src_ip"] = ecs.as_ip(src)
    if ecs.as_ip(dst):
        doc["dest_ip"] = ecs.as_ip(dst)
    doc["tunnelscope"] = {k: x for k, x in body.items() if x is not None}
    return json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
