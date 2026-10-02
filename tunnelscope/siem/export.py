"""T-129 (EXP-46): assess a capture and return one ECS document / one syslog line per verdict."""
from __future__ import annotations

import os

from ..assess.engine import assess_record, load_baselines
from ..evidence.extract import build_records
from ..pq.cbom import build_cbom
from . import ecs, syslog


def verdicts(pcap: str, profiles: list[str] | None = None, only_fail: bool = False):
    """Yield (verdict dict, context) for every verdict of every tunnel in the capture."""
    baselines = load_baselines(profiles=profiles)
    recs = [r for r in build_records(pcap)
            if getattr(r, "_ike", []) or getattr(r, "_esp", []) or getattr(r, "_ah", [])]
    summary = build_cbom(recs, source=pcap)["tunnelscope_sa_summary"] if recs else []
    for i, r in enumerate(recs):
        posture = summary[i]["quantum_posture"] if len(summary) == len(recs) else None
        ctx = {"file": os.path.basename(pcap), "src": r.src, "dst": r.dst, "sa": r.key(), "posture": posture}
        for v in assess_record(r, baselines):
            if only_fail and v.verdict != "FAIL":
                continue
            yield v.to_dict(), ctx


def ecs_documents(pcap: str, profiles=None, only_fail: bool = False, at=None) -> list[dict]:
    at = ecs.timestamp(at)
    return [ecs.verdict_event(v, at=at, **ctx) for v, ctx in verdicts(pcap, profiles, only_fail)]


def syslog_lines(pcap: str, profiles=None, only_fail: bool = False, at=None, hostname: str | None = None) -> list[str]:
    at = ecs.timestamp(at)
    return [syslog.verdict_line(v, at=at, hostname=hostname, file=ctx["file"], src=ctx["src"], dst=ctx["dst"], sa=ctx["sa"])
            for v, ctx in verdicts(pcap, profiles, only_fail)]
