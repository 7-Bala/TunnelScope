#!/usr/bin/env python3
"""EXP-32 analysis (PREREG.md): results/raw.jsonl, alerts.jsonl, reports/, collector-state/ -> results/summary.json.
Nothing is computed anywhere else; RESULT.md quotes summary.json only.

  .venv/bin/python experiments/exp32-site-sensor/analyze.py
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RES = HERE / "results"
sys.path.insert(0, str(HERE.parents[1]))

from tunnelscope.sensor import report as R  # noqa: E402

W = 10


def main() -> None:
    ev = [json.loads(line) for line in (RES / "raw.jsonl").read_text().splitlines() if line.strip()]
    changes = [e for e in ev if e["event"] == "change"]
    lat = [e["latency_s"] for e in changes if e["detected"]]
    out: dict = {"window_s": W, "changes": len(changes)}
    out["H1_detection"] = {"detected": sum(e["detected"] for e in changes), "of": len(changes),
                           "holds": bool(changes) and all(e["detected"] for e in changes) and len(changes) == 10}
    out["H2_latency_s"] = {"all": lat, "median": statistics.median(lat) if lat else None, "max": max(lat) if lat else None,
                           "holds": bool(lat) and len(lat) == len(changes)
                           and statistics.median(lat) <= W + 10 and max(lat) <= 2 * W + 15}
    alerts = [json.loads(line) for line in (RES / "alerts.jsonl").read_text().splitlines()] \
        if (RES / "alerts.jsonl").exists() else []
    spans = [(e["t_change"], e["t_change"] + 6 * W) for e in changes]
    false = [a for a in alerts if not any(s <= a["received"] <= t for s, t in spans)]
    out["H3_false_alerts"] = {"alerts_total": len(alerts), "outside_change_windows": len(false),
                              "examples": [{k: a[k] for k in ("kind", "attribute", "usual", "now", "source")} for a in false[:5]],
                              "holds": len(false) == 0}
    reports = sorted((RES / "reports").glob("*.json"))
    seqs = [json.loads(p.read_text())["seq"] for p in reports]
    st_file = RES / "collector-state" / "sites" / "lab.json"
    st = json.loads(st_file.read_text()) if st_file.exists() else {}
    quarantined = sorted(p.name for p in (RES / "collector-state" / "quarantine").glob("*.json")) \
        if (RES / "collector-state" / "quarantine").is_dir() else []
    left = next((e["files"] for e in ev if e["event"] == "inbox_left"), None)
    accepted = [e["seq"] for e in ev if e["event"] == "collector" and e.get("accepted")]
    out["H4_nothing_lost"] = {"written": len(seqs), "seq_range": [min(seqs), max(seqs)] if seqs else None,
                              "accepted": len(accepted), "accepted_unique": len(set(accepted)),
                              "collector_state": {k: st.get(k) for k in ("last_seq", "accepted", "missing")},
                              "quarantined": quarantined, "left_in_inbox": left,
                              "holds": bool(seqs) and sorted(accepted) == sorted(seqs) == list(range(1, len(seqs) + 1))
                              and not quarantined and not left and st.get("missing") == 0}
    bad = []
    kinds = {"window": 0, "heartbeat": 0}
    for p in reports:
        raw = p.read_bytes()
        try:
            rep = json.loads(raw)
            R.validate(rep, signed=True)
            kinds[rep["kind"]] += 1
            if b"\xd4\xc3\xb2\xa1" in raw or b"\xa1\xb2\xc3\xd4" in raw or b"\x0a\x0d\x0d\x0a" in raw:
                bad.append({"file": p.name, "why": "pcap/pcapng magic"})
        except (ValueError, R.ReportError) as e:
            bad.append({"file": p.name, "why": str(e)[:200]})
    out["H5_allow_list"] = {"reports": len(reports), "kinds": kinds, "failing": bad,
                            "max_report_bytes": max((p.stat().st_size for p in reports), default=0),
                            "holds": bool(reports) and not bad}
    out["ping_summary"] = next((e["text"] for e in ev if e["event"] == "ping_summary"), None)
    (RES / "summary.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
