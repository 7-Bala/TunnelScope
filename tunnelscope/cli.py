"""TunnelScope CLI — the offline entry point (ADR-006).

  tunnelscope analyze <pcap> [--json]     build evidence records from a capture
"""
from __future__ import annotations

import argparse
import json
import sys

from .evidence.extract import build_records
from .ingest.tshark import capture_summary
from .assess.engine import assess_record, load_baselines


def cmd_analyze(args):
    summ = capture_summary(args.pcap)
    recs = build_records(args.pcap)
    if args.json:
        print(json.dumps({"summary": summ, "records": [r.to_dict() for r in recs]}, indent=2))
        return
    print(f"# {args.pcap}")
    print(f"  IKE messages: {summ['n_ike']} | ESP packets: {summ['n_esp']} | exchanges: {', '.join(summ['exchanges']) or 'none'}")
    for r in recs:
        if not getattr(r, "_ike", []):
            continue
        print(f"\n  SA {r.key()}  ({r.src} <-> {r.dst})")
        for attr, f in r.findings.items():
            v = "" if f.value is None else f"= {f.value}"
            print(f"    {attr:22} {f.status.value:15} {v:30}  [{f.vantage.value}] {f.method}")
            if f.note and f.status.name in ("NOT_OBSERVABLE", "UNKNOWN", "CONTRADICTORY"):
                print(f"        └ {f.note}")


def cmd_assess(args):
    baselines = load_baselines()
    recs = build_records(args.pcap)
    all_v = []
    for r in recs:
        if not getattr(r, "_ike", []):
            continue
        vs = assess_record(r, baselines)
        all_v += [v.to_dict() for v in vs]
        if args.json:
            continue
        print(f"\n# {args.pcap}  SA {r.key()}  ({r.src} <-> {r.dst})")
        mark = {"PASS": "PASS ", "FAIL": "FAIL ", "UNKNOWN": "UNK  ",
                "NOT_OBSERVABLE": "N/OBS", "CONTRADICTORY": "CONTR"}
        for v in vs:
            obs = "" if v.observed is None else f"({v.observed})"
            print(f"  [{mark[v.verdict]}] {v.baseline:18} {v.rule_id:16} {v.attribute} {obs}")
            if v.verdict == "FAIL":
                print(f"          → {v.message}  [{v.severity}] — {v.authority.split(' - ')[0].split(',')[0]}")
    if args.json:
        import json as _j; print(_j.dumps(all_v, indent=2))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tunnelscope")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="build evidence records from a pcap")
    a.add_argument("pcap")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_analyze)
    s = sub.add_parser("assess", help="assess a pcap against named baselines")
    s.add_argument("pcap"); s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_assess)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
