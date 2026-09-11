"""TunnelScope CLI — the offline entry point (ADR-006).

  tunnelscope analyze <pcap> [--json]     build evidence records from a capture
"""
from __future__ import annotations

import argparse
import json
import sys

from .evidence.extract import build_records
from .ingest.tshark import capture_summary


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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tunnelscope")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="build evidence records from a pcap")
    a.add_argument("pcap")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_analyze)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
