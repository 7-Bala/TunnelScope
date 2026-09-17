"""TunnelScope CLI — the offline entry point (ADR-006).

  tunnelscope analyze <pcap> [--json]     build evidence records from a capture
  tunnelscope serve [--port N]            local dashboard: drop pcaps in a browser tab (T-059)
"""
from __future__ import annotations

import argparse
import json
import sys

from .evidence.extract import build_records
from .ingest.tshark import capture_summary
from .assess.engine import assess_record, load_baselines
from .pq.cbom import build_cbom
from .report.report import analyze, executive_report, technical_report
from .report.dashboard import render as render_dashboard
from .report.fleet import render as render_fleet, render_json as fleet_json


def cmd_analyze(args):
    summ = capture_summary(args.pcap)
    recs = build_records(args.pcap)
    if args.json:
        print(json.dumps({"summary": summ, "records": [r.to_dict() for r in recs]}, indent=2))
        return
    print(f"# {args.pcap}")
    print(f"  IKE messages: {summ['n_ike']} | ESP packets: {summ['n_esp']} | exchanges: {', '.join(summ['exchanges']) or 'none'}")
    for r in recs:
        if not getattr(r, "_ike", []) and not getattr(r, "_esp", []):
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
        if not getattr(r, "_ike", []) and not getattr(r, "_esp", []):
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


def cmd_cbom(args):
    import json as _j
    print(_j.dumps(build_cbom(build_records(args.pcap), source=args.pcap), indent=2))


def cmd_report(args):
    a = analyze(args.pcap)
    if args.level in ("exec", "both"):
        print(executive_report(a))
    if args.level == "both":
        print("\n\n")
    if args.level in ("tech", "both"):
        print(technical_report(a))


def cmd_dashboard(args):
    open(args.out, "w").write(render_dashboard(args.pcap))
    print(f"wrote {args.out}")


def cmd_crosstier(args):
    from .crosstier.crosstier import load_telemetry, crosstier_records
    recs = build_records(args.pcap)
    tel = load_telemetry(args.telemetry)
    results = crosstier_records(recs, tel)
    if args.json:
        print(json.dumps({sa: [c.__dict__ for c in cks] for sa, cks in results.items()}, indent=2, default=str))
        return
    glyph = {"escalation": "↑", "confirmation": "=", "contradiction": "✗", "new": "+"}
    print(f"# cross-tier reconciliation: {args.pcap}  ×  {args.telemetry}")
    for sa, cks in results.items():
        print(f"\n  SA {sa}")
        for c in cks:
            print(f"    [{glyph.get(c.outcome,'?')}] {c.outcome:13} {c.attribute:20} {c.note}")
        if any(c.outcome == "contradiction" for c in cks):
            print("    ! config and wire diverge — see CONTRADICTORY findings above")


def cmd_serve(args):
    from .api.server import run_server
    run_server(port=args.port, open_browser=not args.no_browser)


def cmd_fleet(args):
    if args.json:
        print(json.dumps(fleet_json(args.directory), indent=2, default=str))
        return
    open(args.out, "w").write(render_fleet(args.directory))
    print(f"wrote {args.out}")


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
    cb = sub.add_parser("cbom", help="emit a CycloneDX CBOM for a pcap")
    cb.add_argument("pcap")
    cb.set_defaults(func=cmd_cbom)
    rp = sub.add_parser("report", help="executive + technical report for a pcap")
    rp.add_argument("pcap"); rp.add_argument("--level", choices=["exec","tech","both"], default="both")
    rp.set_defaults(func=cmd_report)
    db = sub.add_parser("dashboard", help="self-contained HTML dashboard")
    db.add_argument("pcap"); db.add_argument("-o", "--out", default="tunnelscope-dashboard.html")
    db.set_defaults(func=cmd_dashboard)
    ct = sub.add_parser("crosstier", help="reconcile T2 endpoint telemetry against passive findings (Stage 3, C5)")
    ct.add_argument("pcap"); ct.add_argument("telemetry", help="T2 telemetry file (JSON or key: value)")
    ct.add_argument("--json", action="store_true")
    ct.set_defaults(func=cmd_crosstier)
    sv = sub.add_parser("serve", help="local dashboard: open a page, drop in pcaps, see findings (127.0.0.1 only, uploads not saved)")
    sv.add_argument("--port", type=int, default=8765)
    sv.add_argument("--no-browser", action="store_true", help="don't auto-open a browser tab")
    sv.set_defaults(func=cmd_serve)
    fl = sub.add_parser("fleet", help="scan a directory of captures: one aggregated view, per-tunnel evidence kept intact (role B/D)")
    fl.add_argument("directory")
    fl.add_argument("-o", "--out", default="tunnelscope-fleet.html")
    fl.add_argument("--json", action="store_true")
    fl.set_defaults(func=cmd_fleet)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
