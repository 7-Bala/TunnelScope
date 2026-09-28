"""TunnelScope CLI — the offline entry point (ADR-006).

  tunnelscope analyze <pcap> [--json]     build evidence records from a capture
  tunnelscope serve [--port N]            local dashboard: drop pcaps in a browser tab (T-059)

Exit codes (so an automated caller can tell the cases apart):
  0  ran, nothing to report
  1  ran, FAIL verdicts present (only with --fail-on-findings)
  2  input error — missing capture, bad directory, no captures found
  3  dependency error — tshark missing, or drifted away from a field we read
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .errors import TunnelScopeError
from .evidence.extract import build_records
from .ingest.tshark import capture_summary, preflight, REQUIRED_FIELDS
from .assess.engine import assess_record, load_baselines
from .pq.cbom import to_cyclonedx
from .report.report import analyze, executive_report, technical_report
from .report.dashboard import render as render_dashboard
from .report.fleet import render as render_fleet, render_json as fleet_json, scan as fleet_scan


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


def _version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("tunnelscope")
    except PackageNotFoundError:
        return "unknown (not installed)"


def cmd_assess(args):
    baselines = load_baselines(profiles=args.profile)
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
        print(json.dumps(all_v, indent=2))
    if getattr(args, "fail_on_findings", False) and any(v["verdict"] == "FAIL" for v in all_v):
        return 1
    return 0


def cmd_cbom(args):
    import json as _j
    print(_j.dumps(to_cyclonedx(build_records(args.pcap), source=args.pcap), indent=2))


def cmd_report(args):
    a = analyze(args.pcap)
    if args.level in ("exec", "both"):
        print(executive_report(a))
    if args.level == "both":
        print("\n\n")
    if args.level in ("tech", "both"):
        print(technical_report(a))
    print("\n" + _known_vulnerabilities_text(a))


def _known_vulnerabilities_text(a) -> str:
    """DEC-045: known vulnerabilities for the identified software, next to the rule verdicts (never a verdict)."""
    from .intel.lookup import known_vulnerabilities
    out = ["## Known vulnerabilities (INFERRED: some version of the identified software)"]
    for i, sa in enumerate(a["sas"], 1):
        kv = known_vulnerabilities(sa["record"].findings)
        out.append(f"SA {i}: {kv['note']}")
        for p in kv["products"]:
            c = p["counts"]
            src = ", ".join(f"{k} {v}" for k, v in p["sources"].items())
            out.append(f"  {p['implementation']} ({'/'.join(p['ends'])}): {c.get('total', 0)} known CVEs, "
                       f"{c.get('kev', 0)} actively exploited (CISA KEV); sources: {src}")
            for e in p["top"][:5]:
                out.append(f"    {e['id']}  CVSS {e['cvss'] if e['cvss'] is not None else '-'}"
                           f"{'  KEV' if e['kev'] else ''}  [{e['match']}]  {e['description'][:110]}")
    return "\n".join(out)


def cmd_dashboard(args):
    with open(args.out, "w") as fh:
        fh.write(render_dashboard(args.pcap))
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
    run_server(port=args.port, open_browser=not args.no_browser, history=args.history,
               live_follow=args.live_follow, live_interface=args.live_interface, live_window=args.window)


def cmd_live(args):
    """Analyse a live stream window by window (interface ring buffer or a sensor's rotating files)."""
    from .live.live import LiveMonitor
    if args.alerts and not args.history:
        print("--alerts needs --history (alerts compare each window with the tunnel's learned normal)", file=sys.stderr)
        return 2
    mon = LiveMonitor(interface=args.interface, follow=args.follow, window=args.window,
                      history=args.history, keep=args.keep, alerts=args.alerts, alert_format=args.alert_format,
                      headers_only=args.headers_only)
    mon.start_capture()
    print(f"live: {mon.status()['source']}, {mon.window}s windows"
          + (f", learning into {args.history}" if args.history else "") + " (Ctrl-C stops)", file=sys.stderr)

    def show(row):
        if args.json:
            print(json.dumps(row, default=str), flush=True)
            return
        if not row["ok"]:
            print(f"{row['file']}: ERROR {row['error']}", flush=True)
            return
        if not row["n_sas"]:
            print(f"{row['file']}: no IPsec traffic in this window", flush=True)
        for sa in row["sas"]:
            rk = sa["risk"]["risk"]
            an = sa.get("anomaly") or {}
            tag = {"anomalous": "  CHANGED", "learning": "  learning", "normal": ""}.get(an.get("status"), "")
            print(f"{row['file']}: {sa['src']} <-> {sa['dst']}  risk {rk['score']} ({rk['band']}){tag}", flush=True)
            for x in an.get("anomalies", []):
                if x["severity"] != "informational":
                    print(f"      [{x['severity']}] {x['message']}", flush=True)
    try:
        mon.run(on_window=show, max_windows=args.max_windows)
    except KeyboardInterrupt:
        pass
    finally:
        mon.stop()


def _captures(target: str) -> list[str]:
    from pathlib import Path
    p = Path(target)
    if p.is_dir():
        return sorted(str(x) for x in p.rglob("*") if x.suffix in (".pcap", ".pcapng"))
    return [target]


def cmd_watch(args):
    """Detect changes against each tunnel's learned normal, then record."""
    from .anomaly.anomaly import History, observe
    h = History(args.history)
    out, worst = [], 0
    for f in _captures(args.target):
        a = analyze(f)
        results = observe(h, a["sas"], f, record=not args.no_record)
        if args.alerts:
            from .anomaly.alerts import alerts_from, write_alerts
            write_alerts(alerts_from(results, f, os.path.getmtime(f)), args.alerts, args.alert_format)
        for res in results:
            out.append({"source": f, **res})
            worst = max(worst, 1 if res["status"] == "anomalous" else 0)
    if args.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        for r in out:
            tag = {"learning": f"learning ({r['observations']}/{r.get('needed', '?')})",
                   "normal": "normal", "anomalous": "ANOMALOUS"}[r["status"]]
            print(f"{os.path.basename(r['source'])}  {r['tunnel']}  {tag}")
            for x in r["anomalies"]:
                print(f"    [{x['severity']}/{x['layer']}] {x['message']}")
    return 1 if (args.fail_on_anomaly and worst) else 0


def cmd_explain(args):
    from .api.server import analysis_json
    from .explain.explain import as_text, explain_sa
    local_llm = True if getattr(args, "local_llm", False) else None
    a = analyze(args.pcap)
    for sa in analysis_json(a, args.pcap)["sas"]:
        print(as_text(explain_sa(sa, local_llm=local_llm)))
        print()


def cmd_doctor(args):
    """Report the analysis stack this install would actually use."""
    info = preflight()
    print(f"tunnelscope       {_version()}")
    print(f"tshark            {info['tshark_version']}  ({info['tshark']})")
    print(f"required fields   all {len(REQUIRED_FIELDS)} resolve on this tshark")
    bl = load_baselines()
    print(f"baselines         {len(bl)} loaded: {', '.join(sorted(b['baseline'] for b in bl))}")
    from .ingest.tshark import isolation_status
    iso = isolation_status()
    print(f"tshark isolation  network {iso['network']}; limits: {iso['limits']}; {iso['profile']}; "
          f"name resolution {iso['name_resolution']}")
    print("\nready: evidence extraction will not silently under-report on this stack.")
    return 0


def cmd_config(args):
    """T-120: read an IPsec configuration file (offline) into the normalised crypto model."""
    from .config import parse_file
    d = parse_file(args.file)
    if args.json:
        print(json.dumps(d, indent=2))
        return 0 if d["format"] else 1
    if not d["format"]:
        print(f"{args.file}: " + "; ".join(d["unknown"]))
        return 1
    def one(p):
        parts = [", ".join(p[k]) for k in ("encr", "integ", "prf", "ke") if p.get(k)]
        parts += [f"ADDKE{n} {', '.join(v)}" for n, v in sorted(p["addke"].items())]
        return " / ".join(parts) + f"  ({p['text']})" + (f"  [NOT UNDERSTOOD: {', '.join(p['unknown'])}]" if p["unknown"] else "")
    fmt = lambda props: " | ".join(one(p) for p in props) or "(implementation default, not known to TunnelScope)"
    print(f"{args.file}: {d['format']}, {len(d['tunnels'])} connection(s)")
    for t in d["tunnels"]:
        print(f"\n  {t['name']}  {t['ike_version'] or 'IKE version not set'}  {t['local_addrs'] or '?'} -> {t['remote_addrs'] or '?'}")
        print(f"    IKE: {fmt(t['ike_proposals'])}")
        if t["ppk"]:
            print(f"    PPK: id {t['ppk']['id']}, {'required' if t['ppk']['required'] else 'optional'}")
        for c in t["children"]:
            pfs = {True: "PFS on", False: "PFS off", None: "PFS not set"}[c["pfs"]]
            print(f"    child {c['name']} ({c['mode']}, {pfs}): {fmt(c['esp_proposals'] + c['ah_proposals'])}")
        for u in t["unknown"]:
            print(f"    NOT UNDERSTOOD: {u}")
    return 0


def cmd_reconcile(args):
    """T-121: does the traffic match the configuration? Exit 3 if any field mismatches, 1 if no connection fits."""
    from .config import parse_file
    from .config.reconcile import MISMATCH, as_dicts, pick_tunnel, reconcile
    cfg = parse_file(args.config)
    recs = [r for r in build_records(args.pcap) if getattr(r, "_ike", [])]
    if not cfg["tunnels"] or not recs:
        print("nothing to compare: " + ("no IKE in the capture" if not recs else "; ".join(cfg.get("unknown", ["no connections"]))))
        return 1
    rec = recs[0]
    tunnel, why = pick_tunnel(cfg["tunnels"], rec, args.conn)
    if tunnel is None:
        print(f"no matching connection: {why}")
        return 1
    comps = reconcile(tunnel, rec)
    if args.json:
        print(json.dumps({"pcap": args.pcap, "config": args.config, "connection": tunnel["name"],
                          "comparisons": as_dicts(comps)}, indent=2, default=str))
    else:
        glyph = {"match": "=", "consistent": "~", "mismatch": "X", "not comparable": "?", "not configured": "-"}
        print(f"# config vs wire: {args.config} [{tunnel['name']}]  x  {args.pcap}")
        for c in comps:
            print(f"  [{glyph.get(c.outcome, '?')}] {c.outcome:15} {c.field:18} {c.note}")
        n = sum(c.outcome == MISMATCH for c in comps)
        print(f"\n  {n} mismatch(es)" + ("  -> the traffic does not match this configuration" if n else ""))
    return 3 if any(c.outcome == MISMATCH for c in comps) else 0


def cmd_intel(args):
    """T-130: known vulnerabilities for the IKE implementations fingerprinted in a capture (INFERRED: version unknown)."""
    from .intel.lookup import lookup
    impls = sorted({v for r in build_records(args.pcap) if "implementation" in r.findings
                    for v in (r.findings["implementation"].value or {}).values() if v})
    out = [lookup(i) for i in impls]
    if args.json:
        print(json.dumps({"pcap": args.pcap, "implementations": out}, indent=2, default=str))
        return 0
    if not impls:
        print("no implementation could be fingerprinted from this capture (see `analyze`: implementation)")
        return 0
    for r in out:
        c = r["counts"]
        print(f"\n{r['implementation']}: {c['total']} known CVEs ({c['kev']} actively exploited, CISA KEV; "
              f"{c['product_listed']} with the product listed; {c['ipsec_related']} mention IKE/IPsec)")
        for name, st in r["sources"].items():
            print(f"  source {name}: {st['status']}" + (f" ({st['reason']})" if st["reason"] else ""))
        for e in r["cves"][:args.top]:
            flags = " ".join(x for x in ("KEV" if e["kev"] else "", "IPsec" if e["ipsec_related"] else "") if x)
            print(f"  {e['id']:16} {str(e['cvss'] or '-'):>4} {e['match']:8} {flags:10} {' '.join((e['description'] or '').split())[:80]}")
        print(f"  note: {r['note']}")
    return 0


def cmd_intel_bundle(args):
    """T-130: fill a directory with the intel sources for an air-gapped install (needs TUNNELSCOPE_NETWORK=on here)."""
    from .intel.lookup import bundle
    m = bundle(args.out)
    print(json.dumps(m["report"], indent=2))
    print(f"wrote {args.out}/MANIFEST.json; on the air-gapped machine set TUNNELSCOPE_INTEL_DIR={args.out}")
    return 0


def cmd_fleet(args):
    scanned = fleet_scan(args.directory)          # walk the directory exactly once
    f = fleet_json(args.directory, scanned)
    if args.json:
        print(json.dumps(f, indent=2, default=str))
    else:
        with open(args.out, "w") as fh:
            fh.write(render_fleet(args.directory, scanned))
        print(f"wrote {args.out}")
    # A fleet scan that hit unreadable captures has NOT cleared them; saying so
    # in the exit code keeps "some files never parsed" from passing as clean.
    if getattr(args, "fail_on_findings", False) and (
        f["errors"] or any(t["fails"] for t in f["tunnels"])
    ):
        return 1
    return 0


def cmd_gateway(args):
    """DEC-049: register real strongSwan gateways, read and accept the terms and risks."""
    from .remediate import execute, gateways
    hd = args.history
    if args.action == "add":
        entry = {"host": args.host, "user": args.user, "port": args.port, "connection": args.connection,
                 "child": args.child or args.connection, "capture_interface": args.interface,
                 "identity_file": args.identity_file, "known_hosts_file": args.known_hosts, "peer": args.peer,
                 "sudo": args.sudo, "allow_ai_drafts": args.allow_ai_drafts}
        if args.config_glob:
            entry["config_globs"] = args.config_glob
        try:
            gw = execute.save_gateway(args.name, entry, hd)
        except ValueError as e:
            raise TunnelScopeError(str(e))
        print(f"registered {gateways.PREFIX}{gw['name']} ({gw['user']}@{gw['host']}:{gw['port']}, connection {gw['connection']})")
        print(f"before any change: tunnelscope gateway terms, then tunnelscope gateway accept {gw['name']}")
        return 0
    if args.action == "list":
        rows = execute.gateway_list(hd)
        for p in gateways.registry_problems(execute._history_dir(hd)):
            print(f"  ! {p}")
        if not rows:
            print("no gateways registered (tunnelscope gateway add ...)")
        for r in rows:
            state = "terms accepted by " + str(r["consent"].get("by")) if r["accepted"] else "NOT accepted: " + r["consent"]["reason"]
            print(f"{r['name']}  {r['user']}@{r['host']}  connection {r['connection']}"
                  f"{'  peer ' + r['peer'] if r['peer'] else ''}  AI drafts {'on' if r['allow_ai_drafts'] else 'off'}  {state}")
        return 0
    if args.action == "terms":
        t = gateways.terms()
        print(f"{t['title']} (version {t['version']}, sha256 {t['sha256'][:16]})\n")
        for i, c in enumerate(t["clauses"], 1):
            print(f"{i}. {c}\n")
        return 0
    target = args.name if args.name.startswith(gateways.PREFIX) else gateways.PREFIX + args.name
    if args.action == "accept":
        by = args.by or input("Your name: ").strip()
        phrase = gateways.accept_phrase(gateways.name_of(target))
        typed = args.typed if args.typed is not None else input(f"Read `tunnelscope gateway terms` first. To accept, type exactly:\n  {phrase}\n> ")
        res = execute.accept_terms(target, typed, by, hd)
    else:
        res = execute.withdraw_terms(target, args.by or "cli", hd)
    if not res.get("ok"):
        raise TunnelScopeError(res.get("error", "refused"))
    print(f"{res['decision']}: {target}")
    return 0


def cmd_fix(args):
    """Preview a fix, show the exact change and its risks, then apply it only after the typed
    confirmation (real gateways) and roll it back automatically if verification fails."""
    import json as _json
    from .remediate import execute, gateways
    pv = execute.preview_remediation(args.rule, args.target, caller="cli", history_dir=args.history, plan_id=args.plan_id)
    if not pv.get("ok"):
        raise TunnelScopeError(f"preview refused at {pv.get('stage')}: {pv.get('error')}")
    for f, d in (pv.get("diff") or {}).items():
        print(d)
    if pv.get("peer"):
        for f, d in (pv["peer"].get("diff") or {}).items():
            print(f"(other end {pv['peer']['container']})\n{d}")
    cc = pv.get("clone_check") or {}
    print(f"load check: {'ok' if cc.get('ok') else 'FAILED'} ({cc.get('image')})")
    ack = None
    if gateways.is_gateway(args.target):
        live = pv["live"]
        print(f"\nRISKS of changing the real gateway {live['gateway']} ({live['host']}):")
        for r in live["risks"]:
            print(f"  - {r}")
        ack = args.ack if args.ack is not None else input(f"\nTo apply, type exactly:\n  {live['ack_phrase']}\n> ")
    elif not args.yes and input("Apply this change in the lab? [y/N] ").strip().lower() != "y":
        print("not applied")
        return 0
    res = execute.apply_remediation(args.rule, args.target, confirm=True, caller="cli", history_dir=args.history,
                                    plan_id=args.plan_id, digest=pv["digest"], require_digest=True, risk_ack=ack)
    print(_json.dumps({k: res.get(k) for k in ("decision", "stage", "error", "verdict_before", "verdict_after",
                                               "confirmed_fixed", "rolled_back", "rollback_verified", "reason")}, indent=2))
    return 0 if res.get("confirmed_fixed") else 4


def cmd_sensor_key(args):
    """Create a site key file (0600). The same file goes to the site's sensor and to the collector's keys dir."""
    from pathlib import Path
    from .sensor.report import write_key
    try:
        p = write_key(Path(args.out) / f"{args.site}.key")
    except FileExistsError:
        print(f"{args.site}.key already exists in {args.out}; not overwritten", file=sys.stderr)
        return 2
    print(f"wrote {p} (keep it secret; copy it to the site's sensor and to the collector's --keys directory)")
    return 0


def cmd_sensor(args):
    """Site sensor: live analysis at the site; only signed findings reports leave it (T-139)."""
    from .sensor.sensor import Sensor
    s = Sensor(args.site, args.key, args.outbox, args.state, window=args.window, interface=args.interface,
               follow=args.follow, keep=args.keep, headers_only=not args.full_packets,
               mask_addresses=args.mask_addresses)
    print(f"sensor {args.site}: {s.monitor.status()['source']}, {s.window}s windows, reports -> {args.outbox} "
          "(Ctrl-C stops)", file=sys.stderr)
    try:
        s.run(max_reports=args.max_reports, on_report=lambda p: print(p.name, flush=True))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_sensor_mask(args):
    """Site side: the pseudonym a masked report uses for an address (the mask key never leaves the site)."""
    from .sensor.report import pseudonym
    from .sensor.sensor import MASK_KEY_FILE, mask_key
    from pathlib import Path
    if not (Path(args.state) / MASK_KEY_FILE).exists():
        print(f"no mask key in {args.state}: this sensor has not masked any report", file=sys.stderr)
        return 2
    k = mask_key(args.state)
    for a in args.address:
        print(f"{a}\t{pseudonym(k, a)}")
    return 0


def cmd_collect(args):
    """Central collector: accept signed site reports from an inbox directory (T-139)."""
    from .sensor.collector import Collector
    c = Collector(args.inbox, args.state, args.keys, alerts=args.alerts, alert_format=args.alert_format)

    def show(r):
        print(json.dumps(r) if args.json else
              (f"{r['file']}: accepted ({r['kind']}, {r['alerts']} alert(s))" if r["accepted"]
               else f"{r['file']}: REJECTED, {r['reason']}"), flush=True)
    if args.once:
        rows = c.process_once()
        for r in rows:
            show(r)
        return 1 if any(not r["accepted"] for r in rows) else 0
    try:
        c.run(poll_s=args.poll, on_result=show)
    except KeyboardInterrupt:
        pass
    return 0


def cmd_sites(args):
    """Per-site freshness and posture from the collector's state."""
    from .sensor.collector import sites_status
    rows = sites_status(args.state)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no site has reported yet")
    for r in rows:
        print(f"{r['site']}: {r['status'].upper()}, last report {r['age_s']:.0f} s ago, {r['reports']} reports"
              + (f", {r['missing_reports']} missing" if r["missing_reports"] else "")
              + (", addresses masked at the site" if r.get("addresses") == "masked" else ""))
        if r["note"]:
            print(f"    {r['note']}")
        for t in r["tunnels"]:
            print(f"    {t['src']} <-> {t['dst']}: {t['posture']}; failing {', '.join(t['fails']) or 'none'}")
            h = t.get("last_handshake")
            if h and h["posture"] != t["posture"]:
                print(f"        last handshake seen {h['age_s']:.0f} s ago: {h['posture']}")
        for a in r.get("recent_alerts") or []:
            print(f"    ALERT {a['age_s']:.0f} s ago: {a['kind']} of {a['attribute']} on {a['tunnel']} "
                  f"({a.get('usual')} -> {a.get('now')})")
    return 1 if any(r["status"] == "stale" for r in rows) else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tunnelscope")
    ap.add_argument("--version", action="version", version=f"tunnelscope {_version()}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="build evidence records from a pcap")
    a.add_argument("pcap")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_analyze)
    s = sub.add_parser("assess", help="assess a pcap against named baselines")
    s.add_argument("pcap"); s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on-findings", action="store_true",
                   help="exit 1 if any FAIL verdict is present (for CI/monitoring gates)")
    s.add_argument("--profile", action="append", help="also assess against an opt-in rules profile (e.g. cnsa2-ipsec); repeatable")
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
    sv.add_argument("--history", metavar="DIR", help="learn each tunnel's normal and flag changes; stores posture profiles (no packets) in DIR")
    sv.add_argument("--live-follow", metavar="DIR", help="also analyse a live stream: capture files a sensor rotates into DIR")
    sv.add_argument("--live-interface", metavar="IFACE", help="also analyse a live stream captured on IFACE (needs capture permission)")
    sv.add_argument("--window", type=int, default=30, help="live window length in seconds (default 30)")
    sv.set_defaults(func=cmd_serve)
    lv = sub.add_parser("live", help="analyse a live network stream window by window (interface or a sensor's rotating files)")
    src = lv.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", "-i", help="network interface to capture on (needs capture permission)")
    src.add_argument("--follow", metavar="DIR", help="directory a sensor rotates capture files into (e.g. tcpdump -G 30 -w 'DIR/w-%%s.pcap')")
    lv.add_argument("--window", type=int, default=30, help="seconds per window (default 30)")
    lv.add_argument("--history", metavar="DIR", help="anomaly history: compare each window with the tunnel's past")
    lv.add_argument("--keep", action="store_true", help="keep analysed window files (default: delete them)")
    lv.add_argument("--headers-only", action="store_true",
                    help="--interface only: store ESP/AH headers only (IKE stays whole; findings unchanged, EXP-33)")
    lv.add_argument("--json", action="store_true", help="one JSON object per window")
    lv.add_argument("--max-windows", type=int, help="stop after N windows (testing)")
    lv.add_argument("--alerts", metavar="FILE", help="append an alert line for each downgrade / PQ loss / first-time rule failure")
    lv.add_argument("--alert-format", choices=["jsonl", "syslog"], default="jsonl", help="alert line format (syslog = RFC 5424)")
    lv.set_defaults(func=cmd_live)
    wt = sub.add_parser("watch", help="anomaly detection: compare each tunnel with its learned normal, then record it (role D)")
    wt.add_argument("target", help="a capture, or a directory of captures (processed in name order)")
    wt.add_argument("--history", required=True, metavar="DIR", help="where observations are kept")
    wt.add_argument("--no-record", action="store_true", help="compare only; don't add these captures to the history")
    wt.add_argument("--json", action="store_true")
    wt.add_argument("--fail-on-anomaly", action="store_true", help="exit 1 if any tunnel is anomalous")
    wt.add_argument("--alerts", metavar="FILE", help="append an alert line for each downgrade / PQ loss / first-time rule failure")
    wt.add_argument("--alert-format", choices=["jsonl", "syslog"], default="jsonl", help="alert line format (syslog = RFC 5424)")
    wt.set_defaults(func=cmd_watch)
    ex = sub.add_parser("explain", help="plain-English explanation of a capture's verdicts, for non-experts")
    ex.add_argument("pcap")
    ex.add_argument("--local-llm", action="store_true",
                    help="rephrase findings locally on-device with MLX (Apple Silicon only, DEC-031)")
    ex.set_defaults(func=cmd_explain)
    fl = sub.add_parser("fleet", help="scan a directory of captures: one aggregated view, per-tunnel evidence kept intact (role B/D)")
    fl.add_argument("directory")
    fl.add_argument("-o", "--out", default="tunnelscope-fleet.html")
    fl.add_argument("--json", action="store_true")
    fl.add_argument("--fail-on-findings", action="store_true",
                    help="exit 1 if any FAIL verdict, or any capture that failed to parse")
    fl.set_defaults(func=cmd_fleet)
    it = sub.add_parser("intel", help="known vulnerabilities (NVD, EUVD, CISA KEV) for the implementations fingerprinted in a capture")
    it.add_argument("pcap")
    it.add_argument("--top", type=int, default=10)
    it.add_argument("--json", action="store_true")
    it.set_defaults(func=cmd_intel)
    ib = sub.add_parser("intel-bundle", help="download the threat-intel sources into a directory for an air-gapped install")
    ib.add_argument("out")
    ib.set_defaults(func=cmd_intel_bundle)
    rc = sub.add_parser("reconcile", help="does a capture's traffic match a configuration file? (exit 3 on any mismatch)")
    rc.add_argument("pcap")
    rc.add_argument("config")
    rc.add_argument("--conn", help="connection name, when several use the capture's addresses")
    rc.add_argument("--json", action="store_true")
    rc.set_defaults(func=cmd_reconcile)
    cf = sub.add_parser("config", help="read an IPsec configuration file (swanctl.conf, ipsec.conf) offline: normalised crypto model")
    cf.add_argument("file")
    cf.add_argument("--json", action="store_true")
    cf.set_defaults(func=cmd_config)
    gwp = sub.add_parser("gateway", help="real strongSwan gateways for live fixes (DEC-049): add, list, terms, accept, withdraw")
    gwp.add_argument("action", choices=["add", "list", "terms", "accept", "withdraw"])
    gwp.add_argument("name", nargs="?", default="")
    gwp.add_argument("--history", default=".tunnelscope-history")
    gwp.add_argument("--host")
    gwp.add_argument("--user", default="root")
    gwp.add_argument("--port", type=int, default=22)
    gwp.add_argument("--connection", help="the swanctl connection a fix may change")
    gwp.add_argument("--child", help="child SA name used to restart the tunnel (default: the connection name)")
    gwp.add_argument("--config-glob", action="append", help="config file(s) on the gateway (repeatable)")
    gwp.add_argument("--interface", default="any", help="interface tcpdump captures on")
    gwp.add_argument("--identity-file")
    gwp.add_argument("--known-hosts")
    gwp.add_argument("--peer", help="the other end, if it is also a registered gateway")
    gwp.add_argument("--sudo", action="store_true", help="run commands through sudo -n")
    gwp.add_argument("--allow-ai-drafts", action="store_true")
    gwp.add_argument("--by", help="who is accepting or withdrawing")
    gwp.add_argument("--typed", help="the acceptance sentence (non-interactive)")
    gwp.set_defaults(func=cmd_gateway)
    fx = sub.add_parser("fix", help="preview, approve and apply one fix to a lab container or a registered gateway, with automatic rollback")
    fx.add_argument("rule")
    fx.add_argument("--target", required=True, help="lab container, or gw:<name>")
    fx.add_argument("--plan-id", help="a stored AI-drafted plan instead of the hand-written fix")
    fx.add_argument("--history", default=".tunnelscope-history")
    fx.add_argument("--ack", help="the per-change sentence for a gateway (non-interactive)")
    fx.add_argument("--yes", action="store_true", help="lab only: skip the y/N question")
    fx.set_defaults(func=cmd_fix)
    sk = sub.add_parser("sensor-key", help="create a site key for a sensor and the collector (T-139)")
    sk.add_argument("--site", required=True)
    sk.add_argument("--out", required=True, metavar="DIR", help="directory for <site>.key")
    sk.set_defaults(func=cmd_sensor_key)
    sn = sub.add_parser("sensor", help="site sensor: live analysis here, only signed findings reports leave the site")
    ssrc = sn.add_mutually_exclusive_group(required=True)
    ssrc.add_argument("--interface", "-i", help="network interface (mirror/SPAN port) to capture on")
    ssrc.add_argument("--follow", metavar="DIR", help="directory a tap or router rotates capture files into")
    sn.add_argument("--site", required=True, help="site name (letters, digits, - _ .)")
    sn.add_argument("--key", required=True, metavar="FILE", help="the site's key file (tunnelscope sensor-key)")
    sn.add_argument("--outbox", required=True, metavar="DIR", help="where signed reports are written for transfer")
    sn.add_argument("--state", required=True, metavar="DIR", help="sensor state: sequence number, tunnel history")
    sn.add_argument("--window", type=int, default=30, help="seconds per window (default 30)")
    sn.add_argument("--keep", action="store_true", help="keep capture files after analysis (default: delete)")
    sn.add_argument("--full-packets", action="store_true",
                    help="--interface only: store whole ESP/AH packets (default: headers only, IKE whole; EXP-33)")
    sn.add_argument("--mask-addresses", action="store_true",
                    help="replace every IP address in reports and alerts with a keyed pseudonym; the key stays in --state")
    sn.add_argument("--max-reports", type=int, help="stop after N reports (testing)")
    sn.set_defaults(func=cmd_sensor)
    sm = sub.add_parser("sensor-mask", help="site side: show the pseudonym masked reports use for an address")
    sm.add_argument("--state", required=True, metavar="DIR", help="the sensor's --state directory")
    sm.add_argument("address", nargs="+")
    sm.set_defaults(func=cmd_sensor_mask)
    co = sub.add_parser("collect", help="central collector: accept signed site reports from an inbox directory")
    co.add_argument("--inbox", required=True, metavar="DIR")
    co.add_argument("--state", required=True, metavar="DIR", help="per-site state and quarantine")
    co.add_argument("--keys", required=True, metavar="DIR", help="directory of <site>.key files")
    co.add_argument("--alerts", metavar="FILE", help="append each site's alerts, tagged with the site")
    co.add_argument("--alert-format", choices=["jsonl", "syslog"], default="jsonl")
    co.add_argument("--poll", type=float, default=1.0, help="seconds between inbox checks (default 1)")
    co.add_argument("--once", action="store_true", help="process the inbox once and exit (1 if anything was rejected)")
    co.add_argument("--json", action="store_true")
    co.set_defaults(func=cmd_collect)
    si = sub.add_parser("sites", help="per-site freshness and posture from the collector (exit 1 if any site is stale)")
    si.add_argument("--state", required=True, metavar="DIR")
    si.add_argument("--json", action="store_true")
    si.set_defaults(func=cmd_sites)
    dr = sub.add_parser("doctor", help="check the analysis stack (tshark present, fields intact)")
    dr.set_defaults(func=cmd_doctor)
    args = ap.parse_args(argv)

    try:
        # Verify the stack before trusting anything derived from it. Cached per
        # process, so a 70-capture fleet scan pays this once, not per capture.
        if args.func not in (cmd_doctor, cmd_config, cmd_intel_bundle, cmd_gateway, cmd_sensor_key, cmd_sensor_mask, cmd_collect, cmd_sites) and not os.environ.get("TUNNELSCOPE_SKIP_PREFLIGHT"):
            preflight()
        return args.func(args) or 0
    except TunnelScopeError as e:
        # Expected, explainable failures: say what went wrong, not where in
        # our stack it was raised. The exit code tells a script which kind.
        print(f"tunnelscope: {e}", file=sys.stderr)
        return e.exit_code
    except BrokenPipeError:
        return 0          # `| head` is not an error
    except KeyboardInterrupt:
        print("tunnelscope: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
