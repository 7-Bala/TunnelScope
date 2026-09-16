"""Fleet mode (T-049) — the role B/D workflow: point at a directory of
captures, get ONE view across every tunnel. Every existing per-SA guarantee
stays intact (status/vantage/evidence, cited baseline, no invented facts,
I8) — this module only aggregates what `report.analyze()` already produces,
it never re-derives or re-scores anything itself.

Design rule (matches DEC-007 at fleet scale, not just per-tunnel): there is
no single fleet-wide score. A fleet "87/100" would hide exactly what a
single-tunnel "87/100" already hides — which baseline, which rule. The
rollup below is a FAIL COUNT PER RULE, never a blended number.

A capture that fails to parse is its own row with the error message, never
silently dropped — a fleet scan that quietly skips bad files is a worse
failure mode than a slow one.
"""
from __future__ import annotations

import html
from pathlib import Path

from .report import analyze
from ..errors import InputError

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a2230;--muted:#6b7684;--line:#e3e7ea;
--pass:#1a7f4b;--fail:#c0392b;--warn:#b8860b;--unk:#8a94a3;--accent:#0b6bcb}
@media(prefers-color-scheme:dark){:root{--bg:#12151a;--card:#1b2028;--ink:#e8ecf1;--muted:#9aa4b2;--line:#2a313c}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 2px}.sub{color:var(--muted);margin-bottom:20px;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;margin-top:6px;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;white-space:nowrap}
.t-pass{background:rgba(26,127,75,.14);color:var(--pass)}.t-fail{background:rgba(192,57,43,.14);color:var(--fail)}
.t-error{background:rgba(192,57,43,.14);color:var(--fail)}
.t-unknown{background:rgba(138,148,163,.16);color:var(--unk)}
.note{color:var(--muted);font-size:12px}
h3{font-size:13px;margin:16px 0 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.stat{display:inline-block;margin-right:28px}.stat b{font-size:22px;display:block}
.foot{color:var(--muted);font-size:12px;margin-top:18px}
"""


def scan(directory: str) -> dict:
    """Run analyze() over every pcap under `directory`. Returns per-tunnel
    results and unparseable-file errors, never silently skipping either.

    A path that does not exist, or holds no captures, is an error and not an
    empty clean scan: `rglob` on a missing directory yields nothing, so a
    typo'd path would otherwise produce a zero-finding report that reads
    exactly like a healthy fleet. "Scanned nothing" must never render as
    "found nothing wrong".
    """
    root = Path(directory)
    if not root.exists():
        raise InputError(f"directory not found: {directory}")
    if not root.is_dir():
        raise InputError(f"not a directory: {directory}")
    pcaps = sorted(list(root.rglob("*.pcap")) + list(root.rglob("*.pcapng")))
    if not pcaps:
        raise InputError(
            f"no .pcap/.pcapng files found under {directory} — refusing to "
            "report an empty scan as a clean fleet"
        )
    tunnels, errors = [], []
    for p in pcaps:
        try:
            a = analyze(str(p))
            if not a["sas"]:
                errors.append({"path": str(p), "error": "no security association found in capture"})
                continue
            tunnels.append({"path": str(p), "analysis": a})
        except Exception as e:  # noqa: BLE001 - a fleet scan must not die on one bad file
            errors.append({"path": str(p), "error": f"{type(e).__name__}: {e}"})
    return {"directory": str(root), "tunnels": tunnels, "errors": errors,
            "n_scanned": len(pcaps)}


def rollup(fleet: dict) -> dict:
    """Per-baseline, per-rule FAIL counts across the fleet. Never a blended
    score (DEC-007 applied at fleet scale)."""
    counts: dict[str, dict[str, dict[str, int]]] = {}
    for t in fleet["tunnels"]:
        for sa in t["analysis"]["sas"]:
            for v in sa["verdicts"]:
                b = counts.setdefault(v.baseline, {})
                r = b.setdefault(v.rule_id, {"PASS": 0, "FAIL": 0, "UNKNOWN": 0,
                                             "NOT_OBSERVABLE": 0, "CONTRADICTORY": 0})
                r[v.verdict] = r.get(v.verdict, 0) + 1
    return counts


def render(directory: str, fleet: dict | None = None) -> str:
    # `fleet` lets a caller that already scanned (the CLI, wanting both the
    # HTML and the fail counts) reuse it instead of re-walking every capture.
    fleet = fleet if fleet is not None else scan(directory)
    roll = rollup(fleet)
    n_tunnels = sum(len(t["analysis"]["sas"]) for t in fleet["tunnels"])
    n_downgraded = sum(
        1 for t in fleet["tunnels"] for i, sa in enumerate(t["analysis"]["sas"])
        if "DOWNGRAD" in t["analysis"]["cbom"]["tunnelscope_sa_summary"][i]["quantum_posture"])

    body = [
        "<h1>TunnelScope — Fleet Posture</h1>",
        f'<div class="sub">Directory: {html.escape(fleet["directory"])} · '
        f'{fleet["n_scanned"]} file(s) scanned · every finding still shows its own status, '
        "vantage and evidence — nothing here is averaged into one score</div>",
        '<div class="card">',
        f'<span class="stat"><b>{n_tunnels}</b>tunnel(s)</span>',
        f'<span class="stat"><b>{len(fleet["tunnels"])}</b>capture(s) parsed</span>',
        f'<span class="stat"><b>{len(fleet["errors"])}</b>capture(s) failed to parse</span>',
        f'<span class="stat"><b>{n_downgraded}</b>PQ-downgraded tunnel(s)</span>',
        "</div>",
    ]

    body.append('<div class="card"><h3>Fleet rollup — FAIL count per rule (never a blended score)</h3>')
    body.append('<table><tr><th>Baseline</th><th>Rule</th><th>Fail</th><th>Pass</th><th>Unknown / N-Obs</th></tr>')
    for b, rules in sorted(roll.items()):
        for rid, c in sorted(rules.items()):
            unk = c.get("UNKNOWN", 0) + c.get("NOT_OBSERVABLE", 0)
            fail_cls = "t-fail" if c["FAIL"] else "t-pass"
            body.append(f'<tr><td>{html.escape(b)}</td><td>{html.escape(rid)}</td>'
                        f'<td><span class="tag {fail_cls}">{c["FAIL"]}</span></td>'
                        f'<td>{c["PASS"]}</td><td>{unk}</td></tr>')
    body.append("</table></div>")

    body.append('<div class="card"><h3>Every tunnel</h3>')
    body.append('<table><tr><th>Capture</th><th>SA</th><th>PQ posture</th><th>High-severity fails</th></tr>')
    for t in fleet["tunnels"]:
        a = t["analysis"]
        for i, sa in enumerate(a["sas"]):
            posture = a["cbom"]["tunnelscope_sa_summary"][i]["quantum_posture"]
            # DOWNGRADED is a real fail. "classical" is not a fail on its own
            # (no PQ was ever offered/expected) but is not a pass either -
            # green here would read as "this is fine," which overstates it.
            if "DOWNGRAD" in posture:
                dg = "t-fail"
            elif posture.startswith("post-quantum"):
                dg = "t-pass"
            else:
                dg = "t-unknown"
            highs = [v for v in sa["verdicts"] if v.verdict == "FAIL" and v.severity == "high"]
            hi_str = ", ".join(f"{v.rule_id} ({v.baseline})" for v in highs) or "—"
            r = sa["record"]
            body.append(f'<tr><td>{html.escape(t["path"])}</td><td>{html.escape(r.src)} ↔ '
                        f'{html.escape(r.dst)}</td><td><span class="tag {dg}">{html.escape(posture)}</span></td>'
                        f'<td class="note">{html.escape(hi_str)}</td></tr>')
    body.append("</table></div>")

    if fleet["errors"]:
        body.append('<div class="card"><h3>Failed to parse — not silently skipped</h3>')
        body.append('<table><tr><th>File</th><th>Error</th></tr>')
        for e in fleet["errors"]:
            body.append(f'<tr><td>{html.escape(e["path"])}</td>'
                        f'<td><span class="tag t-error">{html.escape(e["error"])}</span></td></tr>')
        body.append("</table></div>")

    body.append('<div class="foot">Generated by TunnelScope fleet mode. Each tunnel keeps its own '
                'evidence and cited verdicts — this view aggregates counts, never scores.</div>')
    return (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>TunnelScope — Fleet: {html.escape(fleet["directory"])}</title>'
            f'<style>{_CSS}</style></head><body><div class="wrap">' + "\n".join(body) +
            "</div></body></html>")


def render_json(directory: str, fleet: dict | None = None) -> dict:
    """Machine-readable fleet summary, for role D's SIEM-integration workflow."""
    fleet = fleet if fleet is not None else scan(directory)
    roll = rollup(fleet)
    tunnels = []
    for t in fleet["tunnels"]:
        a = t["analysis"]
        for i, sa in enumerate(a["sas"]):
            r = sa["record"]
            tunnels.append({
                "path": t["path"], "src": r.src, "dst": r.dst,
                "quantum_posture": a["cbom"]["tunnelscope_sa_summary"][i]["quantum_posture"],
                "fails": [{"baseline": v.baseline, "rule_id": v.rule_id, "severity": v.severity}
                         for v in sa["verdicts"] if v.verdict == "FAIL"],
            })
    return {"directory": fleet["directory"], "n_scanned": fleet["n_scanned"],
            "tunnels": tunnels, "errors": fleet["errors"], "rollup": roll}
