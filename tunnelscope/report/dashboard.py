"""Self-contained HTML dashboard (T-037). Offline (ADR-006): one file, no server,
no external assets. Every panel maps to an analyst job-to-be-done (doc 03):
posture at a glance (J2/J4), per-baseline compliance (J2), the evidence trail
(trust), and what could not be seen (J3, honesty). Status colours make
observed / inferred / not-observable / contradictory visually distinct (DEC-008).
"""
from __future__ import annotations

import html
import json

from .report import analyze

_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a2230;--muted:#6b7684;--line:#e3e7 ;
--pass:#1a7f4b;--fail:#c0392b;--warn:#b8860b;--unk:#8a94a3;--pq:#6c3fc4;--accent:#0b6bcb}
@media(prefers-color-scheme:dark){:root{--bg:#12151a;--card:#1b2028;--ink:#e8ecf1;--muted:#9aa4b2;--line:#2a313c}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
.wrap{max-width:1080px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 2px}.sub{color:var(--muted);margin-bottom:20px;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:16px}
.sa-h{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.posture{font-weight:600;padding:4px 10px;border-radius:20px;font-size:12px;background:rgba(108,63,196,.12);color:var(--pq)}
.posture.dg{background:rgba(192,57,43,.14);color:var(--fail)}
.scores{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
.score{flex:1;min-width:150px;border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.score .b{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.score .v{font-size:22px;font-weight:700}.score .c{font-size:11px;color:var(--muted)}
table{width:100%;border-collapse:collapse;margin-top:6px;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;white-space:nowrap}
.t-observed{background:rgba(26,127,75,.14);color:var(--pass)}
.t-inferred{background:rgba(11,107,203,.12);color:var(--accent)}
.t-measured{background:rgba(11,107,203,.12);color:var(--accent)}
.t-unknown,.t-not-observable{background:rgba(138,148,163,.16);color:var(--unk)}
.t-contradictory{background:rgba(184,134,11,.16);color:var(--warn)}
.t-pass{background:rgba(26,127,75,.14);color:var(--pass)}.t-fail{background:rgba(192,57,43,.14);color:var(--fail)}
.note{color:var(--muted);font-size:12px}.foot{color:var(--muted);font-size:12px;margin-top:18px}
h3{font-size:13px;margin:16px 0 4px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
"""


def _tag(status):
    cls = status.lower().replace("_", "-").replace(" ", "-")
    return f'<span class="tag t-{cls}">{html.escape(status.lower().replace("_"," "))}</span>'


def render(pcap: str) -> str:
    a = analyze(pcap)
    body = [f'<h1>TunnelScope — IPsec Posture</h1>',
            f'<div class="sub">Source: {html.escape(pcap)} · {len(a["sas"])} security association(s) · '
            'every finding shows its status, vantage and evidence; verdicts cite their standard</div>']
    for i, sa in enumerate(a["sas"], 1):
        r = sa["record"]
        posture = a["cbom"]["tunnelscope_sa_summary"][i - 1]["quantum_posture"]
        dg = "dg" if ("DOWNGRAD" in posture or "classical (quantum" in posture) else ""
        body.append('<div class="card">')
        body.append(f'<div class="sa-h"><div><b>SA {i}</b> &nbsp;{html.escape(r.src)} ↔ {html.escape(r.dst)}</div>'
                    f'<span class="posture {dg}">{html.escape(posture)}</span></div>')
        # scores
        body.append('<div class="scores">')
        for b, s in sa["scores"].items():
            v = "n/a" if s["score"] is None else s["score"]
            body.append(f'<div class="score"><div class="b">{html.escape(b)}</div>'
                        f'<div class="v">{v}</div><div class="c">coverage {int(s["coverage"]*100)}% · '
                        f'{s["counts"]["pass"]}✓ {s["counts"]["fail"]}✗ {s["counts"]["unknown"]+s["counts"]["not_observable"]}?</div></div>')
        body.append('</div>')
        if sa["sensitivity"]["verdict"] == "fragile":
            body.append('<div class="note">Scores rest on few rules and shift under re-weighting — read the verdicts, not the number.</div>')
        # verdicts
        body.append('<h3>Verdicts</h3><table><tr><th>Result</th><th>Baseline</th><th>Rule</th><th>Detail</th></tr>')
        for v in sorted(sa["verdicts"], key=lambda x: {"FAIL":0,"CONTRADICTORY":1,"UNKNOWN":2,"NOT_OBSERVABLE":3,"PASS":4}[x.verdict]):
            detail = html.escape(v.message or (f"observed {v.observed}" if v.observed is not None else ""))
            body.append(f'<tr><td>{_tag(v.verdict)}</td><td>{html.escape(v.baseline)}</td>'
                        f'<td>{html.escape(v.rule_id)}</td><td>{detail}</td></tr>')
        body.append('</table>')
        # evidence
        body.append('<h3>Evidence</h3><table><tr><th>Attribute</th><th>Status</th><th>Value</th><th>Vantage</th><th>Method</th></tr>')
        for attr, f in r.findings.items():
            val = "—" if f.value is None else html.escape(str(f.value))
            body.append(f'<tr><td>{html.escape(attr)}</td><td>{_tag(f.status.value)}</td>'
                        f'<td>{val}</td><td>{f.vantage.value}</td><td class="note">{html.escape(f.method)}</td></tr>')
        body.append('</table>')
        gaps = a["cbom"]["tunnelscope_sa_summary"][i-1]["gaps"]
        if gaps:
            body.append('<h3>Not observable at this vantage</h3><div class="note">' +
                        "; ".join(html.escape(f"{g['attribute']}: {g.get('note','')}") for g in gaps) + '</div>')
        body.append('</div>')
    body.append('<div class="foot">Generated by TunnelScope. Findings are labelled observed / inferred / '
                'measured / not-observable / contradictory. Absence of evidence is never scored as compliance.</div>')
    return (f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1"><title>TunnelScope — {html.escape(pcap)}</title>'
            f'<style>{_CSS}</style></head><body><div class="wrap">' + "\n".join(body) + '</div></body></html>')
