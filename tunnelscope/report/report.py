"""Report generation (T-036, PS §E) — executive + technical, from the evidence
graph only (invariant I8: no facts invented here; an LLM, if ever added, may
only rephrase this text).

Two levels:
  - executive: posture, the headline findings, per-baseline score + coverage.
  - technical: every SA, every finding with its status/vantage/evidence, every
    verdict with its cited authority. Observed / inferred / unknown /
    not-observable / contradictory are visually distinct (never merged).
"""
from __future__ import annotations

from ..evidence.extract import build_records
from ..assess.engine import assess_record, load_baselines
from ..assess.context import executive_lines, load_context, technical_lines
from ..score.score import score_record, score_sensitivity
from ..pq.cbom import build_cbom

_MARK = {"OBSERVED": "observed", "MEASURED": "measured", "INFERRED": "inferred",
         "UNKNOWN": "unknown", "NOT_OBSERVABLE": "not observable", "CONTRADICTORY": "CONTRADICTORY"}
_VMARK = {"PASS": "PASS", "FAIL": "FAIL", "UNKNOWN": "unknown",
          "NOT_OBSERVABLE": "not observable", "CONTRADICTORY": "CONTRADICTORY"}


def analyze(pcap: str) -> dict:
    baselines = load_baselines()
    recs = [r for r in build_records(pcap) if getattr(r, "_ike", []) or getattr(r, "_esp", [])]
    out = []
    for r in recs:
        verdicts = assess_record(r, baselines)
        out.append({"record": r, "verdicts": verdicts,
                    "scores": score_record(verdicts),
                    "sensitivity": score_sensitivity(verdicts)})
    cbom = build_cbom(recs, source=pcap)
    return {"pcap": pcap, "sas": out, "cbom": cbom}


def executive_report(a: dict) -> str:
    L = [f"# IPsec Posture — Executive Summary", "",
         f"**Source:** `{a['pcap']}`  ·  **Security associations analysed:** {len(a['sas'])}", ""]
    for i, sa in enumerate(a["sas"], 1):
        r = sa["record"]
        posture = a["cbom"]["tunnelscope_sa_summary"][i - 1]["quantum_posture"]
        L += [f"## SA {i}: {r.src} ↔ {r.dst}", "",
              f"- **Quantum posture:** {posture}"]
        fails = [v for v in sa["verdicts"] if v.verdict == "FAIL"]
        highs = [v for v in fails if v.severity == "high"]
        if highs:
            L.append(f"- **{len(highs)} high-severity finding(s):** " +
                     ", ".join(f"{v.rule_id} ({v.baseline})" for v in highs))
        L.append("- **Compliance by baseline:**")
        for b, s in sa["scores"].items():
            sc = "not assessable" if s["score"] is None else f"{s['score']}/100 (coverage {int(s['coverage']*100)}%)"
            L.append(f"    - {b}: {sc}")
        if sa["sensitivity"]["verdict"] == "fragile":
            L.append("    - _note: scores here rest on few rules and shift under re-weighting — read the verdict list, not the number._")
        contra = [v for v in sa["verdicts"] if v.verdict == "CONTRADICTORY"]
        if contra:
            L.append(f"- **⚠ {len(contra)} contradiction(s)** between evidence surfaces — see technical report.")
        L.append("")
    L += executive_lines(load_context("india"), [v for sa in a["sas"] for v in sa["verdicts"]])
    L += ["---", "_Findings are labelled observed / inferred / not-observable. "
          "The tool reports only what the capture supports; absence of evidence is never scored as compliance._"]
    return "\n".join(L)


def technical_report(a: dict) -> str:
    L = [f"# IPsec Posture — Technical Report", "", f"**Source:** `{a['pcap']}`", ""]
    for i, sa in enumerate(a["sas"], 1):
        r = sa["record"]
        L += [f"## SA {i}  ({r.src} ↔ {r.dst})  IKE SPI {r.key()}", "",
              "### Evidence (what was seen, and from where)", "",
              "| Attribute | Status | Value | Vantage | Method |", "|---|---|---|---|---|"]
        for attr, f in r.findings.items():
            val = "—" if f.value is None else f"`{f.value}`"
            L.append(f"| {attr} | {_MARK[f.status.value]} | {val} | {f.vantage.value} | {f.method} |")
        L += ["", "### Verdicts (each cites its authority)", "",
              "| Verdict | Baseline | Rule | Severity | Detail |", "|---|---|---|---|---|"]
        for v in sa["verdicts"]:
            detail = v.message or (f"observed `{v.observed}`" if v.observed is not None else "")
            L.append(f"| {_VMARK[v.verdict]} | {v.baseline} | {v.rule_id} | {v.severity} | {detail} |")
        L += ["", "### Score", ""]
        for b, s in sa["scores"].items():
            L.append(f"- **{b}:** {'not assessable' if s['score'] is None else str(s['score'])+'/100'} "
                     f"— {s['note']}")
        L += ["", "> Authorities: " + "; ".join(sorted({v.authority for v in sa["verdicts"]})), ""]
    L += technical_lines(load_context("india"), [v for sa in a["sas"] for v in sa["verdicts"]])
    L += ["## Cryptographic Bill of Materials (CycloneDX 1.6)", "",
          "```json", "", "(emit with `tunnelscope cbom <pcap>`)", "```"]
    return "\n".join(L)
