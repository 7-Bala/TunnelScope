#!/usr/bin/env python3
"""EXP-33 analysis (PREREG.md + ADDENDUM A) -> results/summary.json. RESULT.md quotes that file only."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
CAP = ROOT / "testbed" / "captures" / "exp33"
LIMIT = 80

from tunnelscope.ingest.tshark import tshark_bin  # noqa: E402
from tunnelscope.report.report import analyze  # noqa: E402


def per_sa(path: Path) -> dict:
    out = {}
    for sa in analyze(str(path))["sas"]:
        rec, verdicts = sa["record"], sa["verdicts"]
        spis = sorted({str(p.get("spi")) for p in getattr(rec, "_esp", [])})
        key = f"{rec.src}->{rec.dst} ike={rec.key()} esp={','.join(spis)}"
        out[key] = {"findings": {a: [f.status.value, json.dumps(f.value, sort_keys=True, default=str)]
                                 for a, f in rec.findings.items()},
                    "verdicts": {v.rule_id: v.verdict for v in verdicts}}
    return out


def records(path: Path) -> list[tuple[int, int, int, str]]:
    r = subprocess.run([tshark_bin(), "-r", str(path), "-T", "fields", "-e", "frame.interface_id", "-e", "frame.len",
                        "-e", "frame.cap_len", "-e", "isakmp", "-e", "esp", "-e", "ah"], capture_output=True, text=True,
                       check=True)
    rows = []
    for line in r.stdout.splitlines():
        iface, ln, cap, ike, esp, ah = (line.split("\t") + [""] * 6)[:6]
        kind = "ike" if ike else "esp/ah" if (esp or ah) else "other"
        rows.append((int(iface or 0), int(ln), int(cap), kind))
    return rows


def main():
    ref, hdr = CAP / "reference.pcapng", CAP / "headers.pcapng"
    a, b = per_sa(ref), per_sa(hdr)
    diffs = []
    for k in sorted(set(a) | set(b)):
        if k not in a or k not in b:
            diffs.append({"sa": k, "why": "only in " + ("reference" if k in a else "headers")})
            continue
        for part in ("findings", "verdicts"):
            for attr in sorted(set(a[k][part]) | set(b[k][part])):
                if a[k][part].get(attr) != b[k][part].get(attr):
                    diffs.append({"sa": k, part: attr, "reference": a[k][part].get(attr),
                                  "headers": b[k][part].get(attr)})
    rows = records(hdr)
    ike = [r for r in rows if r[3] == "ike"]
    esp = [r for r in rows if r[3] == "esp/ah"]
    bad = [r for r in esp if r[2] > LIMIT] + [r for r in ike if r[2] != r[1]]
    ref_rows = records(ref)
    out = {"sas": {"reference": len(a), "headers": len(b)},
           "H1_same_findings": {"differences": diffs[:20], "n_differences": len(diffs), "holds": bool(a) and not diffs},
           "H2_headers_only": {"ike_records": len(ike), "esp_ah_records": len(esp), "violations": len(bad),
                               "max_esp_stored": max((r[2] for r in esp), default=None),
                               "holds": bool(ike) and bool(esp) and not bad},
           "H3_size": {"reference_bytes": ref.stat().st_size, "headers_bytes": hdr.stat().st_size,
                       "reference_packets": len(ref_rows), "headers_packets": len(rows),
                       "esp_payload_bytes_stored_reference": sum(r[2] for r in ref_rows if r[3] == "esp/ah"),
                       "esp_payload_bytes_stored_headers": sum(r[2] for r in esp)}}
    (HERE / "results" / "summary.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
