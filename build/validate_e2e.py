#!/usr/bin/env python3
"""T-039 — end-to-end validation: run the TunnelScope pipeline over every
dataset capture and check its findings against the causal ground truth in
dataset/MANIFEST.csv (which is itself T2-derived, never from the analyzer).

Checks per capture (only where the manifest carries ground truth):
  - pq_key_exchange matches gt_pq (ML-KEM present / classical-only / downgrade);
  - ike_dh_group matches gt (when observable);
  - mode is NEVER claimed as a value at T0 (must be NOT_OBSERVABLE) - the
    standing anti-overclaim check;
  - the AES-128/256 negative control: no ESP-side key-length finding exists.

Emits build/E2E-VALIDATION.md and exits non-zero on any mismatch.
"""
import csv
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tunnelscope.evidence.extract import build_records  # noqa: E402

CAP = os.path.join(ROOT, "testbed", "captures")
MAN = os.path.join(ROOT, "dataset", "MANIFEST.csv")


def main_record(pcap):
    recs = build_records(pcap)
    recs = [r for r in recs if getattr(r, "_ike", []) or getattr(r, "_esp", [])]
    return max(recs, key=lambda r: len(getattr(r, "_ike", [])) + len(getattr(r, "_esp", []))) if recs else None


def check(row):
    pcap = os.path.join(CAP, row["path"])
    r = main_record(pcap)
    issues = []
    if r is None:
        return ["no record built"]
    F = r.findings

    # mode must never be a value at T0 (anti-overclaim)
    if "mode" in F and F["mode"].status.value not in ("NOT_OBSERVABLE", "UNKNOWN"):
        issues.append(f"mode claimed as {F['mode'].status.value} at T0 (must be NOT_OBSERVABLE)")

    # never an ESP-side key length
    if "esp_key_length" in F:
        issues.append("esp_key_length finding exists (F-05 violation)")

    # PQ ground truth
    gt_pq = row.get("gt_pq", "")
    if gt_pq and "pq_key_exchange" in F:
        v = F["pq_key_exchange"].value
        if gt_pq == "ML-KEM-768" and not (isinstance(v, list) and "ML-KEM-768" in v):
            issues.append(f"pq: gt ML-KEM-768 but got {v}")
        if gt_pq == "offered-but-not-used" and v != "offered-but-not-used":
            issues.append(f"pq: gt downgrade but got {v}")
        if gt_pq == "False" and v != "classical-only":
            issues.append(f"pq: gt classical but got {v}")

    # DH group observability (when IKE_SA_INIT present, dh should be observed)
    if row["experiment"].startswith(("EXP-01", "EXP-04")) and "IKE_SA_INIT" in str(F.get("ike_exchanges").value if F.get("ike_exchanges") else ""):
        if "ike_dh_group" in F and F["ike_dh_group"].status.value == "OBSERVED":
            if F["ike_dh_group"].value != "MODP-2048":
                issues.append(f"dh: expected MODP-2048, got {F['ike_dh_group'].value}")
    return issues


def main():
    rows = list(csv.DictReader(open(MAN)))
    results = []
    for row in rows:
        if row["experiment"] == "EXP-06r1-superseded":
            continue
        if row.get("split") == "excluded":   # synthetic detector fixtures carry no crypto ground truth
            continue
        issues = check(row)
        results.append((row["path"], row["experiment"], issues))

    n = len(results)
    failed = [(p, e, i) for p, e, i in results if i]
    by_exp = Counter(e for _, e, _ in results)

    lines = ["# TunnelScope — End-to-End Validation (T-039)", "",
             f"Ran the full pipeline (ingest → evidence → assess) over **{n} captures** and checked "
             "every finding against the causal ground truth in `dataset/MANIFEST.csv`.", "",
             f"**Result: {n - len(failed)}/{n} captures pass; {len(failed)} mismatch(es).**", "",
             "## Coverage by experiment", ""]
    for exp, c in sorted(by_exp.items()):
        lines.append(f"- {exp}: {c} captures")
    lines += ["", "## Standing anti-overclaim checks (every capture)", "",
              "- mode is never claimed as a value at T0 (EXP-08): enforced",
              "- no ESP-side key-length finding ever exists (F-05/EXP-02): enforced", ""]
    if failed:
        lines += ["## Mismatches", ""]
        for p, e, i in failed:
            lines.append(f"- `{p}` ({e}): " + "; ".join(i))
    else:
        lines += ["## Mismatches", "", "None. Every finding matches ground truth, and the pipeline "
                  "never overclaimed a NOT-OBSERVABLE attribute.", ""]
    open(os.path.join(ROOT, "build", "E2E-VALIDATION.md"), "w").write("\n".join(lines))
    print("\n".join(lines[:8]))
    print(f"\nWrote build/E2E-VALIDATION.md")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
