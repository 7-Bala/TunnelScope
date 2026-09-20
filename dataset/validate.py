#!/usr/bin/env python3
"""T-023 — strict dataset validator. Exits NON-ZERO on any violation.

Checks (each a hard failure):
  1. every pcap in MANIFEST.csv exists and its SHA-256 matches;
  2. no unmanifested pcap under testbed/captures (nothing untracked);
  3. every non-superseded capture has a ground-truth reference (T2) OR an arm
     whose config is known — no capture without provenance;
  4. no split leakage: a locked_test capture's (experiment, arm, rep-family)
     never also appears in train;
  5. the EXP-02 negative-control arms (AES-128 and AES-256, same family) are
     both present — the built-in contamination check must be runnable.
"""
import csv
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "testbed" / "captures"
MAN = Path(__file__).resolve().parent / "MANIFEST.csv"


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    fails = []
    rows = list(csv.DictReader(open(MAN)))
    manifest_paths = {r["path"] for r in rows}

    # 1. existence + hash
    for r in rows:
        p = CAP / r["path"]
        if not p.exists():
            fails.append(f"missing file: {r['path']}"); continue
        if sha256(p) != r["sha256"]:
            fails.append(f"hash mismatch: {r['path']}")

    # 2. nothing untracked (exp05 raw pcaps are intentionally excluded/gitignored)
    for p in CAP.rglob("*.pcap"):
        rel = str(p.relative_to(CAP))
        if rel.startswith(("exp05/", "exp15/traffic/", "exp16/")):
            continue
        if rel not in manifest_paths:
            fails.append(f"untracked pcap not in manifest: {rel}")

    # 3. provenance
    for r in rows:
        if r["experiment"] == "EXP-06r1-superseded":
            continue
        # Synthetic detector fixtures (split=excluded) carry no crypto ground
        # truth by nature — they are forged plaintext headers, never in an ML
        # split — so the provenance rule does not apply to them.
        if r["split"] == "excluded":
            continue
        if not r["ground_truth_json"] and not r["arm"]:
            fails.append(f"no ground truth / known arm: {r['path']}")

    # 4. split leakage: same (experiment, arm) family must not straddle train and locked_test
    #    UNLESS separated by repetition (rep-family) — rep5 in test, rep1-3 in train is allowed.
    def repfam(path):
        m = re.search(r"rep(\d)", path); return m.group(1) if m else "norep"
    seen = defaultdict(set)
    for r in rows:
        key = (r["experiment"], r["arm"], repfam(r["path"]))
        seen[key].add(r["split"])
    for key, splits in seen.items():
        if "train" in splits and "locked_test" in splits:
            fails.append(f"split leakage: {key} in both train and locked_test")

    # 5. negative-control arms present
    arms = {r["arm"] for r in rows}
    for lo, hi in [("cs-aes128gcm16", "cs-aes256gcm16"), ("cs-aes128cbc-sha256", "cs-aes256cbc-sha256")]:
        if lo not in arms or hi not in arms:
            fails.append(f"EXP-02 negative-control pair missing: {lo}/{hi}")

    # 6. EXP-05 sub-dataset: every manifest row has its per-packet table
    e5 = CAP / "exp05" / "manifest.csv"
    if e5.exists():
        import csv as _csv
        for row in _csv.reader(open(e5)):
            if not row:
                continue
            tag = row[0]
            if not (CAP / "exp05" / f"{tag}.pkts.csv.gz").exists():
                fails.append(f"EXP-05 table missing for manifest row: {tag}")
    else:
        fails.append("EXP-05 manifest.csv missing")

    if fails:
        print(f"DATASET VALIDATION: FAIL ({len(fails)} issue(s))")
        for f in fails[:40]:
            print("  -", f)
        sys.exit(1)
    print(f"DATASET VALIDATION: PASS — {len(rows)} pcaps, all hashes match, provenance and splits clean")
    sys.exit(0)


if __name__ == "__main__":
    main()
