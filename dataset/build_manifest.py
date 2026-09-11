#!/usr/bin/env python3
"""T-023 — build a hash-verified, documented dataset manifest from the testbed captures.

Dataset-hygiene practices adopted from (credit) naman9271/ipsec-pcap-lab: per-file
SHA-256, an explicit train/validation/locked-test split, and a strict validator
(validate.py). Our additions: causal ground truth (the configured arm + the
endpoint's own swanctl/pluto log, T2 — never inferred from the capture), an
explicit vantage tier per capture, and a documented split by SESSION/CONFIGURATION
(never by packet or flow — DEC-009).

Emits: dataset/MANIFEST.csv, dataset/DATASHEET.md
Run:   python3 dataset/build_manifest.py
"""
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "testbed" / "captures"
OUT = Path(__file__).resolve().parent

# arm-name -> ground-truth crypto config (causal: what we configured, T2-confirmed)
GT = {
    "cs-aes128gcm16": dict(ike="v2", cipher="AES-GCM-16", keylen=128, mode="tunnel", pfs=False),
    "cs-aes256gcm16": dict(ike="v2", cipher="AES-GCM-16", keylen=256, mode="tunnel", pfs=False),
    "cs-aes128cbc-sha256": dict(ike="v2", cipher="AES-CBC+HMAC-SHA256", keylen=128, mode="tunnel", pfs=False),
    "cs-aes256cbc-sha256": dict(ike="v2", cipher="AES-CBC+HMAC-SHA256", keylen=256, mode="tunnel", pfs=False),
    "cs-aes128ctr-sha256": dict(ike="v2", cipher="AES-CTR+HMAC-SHA256", keylen=128, mode="tunnel", pfs=False),
    "cs-chacha20poly1305": dict(ike="v2", cipher="ChaCha20-Poly1305", keylen=256, mode="tunnel", pfs=False),
    "cs-transport-aes256gcm16": dict(ike="v2", cipher="AES-GCM-16", keylen=256, mode="transport", pfs=False),
    "cs-pfs-off-aes256gcm16": dict(ike="v2", cipher="AES-GCM-16", keylen=256, mode="tunnel", pfs=False),
    "cs-pfs-on-aes256gcm16": dict(ike="v2", cipher="AES-GCM-16", keylen=256, mode="tunnel", pfs=True),
    "classical-baseline": dict(ike="v2", cipher="AES-GCM-16", keylen=256, mode="tunnel", pfs=False, pq=False),
    "pq-mlkem768": dict(ike="v2", cipher="AES-GCM-16", keylen=256, mode="tunnel", pfs=False, pq="ML-KEM-768"),
}
IMPL = {"exp07": "libreswan-5.4", "default_pq": "strongswan-6.1.0", "default": "strongswan-5.9.8"}


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def npkts(p):
    try:
        return int(subprocess.run(["tshark", "-r", str(p), "-T", "fields", "-e", "frame.number"],
                                  capture_output=True, text=True).stdout.count("\n"))
    except Exception:
        return -1


def arm_of(name):
    for a in sorted(GT, key=len, reverse=True):
        if name.startswith(a):
            return a
    m = re.match(r"(rekey-|a7-)?(cs-[a-z0-9-]+?)(-run2|-a7|-success-baseline)?$", name)
    return m.group(2) if m else None


def experiment_of(relpath, name):
    if relpath.startswith("exp06r2"): return "EXP-06r2-failure-diagnosis"
    if relpath.startswith("exp07"): return "EXP-07-libreswan"
    if name.startswith("rekey-"): return "EXP-03-pfs"
    if name.startswith("a7-"): return "EXP-08-mode"
    if name.startswith(("classical-baseline", "pq-mlkem768")): return "EXP-04-pq"
    if name.startswith("fail-"): return "EXP-06r1-superseded"
    return "EXP-01/02-cipher"


def split_of(experiment, name):
    # Split by SESSION/CONFIGURATION, never by packet/flow (DEC-009).
    # Locked test set: one held-out repetition family per multi-rep experiment.
    if "rep5" in name: return "locked_test"
    if "rep4" in name: return "validation"
    if experiment == "EXP-07-libreswan": return "locked_test"   # cross-impl = generalisation test
    return "train"


def main():
    rows = []
    for p in sorted(CAP.rglob("*.pcap")):
        rel = str(p.relative_to(CAP))
        if rel.startswith("exp05/"):        # EXP-05 is a separate sub-dataset (traffic-class
            continue                         # ground truth) with its own hash manifest + tables
        name = p.stem
        arm = arm_of(name)
        experiment = experiment_of(rel, name)
        impl = (IMPL["exp07"] if rel.startswith("exp07")
                else IMPL["default_pq"] if name.startswith(("classical-baseline", "pq-mlkem768"))
                else IMPL["default"])
        gt = dict(GT.get(arm, {}))
        gtf = p.with_suffix(".groundtruth.json")
        rows.append(dict(
            path=rel, sha256=sha256(p), bytes=p.stat().st_size, n_packets=npkts(p),
            experiment=experiment, arm=arm or "", implementation=impl,
            vantage="T0/T1 (router, keyless)",
            ground_truth_json=gtf.name if gtf.exists() else "",
            gt_cipher=gt.get("cipher", ""), gt_keylen=gt.get("keylen", ""),
            gt_mode=gt.get("mode", ""), gt_pfs=gt.get("pfs", ""), gt_pq=gt.get("pq", ""),
            split=split_of(experiment, name),
        ))
    fields = list(rows[0].keys())
    with open(OUT / "MANIFEST.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)

    # EXP-05 sessions are per-packet tables, not pcaps; fold in their own manifest.
    e5 = CAP / "exp05" / "manifest.csv"
    n_e5 = sum(1 for _ in open(e5)) if e5.exists() else 0

    from collections import Counter
    by_exp = Counter(r["experiment"] for r in rows)
    by_split = Counter(r["split"] for r in rows)
    (OUT / "DATASHEET.md").write_text(f"""# TunnelScope IPsec Capture Dataset — Datasheet

**Built:** 2026-09-12 by `dataset/build_manifest.py` · **Manifest:** `MANIFEST.csv`
(one row per pcap: path, SHA-256, packets, experiment, arm, implementation, vantage,
ground-truth crypto config, split). Validate with `python3 dataset/validate.py`.

## What this is
Controlled IPsec/IKE captures generated by the TunnelScope testbed (`testbed/`) for the
experiments in `experiments/`. **Not** a sample of real-world traffic: it is a measurement
instrument with known, causal ground truth. Two implementations: strongSwan (5.9.8 classical,
6.1.0 PQ) and Libreswan 5.4.

## Provenance and ground truth
Every capture is taken at the **router** container, which runs no IPsec and holds no keys — a
genuine third-party passive (T0/T1) vantage (`testbed/TOPOLOGY.md`). Ground truth is **causal**:
the configuration we set, confirmed by the endpoint's own `swanctl`/`pluto` log (T2, in the
`*.groundtruth.json` files). It is **never** inferred from the capture — no circular validation.

## Contents
- **{len(rows)} pcaps** across: {', '.join(f'{k} ({v})' for k, v in sorted(by_exp.items()))}.
- **{n_e5} EXP-05 rows** as per-packet tables (`testbed/captures/exp05/*.pkts.csv.gz`), raw pcaps
  hashed in `testbed/captures/exp05/manifest.csv`.

## Splits (by session/configuration, never by packet or flow — DEC-009)
{', '.join(f'{k}: {v}' for k, v in sorted(by_split.items()))}.
- `locked_test` includes the held-out rep5 families **and the entire Libreswan set** (cross-
  implementation generalisation is a test, not training).
- Leakage controls: EXP-02 is a built-in negative control (AES-128 vs 256 must be near-chance);
  EXP-05 carries a permutation null. See each experiment's RESULT for the split actually used.

## Known limitations
- Synthetic traffic shapes (EXP-05), one network path, no injected loss/jitter, PSK auth only,
  two open-source stacks (no vendor appliances). Stated in each RESULT.

## Credit
Dataset-hygiene practices (per-file SHA-256, locked test set, strict validator) adapted from
`naman9271/ipsec-pcap-lab`.
""")
    print(f"MANIFEST.csv: {len(rows)} pcaps | splits {dict(by_split)}")
    print(f"DATASHEET.md written")


if __name__ == "__main__":
    main()
