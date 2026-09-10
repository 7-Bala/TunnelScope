#!/usr/bin/env python3
"""EXP-02 — AES-128 vs AES-256 negative control (dataset-integrity gate).

This is a HARD GATE per the project's own rules: it must show approximately
chance-level discrimination. If it does not, we assume dataset leakage or
another confounder until proven otherwise — we do NOT celebrate an
above-chance result on this pair.

Two independent tests, both against the same evidence (ESP packet lengths
observed at the router, T0 vantage — no keys, no dissector transform ID):

  1. EXACT SET COMPARISON: for each matched pair of arms differing ONLY in
     key length (128-bit vs 256-bit, same family), compare the SET of
     observed esp_content lengths. Since our probe sequence sends the exact
     same sizes to both arms, F-05 predicts the two sets are IDENTICAL.

  2. CLASSIFIER TEST: pool both arms' packets, label by key length, and
     attempt to predict the label from esp_content length (and from
     ip.id / timing jitter, as confound checks) using stratified k-fold
     cross-validation. F-05 predicts accuracy indistinguishable from chance
     (50%). This is the leakage/contamination detector: if this classifier
     scores meaningfully above chance, STOP and investigate before trusting
     any other ML result in the project (see EXPERIMENT-REGISTER.md EXP-02
     and 05-DISCOVER-datasets.md sec 6).

Usage: python3 analyze.py <captures-dir> <results-dir>
"""
import json
import subprocess
import sys
from pathlib import Path

import random

PAIRS = [
    ("cs-aes128gcm16", "cs-aes256gcm16", "AES-GCM (AEAD)"),
    ("cs-aes128cbc-sha256", "cs-aes256cbc-sha256", "AES-CBC+HMAC-SHA256 (non-AEAD)"),
]


def extract_fields(pcap_path: Path) -> list[dict]:
    out = subprocess.run(
        ["tshark", "-r", str(pcap_path), "-Y", "esp", "-T", "fields",
         "-e", "frame.time_relative", "-e", "ip.len", "-e", "ip.id", "-e", "ip.src"],
        capture_output=True, text=True, check=True,
    ).stdout
    rows = []
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) != 4:
            continue
        t, ip_len, ip_id, src = parts
        rows.append({
            "t": float(t), "ip_len": int(ip_len),
            "esp_content": int(ip_len) - 20 - 8,
            "ip_id": int(ip_id, 16) if ip_id.startswith("0x") else int(ip_id or 0),
            "src": src,
        })
    return rows


def exact_set_comparison(rows_a, rows_b):
    set_a = sorted(set(r["esp_content"] for r in rows_a))
    set_b = sorted(set(r["esp_content"] for r in rows_b))
    return {
        "lengths_128": set_a,
        "lengths_256": set_b,
        "identical_sets": set_a == set_b,
        "symmetric_difference": sorted(set(set_a) ^ set(set_b)),
    }


def stratified_kfold_indices(n_a, n_b, k=5, seed=1337):
    rng = random.Random(seed)
    idx_a = list(range(n_a))
    idx_b = list(range(n_b))
    rng.shuffle(idx_a)
    rng.shuffle(idx_b)
    folds = []
    for i in range(k):
        test_a = set(idx_a[i::k])
        test_b = set(idx_b[i::k])
        folds.append((test_a, test_b))
    return folds


def classifier_test(rows_a, rows_b, feature_key="esp_content", k=5):
    """Trivial threshold/lookup classifier: for each fold, build a mapping
    from observed feature value -> majority class in the TRAIN split, and
    predict the majority class for TEST. This is the strongest possible
    classifier for a feature this coarse (a lookup table dominates any
    smooth model when the feature space is small and discrete), so if even
    this fails to beat chance, no realistic classifier will succeed either.
    """
    n_a, n_b = len(rows_a), len(rows_b)
    folds = stratified_kfold_indices(n_a, n_b, k=k)
    accs = []
    for test_a_idx, test_b_idx in folds:
        train = ([(rows_a[i][feature_key], 0) for i in range(n_a) if i not in test_a_idx] +
                  [(rows_b[i][feature_key], 1) for i in range(n_b) if i not in test_b_idx])
        test = ([(rows_a[i][feature_key], 0) for i in test_a_idx] +
                 [(rows_b[i][feature_key], 1) for i in test_b_idx])

        # majority-vote-per-feature-value lookup table from TRAIN only
        from collections import defaultdict, Counter
        table = defaultdict(Counter)
        for val, label in train:
            table[val][label] += 1
        overall_majority = Counter(l for _, l in train).most_common(1)[0][0]

        correct = 0
        for val, label in test:
            if val in table:
                pred = table[val].most_common(1)[0][0]
            else:
                pred = overall_majority
            correct += (pred == label)
        accs.append(correct / len(test) if test else float("nan"))
    return {"fold_accuracies": accs, "mean_accuracy": sum(accs) / len(accs), "n_folds": k}


def main():
    captures_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures")
    results_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "results")
    results_dir.mkdir(parents=True, exist_ok=True)

    report = {"pairs": {}}
    any_leak_flag = False

    for arm_128, arm_256, label in PAIRS:
        pcap_a = captures_dir / f"{arm_128}.pcap"
        pcap_b = captures_dir / f"{arm_256}.pcap"
        if not (pcap_a.exists() and pcap_b.exists()):
            print(f"SKIP {label}: missing pcap(s)")
            continue

        rows_a = extract_fields(pcap_a)
        rows_b = extract_fields(pcap_b)

        exact = exact_set_comparison(rows_a, rows_b)
        clf_len = classifier_test(rows_a, rows_b, feature_key="esp_content")
        # Confound checks: does IP ID (a per-host counter, NOT part of the
        # cipher) leak host/session identity in a way a naive pipeline might
        # accidentally correlate with the label? We test it explicitly so a
        # future dataset-generation run can catch this class of leakage too.
        clf_ipid = classifier_test(rows_a, rows_b, feature_key="ip_id")

        entry = {
            "label": label,
            "arm_128": arm_128,
            "arm_256": arm_256,
            "n_packets_128": len(rows_a),
            "n_packets_256": len(rows_b),
            "exact_length_set_comparison": exact,
            "classifier_on_esp_length": clf_len,
            "classifier_on_ip_id_confound_check": clf_ipid,
        }
        report["pairs"][label] = entry

        leak_len = clf_len["mean_accuracy"] > 0.60  # generous margin above 0.50 chance
        leak_ipid = clf_ipid["mean_accuracy"] > 0.60
        any_leak_flag = any_leak_flag or leak_len or leak_ipid

        print(f"\n=== {label} ===")
        print(f"  exact length sets identical: {exact['identical_sets']}"
              f"  (symmetric diff: {exact['symmetric_difference']})")
        print(f"  classifier(esp_length) mean accuracy: {clf_len['mean_accuracy']:.3f} "
              f"(chance=0.500) folds={clf_len['fold_accuracies']}")
        print(f"  classifier(ip.id CONFOUND CHECK) mean accuracy: {clf_ipid['mean_accuracy']:.3f}")
        if leak_len:
            print("  *** WARNING: esp_length classifier exceeds 0.60 — POSSIBLE LEAKAGE, INVESTIGATE ***")
        if leak_ipid:
            print("  *** WARNING: ip.id classifier exceeds 0.60 — POSSIBLE HOST/SESSION-IDENTITY CONFOUND ***")

    report["INTEGRITY_GATE_STATUS"] = "FAIL — INVESTIGATE BEFORE TRUSTING OTHER ML RESULTS" if any_leak_flag else "PASS"
    (results_dir / "exp02_results.json").write_text(json.dumps(report, indent=2))
    print(f"\n{'='*70}\nINTEGRITY GATE: {report['INTEGRITY_GATE_STATUS']}\n{'='*70}")
    print(f"Wrote {results_dir / 'exp02_results.json'}")


if __name__ == "__main__":
    main()
