#!/usr/bin/env python3
"""EXP-01 — ESP cipher-family constraint/sieve.

Tests F-04: the claim that ESP cipher-suite FAMILY can be narrowed to a small
candidate set using only observed ESP frame lengths (IV/ICV/alignment
structural constants), with no keys and no dissector support for the actual
transform.

Method (deterministic constraint satisfaction, not ML):
  For a candidate cipher suite (iv_len, icv_len, alignment) and an observed
  ESP-content length `c` (= outer IP total length - 20B outer IPv4 header -
  8B ESP SPI/Seq fields):
      ciphertext_len = c - iv_len - icv_len
  The suite is CONSISTENT with this packet iff ciphertext_len >= 0 AND
  ciphertext_len % alignment == 0. A suite is ELIMINATED by a capture if any
  single observed packet is inconsistent with it. The surviving candidate
  set after all packets is the sieve's output.

Ground truth is read from the .groundtruth.json file written by
testbed/scripts/run_arm.sh, which is itself read from strongSwan's own
swanctl/vici state (T2) — never from this script's own inference. This
script never uses its own output as its own validation (no circular
validation, per project decision).

Usage: python3 analyze.py <captures-dir> <results-dir>
"""
import json
import re
import subprocess
import sys
from pathlib import Path

# --- Cipher-suite catalog -----------------------------------------------
# (iv_len, icv_len, alignment) in bytes. Includes suites NOT present in our
# testbed captures (marked not_tested) specifically to test for FALSE
# ELIMINATION: the sieve must never eliminate a suite that is structurally
# consistent with the evidence just because we didn't generate it.
CATALOG = {
    "AES-CBC+HMAC-SHA1-96":        dict(iv=16, icv=12, align=16, tested=False),
    "AES-CBC+HMAC-SHA256-128":     dict(iv=16, icv=16, align=16, tested=True),
    "AES-CBC+AES-XCBC-MAC-96":     dict(iv=16, icv=12, align=16, tested=False),
    "AES-CTR+HMAC-SHA1-96":        dict(iv=8,  icv=12, align=4,  tested=False),
    "AES-CTR+HMAC-SHA256-128":     dict(iv=8,  icv=16, align=4,  tested=True),
    "AES-GCM-16":                  dict(iv=8,  icv=16, align=4,  tested=True),
    "AES-CCM-16":                  dict(iv=8,  icv=16, align=4,  tested=False),
    "ChaCha20-Poly1305":           dict(iv=8,  icv=16, align=4,  tested=True),
}

# arm name -> (ground-truth family key into CATALOG, key length is NOT part
# of the family — that's the EXP-02 question, deliberately not encoded here)
ARM_TO_FAMILY = {
    "cs-aes128gcm16": "AES-GCM-16",
    "cs-aes256gcm16": "AES-GCM-16",
    "cs-aes128cbc-sha256": "AES-CBC+HMAC-SHA256-128",
    "cs-aes256cbc-sha256": "AES-CBC+HMAC-SHA256-128",
    "cs-aes128ctr-sha256": "AES-CTR+HMAC-SHA256-128",
    "cs-chacha20poly1305": "ChaCha20-Poly1305",
    "cs-transport-aes256gcm16": "AES-GCM-16",
}

OUTER_IPV4_HDR = 20
ESP_SPI_SEQ = 8


def extract_esp_content_lengths(pcap_path: Path) -> list[int]:
    """Return the list of ESP-content lengths (post SPI/Seq, pre-decrypt) for
    every ESP packet in the capture, in both directions, using tshark as the
    packet-parsing oracle (we do not reimplement IP/ESP header parsing —
    reuse mature tooling per the project's own decision log)."""
    out = subprocess.run(
        ["tshark", "-r", str(pcap_path), "-Y", "esp", "-T", "fields", "-e", "ip.len"],
        capture_output=True, text=True, check=True,
    ).stdout
    lengths = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        ip_len = int(line)
        esp_content = ip_len - OUTER_IPV4_HDR - ESP_SPI_SEQ
        lengths.append(esp_content)
    return lengths


def sieve(esp_content_lengths: list[int]) -> dict:
    """Run the constraint sieve incrementally, recording the candidate set
    after each additional packet — this both gives the final answer and
    answers 'minimum observation required' directly."""
    trace = []
    surviving = set(CATALOG.keys())
    for i, c in enumerate(esp_content_lengths, start=1):
        still_alive = set()
        for name in surviving:
            spec = CATALOG[name]
            ct = c - spec["iv"] - spec["icv"]
            if ct >= 0 and ct % spec["align"] == 0:
                still_alive.add(name)
        surviving = still_alive
        trace.append({"n_packets": i, "esp_content": c, "candidates_remaining": sorted(surviving)})
        if len(surviving) <= 1:
            # Nothing more to learn structurally; record remaining packets
            # anyway for the robustness check (candidate set must not
            # spuriously CHANGE once minimal, i.e. no false elimination of
            # the true suite by a later packet).
            pass
    return {"final_candidates": sorted(surviving), "trace": trace}


def parse_ground_truth(gt_path: Path) -> str | None:
    text = json.loads(gt_path.read_text())["alice_list_sas"]
    # e.g. "ESP:AES_GCM_16-128" or "ESP:AES_CBC-256/HMAC_SHA2_256_128" etc.
    m = re.search(r"ESP:([A-Z0-9_]+(?:-\d+)?(?:/[A-Z0-9_]+)?)", text)
    return m.group(1) if m else None


def main():
    captures_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures")
    results_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "results")
    results_dir.mkdir(parents=True, exist_ok=True)

    report = {"catalog": CATALOG, "arms": {}}

    for arm, family in ARM_TO_FAMILY.items():
        pcap = captures_dir / f"{arm}.pcap"
        gt = captures_dir / f"{arm}.groundtruth.json"
        if not pcap.exists():
            print(f"SKIP {arm}: pcap not found at {pcap}")
            continue

        lengths = extract_esp_content_lengths(pcap)
        result = sieve(lengths)
        gt_raw = parse_ground_truth(gt) if gt.exists() else None

        true_family_in_candidates = family in result["final_candidates"]
        ambiguity_set = result["final_candidates"]
        # packets needed until the candidate set stopped shrinking
        min_n = next(
            (t["n_packets"] for t in result["trace"]
             if set(t["candidates_remaining"]) == set(ambiguity_set)),
            len(result["trace"]),
        )

        entry = {
            "arm": arm,
            "true_family": family,
            "ground_truth_raw_string": gt_raw,
            "n_esp_packets_observed": len(lengths),
            "distinct_esp_content_lengths": sorted(set(lengths)),
            "final_candidate_set": ambiguity_set,
            "candidate_set_size": len(ambiguity_set),
            "true_family_survived": true_family_in_candidates,  # MUST be True or the sieve is broken
            "packets_needed_to_converge": min_n,
        }
        report["arms"][arm] = entry

        status = "OK" if true_family_in_candidates else "*** SIEVE BUG: TRUE FAMILY ELIMINATED ***"
        print(f"[{arm}] true={family} candidates={ambiguity_set} "
              f"(n={len(ambiguity_set)}, converged @ packet {min_n}/{len(lengths)}) {status}")

    (results_dir / "exp01_results.json").write_text(json.dumps(report, indent=2))
    print(f"\nWrote {results_dir / 'exp01_results.json'}")


if __name__ == "__main__":
    main()
