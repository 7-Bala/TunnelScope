from __future__ import annotations

import csv
import gzip
from pathlib import Path
import re

from dataset.build_traffic_datasheet import (
    ROOT,
    build_datasheet,
    build_datasheet_text,
    check_discrepancies,
    count_by_arm,
    count_by_class,
    count_by_rep,
    count_by_source,
    count_class_by_arm,
    load_manifests,
)


def test_builder_deterministic(tmp_path):
    """Requirement a: running the builder twice gives identical text."""
    text1 = build_datasheet_text()
    text2 = build_datasheet_text()
    assert text1 == text2
    assert len(text1) > 0

    # Also test that build_datasheet produces byte-identical files on repeated runs
    out1 = tmp_path / "out1.md"
    out2 = tmp_path / "out2.md"
    build_datasheet(output_path=out1)
    build_datasheet(output_path=out2)
    assert out1.read_bytes() == out2.read_bytes()
    assert out1.read_text(encoding="utf-8") == text1

    datasheet_path = ROOT / "dataset" / "TRAFFIC-DATASHEET.md"
    assert datasheet_path.exists()
    assert datasheet_path.read_text(encoding="utf-8") == text1


def test_total_sessions_equals_distinct_tags():
    """Requirement b: the total sessions number in the output equals the number of distinct tags across manifests."""
    manifest_paths = [
        ROOT / "testbed" / "captures" / "exp05" / "manifest.csv",
        ROOT / "testbed" / "captures" / "exp15" / "traffic" / "manifest.csv",
        ROOT / "testbed" / "captures" / "exp16" / "manifest.csv",
    ]

    distinct_tags: set[str] = set()
    for mpath in manifest_paths:
        with open(mpath, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if row:
                    distinct_tags.add(row[0])

    text = build_datasheet_text()
    match = re.search(r"total sessions:\s*(\d+)", text, re.IGNORECASE)
    assert match is not None, "Total sessions not found in generated datasheet"
    total_in_output = int(match.group(1))

    assert total_in_output == len(distinct_tags)
    assert total_in_output == 300


def test_sum_of_per_class_counts_equals_total():
    """Requirement c: the sum of the per-class counts equals the total."""
    text = build_datasheet_text()
    match = re.search(r"total sessions:\s*(\d+)", text, re.IGNORECASE)
    assert match is not None
    total_sessions = int(match.group(1))

    # Parse per-class counts from the Markdown table under 'By class'
    class_section = re.search(r"### By class\s*\n\s*\|[^\n]+\|\s*\n\s*\|[^\n]+\|\s*\n((?:\|[^\n]+\|\s*\n)+)", text)
    assert class_section is not None, "By class table not found"

    table_rows = class_section.group(1).strip().splitlines()
    per_class_counts = []
    for row in table_rows:
        parts = [p.strip() for p in row.split("|")[1:-1]]
        if len(parts) >= 2:
            per_class_counts.append(int(parts[1]))

    assert len(per_class_counts) > 0
    assert sum(per_class_counts) == total_sessions

    # Also test via loaded sessions and function
    sessions = load_manifests()
    by_class = count_by_class(sessions)
    assert sum(by_class.values()) == total_sessions


def test_tbd_owner_decision_appears_twice():
    """Requirement d: the words TBD (owner decision) appear twice in the output (licence and citation)."""
    text = build_datasheet_text()
    assert text.count("TBD (owner decision)") == 2

    # Verify both sections exist
    assert re.search(r"## Licence\s*\n\s*TBD \(owner decision\)", text) is not None
    assert re.search(r"## Citation\s*\n\s*TBD \(owner decision\)", text) is not None


def test_section_order_and_content():
    """Verify sections appear in the exact order required."""
    text = build_datasheet_text()
    headers = [
        "## Contents",
        "## How it was made",
        "## Files and format",
        "## Known limits",
        "## Licence",
        "## Citation",
        "## Discrepancies",
    ]
    indices = [text.find(h) for h in headers]
    for i, h in enumerate(headers):
        assert indices[i] != -1, f"Missing section header: {h}"
    assert indices == sorted(indices), "Sections are not in the required order"


def test_discrepancies_real_dataset_is_none():
    """Verify real dataset has zero discrepancies and output says 'none'."""
    sessions = load_manifests()
    discrepancies = check_discrepancies(sessions)
    assert len(discrepancies) == 0

    text = build_datasheet_text(sessions=sessions, discrepancies=discrepancies)
    assert re.search(r"## Discrepancies\s*\n\s*none", text) is not None


def test_deduplication_keeps_first_row(tmp_path):
    """Verify load_manifests deduplication keeps the first row on duplicates."""
    # Write a test manifest with a duplicate tag
    manifest_file = tmp_path / "manifest.csv"
    with open(manifest_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["tag1", "base", "web", 1, 100, 50, "hash1"])
        writer.writerow(["tag1", "tfc", "bulk", 2, 200, 999, "hash2"])  # duplicate

    defs = [("EXP-TEST", "manifest.csv", "")]
    sessions = load_manifests(root=tmp_path, manifest_defs=defs)

    assert len(sessions) == 1
    assert sessions[0]["tag"] == "tag1"
    assert sessions[0]["arm"] == "base"
    assert sessions[0]["class"] == "web"
    assert sessions[0]["packets"] == 50


def test_discrepancies_detected_on_mismatch_or_missing(tmp_path):
    """Verify check_discrepancies catches missing files and row count mismatches."""
    # 1. Missing table session
    missing_session = {
        "source": "EXP-15",
        "tag": "test-missing",
        "arm": "tun",
        "class": "web",
        "rep": 1,
        "seed": 1,
        "packets": 100,
        "sha256": "abc",
        "pkts_dir": tmp_path,
    }

    # 2. Row count mismatch table session
    mismatch_tag = "test-mismatch"
    mismatch_file = tmp_path / f"{mismatch_tag}.pkts.csv.gz"
    with gzip.open(mismatch_file, "wt", newline="", encoding="utf-8") as gz:
        writer = csv.writer(gz)
        writer.writerow(["t", "dir", "len"])
        for i in range(3):
            writer.writerow([f"0.{i}", "out", "64"])

    mismatch_session = {
        "source": "EXP-05",
        "tag": mismatch_tag,
        "arm": "base",
        "class": "bulk",
        "rep": 1,
        "seed": 1,
        "packets": 10,  # Manifest says 10, actual data rows = 3
        "sha256": "def",
        "pkts_dir": tmp_path,
    }

    disc = check_discrepancies([missing_session, mismatch_session])
    assert len(disc) == 2

    disc_missing = [d for d in disc if "test-missing" in d]
    assert len(disc_missing) == 1
    assert "missing" in disc_missing[0]

    disc_mismatch = [d for d in disc if "test-mismatch" in d]
    assert len(disc_mismatch) == 1
    assert "row count mismatch" in disc_mismatch[0]
    assert "manifest=10" in disc_mismatch[0]
    assert "table=3" in disc_mismatch[0]

    # Verify rendering under Discrepancies heading
    text = build_datasheet_text(sessions=[missing_session, mismatch_session], discrepancies=disc)
    disc_section = text.split("## Discrepancies")[1]
    assert "none" not in disc_section
    assert "test-missing" in disc_section
    assert "test-mismatch" in disc_section


def test_corrupted_table_handled_as_discrepancy(tmp_path):
    """Verify check_discrepancies catches corrupted files and reports them without crashing."""
    corrupted_tag = "test-corrupted"
    corrupted_file = tmp_path / f"{corrupted_tag}.pkts.csv.gz"
    corrupted_file.write_bytes(b"not-gzip-data-at-all\xff\xfe")

    corrupted_session = {
        "source": "EXP-16",
        "tag": corrupted_tag,
        "arm": "base",
        "class": "bulk",
        "rep": 1,
        "seed": 1,
        "packets": 5,
        "sha256": "xyz",
        "pkts_dir": tmp_path,
    }

    disc = check_discrepancies([corrupted_session])
    assert len(disc) == 1
    assert "test-corrupted" in disc[0]
    assert "error reading table" in disc[0]
