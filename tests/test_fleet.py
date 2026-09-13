"""Fleet mode (T-049) — role B/D's actual workflow: many captures in, one
aggregated view out, every per-tunnel guarantee (evidence, cited baseline)
kept intact. No blended score (DEC-007 applied at fleet scale); a file that
fails to parse is its own row, never silently dropped."""
import os
import shutil

import pytest

from tunnelscope.report.fleet import scan, rollup, render, render_json

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")


@pytest.fixture
def sample_dir(tmp_path):
    for name in ["classical-baseline.pcap", "pq-downgrade.pcap"]:
        shutil.copy(os.path.join(CAP, name), tmp_path / name)
    (tmp_path / "not-a-pcap.pcap").write_text("this is not a real capture")
    return str(tmp_path)


def test_scan_finds_every_file_never_silently_skips(sample_dir):
    fleet = scan(sample_dir)
    assert fleet["n_scanned"] == 3
    assert len(fleet["tunnels"]) == 2
    assert len(fleet["errors"]) == 1
    assert "not-a-pcap.pcap" in fleet["errors"][0]["path"]


def test_rollup_counts_per_rule_not_a_blended_score(sample_dir):
    fleet = scan(sample_dir)
    roll = rollup(fleet)
    # classical-baseline + pq-downgrade both use MODP-2048 -> both FAIL DISA V-207193
    assert roll["DISA-VPN-SRG-V2R6"]["V-207193"]["FAIL"] == 2
    # pq-downgrade specifically fails the downgrade rule; classical-baseline (never offered PQ) does not
    assert roll["DST-NQM-2026"]["DST-PQ-DOWNGRADE"]["FAIL"] == 1


def test_render_html_never_shows_a_single_fleet_score(sample_dir):
    out = render(sample_dir)
    assert "not-a-pcap.pcap" in out  # error surfaced, not dropped
    assert "DOWNGRADED" in out       # per-tunnel posture still shown
    assert "/100" not in out         # no blended fleet-wide score


def test_render_json_shape(sample_dir):
    j = render_json(sample_dir)
    assert j["n_scanned"] == 3
    assert len(j["tunnels"]) == 2
    assert any(t["quantum_posture"].startswith("DOWNGRADED") for t in j["tunnels"])
