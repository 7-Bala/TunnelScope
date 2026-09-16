"""Robustness of the failure paths themselves (T-055).

The project's core claim is that it reports honestly rather than confidently
wrong. That property was only ever tested on captures it CAN read. These tests
cover the other half: what happens when the input is missing, unreadable, or
when the analysis stack drifts underneath us. Every case below was a real
reproduced defect before this file existed — most of them exited 0.
"""
import os
import shutil

import pytest

from tunnelscope.cli import main
from tunnelscope.errors import DependencyError, InputError
from tunnelscope.ingest import tshark
from tunnelscope.ingest.tshark import _flags, _float, capture_summary, preflight
from tunnelscope.report.fleet import scan

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")
GOOD = os.path.join(CAP, "classical-baseline.pcap")


# --- "scanned nothing" must never read as "found nothing wrong" -------------

def test_fleet_on_missing_directory_is_an_error_not_a_clean_scan():
    # rglob on a missing dir yields nothing, so this used to return
    # n_scanned=0 with no errors and exit 0 — a typo'd path in a cron job was
    # indistinguishable from a healthy fleet.
    with pytest.raises(InputError, match="directory not found"):
        scan("/definitely/not/here")


def test_fleet_on_directory_with_no_captures_is_an_error(tmp_path):
    with pytest.raises(InputError, match="no .pcap"):
        scan(str(tmp_path))


def test_fleet_on_a_file_instead_of_a_directory_is_an_error():
    with pytest.raises(InputError, match="not a directory"):
        scan(GOOD)


# --- unreadable input explains itself --------------------------------------

def test_missing_capture_names_the_file(tmp_path):
    with pytest.raises(InputError, match="capture not found"):
        capture_summary(str(tmp_path / "nope.pcap"))


def test_corrupt_capture_surfaces_tsharks_own_reason(tmp_path):
    # check=True used to bury tshark's stderr inside CalledProcessError, so the
    # operator saw the whole command line but never WHY it failed.
    bad = tmp_path / "corrupt.pcap"
    bad.write_text("this is not a capture")
    with pytest.raises(InputError, match="isn't a capture file|could not read"):
        capture_summary(str(bad))


# --- parsing tshark output is tolerant, not fatal ---------------------------

def test_flags_are_read_as_hex_at_every_call_site():
    # A bare "20" read as decimal is 0x14: the responder bit reads clear,
    # ike_sa_crypto() returns {}, and the whole IKE crypto finding silently
    # disappears. Both call sites must agree that flags are hex.
    assert _flags("0x20") == 0x20
    assert _flags("20") == 0x20          # would be 20 (decimal) under _int()
    assert _flags("0x20,0x08") == 0x20   # multi-occurrence takes the first
    assert _flags("") == 0
    assert _flags("nonsense") == 0


def test_unparseable_numbers_are_gaps_not_crashes():
    assert _float("") == 0.0
    assert _float("not-a-time") == 0.0
    assert _float("1.25") == 1.25


# --- the analysis stack is verified before it is trusted --------------------

def test_preflight_reports_provenance_on_a_healthy_stack():
    info = preflight()
    assert info["tshark"] and info["tshark_version"]


def test_preflight_refuses_to_run_when_tshark_dropped_a_field(monkeypatch):
    # Simulates upstream dissector drift (T-024 saw ADDKE naming move). A field
    # that stops resolving yields EMPTY findings, not an error — which is
    # exactly "absence scored as compliance". Refuse loudly instead.
    surviving = frozenset(f for f in tshark.REQUIRED_FIELDS if f != "isakmp.tf.id.dh")
    monkeypatch.setattr(tshark, "_known_fields", lambda: surviving)
    with pytest.raises(DependencyError, match="isakmp.tf.id.dh"):
        preflight()


def test_missing_tshark_names_the_dependency(monkeypatch):
    monkeypatch.setattr(tshark.shutil, "which", lambda _: None)
    with pytest.raises(DependencyError, match="tshark not found"):
        tshark.tshark_bin()


# --- exit codes let automation tell the cases apart ------------------------

def test_input_errors_exit_2_not_0(tmp_path, capsys):
    assert main(["fleet", str(tmp_path / "missing"), "--json"]) == 2
    assert main(["analyze", str(tmp_path / "nope.pcap")]) == 2


def test_default_run_still_exits_0_even_with_fails(capsys):
    # The demo script and existing docs rely on this; the findings gate is
    # opt-in precisely so enabling it cannot change documented behaviour.
    assert main(["assess", GOOD]) == 0


def test_fail_on_findings_exits_1_when_fails_present(capsys):
    assert main(["assess", GOOD, "--fail-on-findings", "--json"]) == 1


def test_fleet_fail_on_findings_counts_unparsed_captures(tmp_path, capsys):
    # A capture that never parsed has NOT been cleared; a monitoring gate must
    # not treat "we could not read it" as "it is fine".
    shutil.copy(GOOD, tmp_path / "good.pcap")
    (tmp_path / "bad.pcap").write_text("junk")
    assert main(["fleet", str(tmp_path), "--json", "--fail-on-findings"]) == 1


def test_doctor_reports_the_stack(capsys):
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "tshark" in out and "resolve on this tshark" in out
