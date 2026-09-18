"""T-054 — the findings differential's comparison and allow-file logic
(build/findings_diff.py). The git-worktree run itself is exercised in CI."""
import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("findings_diff", os.path.join(ROOT, "build", "findings_diff.py"))
fd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fd)


def test_diff_reports_value_status_confidence_and_records():
    base = {"a.pcap": {"ike:1": {"pfs": ["INFERRED", True, 0.9], "mode": ["NOT_OBSERVABLE", None, 1.0]},
                       "ike:2": {"pfs": ["INFERRED", False, 0.9]}}}
    head = {"a.pcap": {"ike:1": {"pfs": ["INFERRED", True, 0.8], "mode": ["NOT_OBSERVABLE", None, 1.0]},
                       "ike:3": {"pfs": ["INFERRED", False, 0.9]}}}
    got = {(p, r, n) for p, r, n, _, _ in fd.diff(base, head)}
    assert got == {("a.pcap", "ike:1", "pfs"), ("a.pcap", "ike:2", "<record>"),
                   ("a.pcap", "ike:3", "<record>")}


def test_identical_dumps_have_no_diff():
    d = {"a.pcap": {"ike:1": {"pfs": ["INFERRED", True, 0.9]}}}
    assert fd.diff(d, d) == []


def test_allow_file_requires_a_reason(tmp_path):
    p = tmp_path / "allow.txt"
    p.write_text("# comment only\n\nencap/* :: esp_*  # T-057 offsets\n")
    assert fd.load_allow(str(p)) == [("encap/*", "esp_*", "T-057 offsets")]
    p.write_text("encap/* :: esp_*\n")
    with pytest.raises(SystemExit):
        fd.load_allow(str(p))
