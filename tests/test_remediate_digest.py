"""T-104: Apply runs exactly what the human previewed, or refuses. Uses the in-memory lab."""
import json

import pytest
from fake_lab import ALICE_CONF, FakeLab, sas

from tunnelscope.remediate.execute import apply_remediation, preview_remediation

A, FA = "sih26-alice-pq", "/tmp/exp15-alice.conf"


@pytest.fixture
def lab(monkeypatch, tmp_path):
    return FakeLab(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "PASS"})).install(monkeypatch, tmp_path)


def test_preview_digest_is_deterministic(lab, tmp_path):
    a = preview_remediation("V-207193", A, history_dir=tmp_path)
    b = preview_remediation("V-207193", A, history_dir=tmp_path)
    assert a["ok"] and len(a["digest"]) == 64 and a["digest"] == b["digest"]
    assert a["source"] == "hand-written"


def test_apply_with_the_previewed_digest_runs(lab, tmp_path):
    d = preview_remediation("V-207193", A, history_dir=tmp_path)["digest"]
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, digest=d, require_digest=True)
    assert r["ok"] is True and r["confirmed_fixed"] is True, r
    audit = [json.loads(l) for l in (tmp_path / "remediate.jsonl").read_text().splitlines()]
    applied = [x for x in audit if x.get("decision") == "applied"]
    assert applied and applied[-1]["digest"] == d and applied[-1]["source"] == "hand-written"


def test_apply_without_a_digest_is_refused_when_required(lab, tmp_path):
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, require_digest=True)
    assert r["decision"] == "refused" and r["stage"] == "validate" and "preview" in r["error"]
    assert lab.fs[A][FA] == ALICE_CONF


def test_config_changed_since_the_preview_is_refused_and_nothing_changes(lab, tmp_path):
    d = preview_remediation("V-207193", A, history_dir=tmp_path)["digest"]
    lab.fs[A][FA] = lab.fs[A][FA].replace("proposals = aes256-sha256-modp2048", "proposals = aes128-sha256-modp2048", 1)
    changed = lab.fs[A][FA]
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, digest=d, require_digest=True)
    assert r["stage"] == "stale_preview" and "Nothing was changed" in r["error"]
    assert lab.fs[A][FA] == changed
    assert not any(a[0] == "tcpdump" for _, a, _ in lab.calls), "refused before the baseline capture"


def test_a_digest_for_another_target_or_rule_is_refused(lab, tmp_path):
    d_bob = preview_remediation("V-207193", "sih26-bob-pq", history_dir=tmp_path)["digest"]
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, digest=d_bob)
    assert r["stage"] == "stale_preview"
    d_other = preview_remediation("V-207223", A, history_dir=tmp_path)["digest"]
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, digest=d_other)
    assert r["stage"] == "stale_preview"


def test_the_same_digest_cannot_be_applied_twice(lab, tmp_path):
    d = preview_remediation("V-207193", A, history_dir=tmp_path)["digest"]
    assert apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, digest=d)["ok"] is True
    after = dict(lab.fs[A])
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, digest=d)
    assert r["decision"] == "refused" and r["stage"] in ("stale_preview", "dry_run")
    assert lab.fs[A] == after
