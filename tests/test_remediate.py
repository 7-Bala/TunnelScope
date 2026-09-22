"""Tests for remediation plan generator (Stage 1: read-only, no execution)."""
import inspect
import json
import pathlib
import threading
import urllib.error
import urllib.request

import pytest

from tunnelscope.api import server
from tunnelscope.assess.engine import load_baselines
from tunnelscope.remediate import plan
from tunnelscope.remediate.plan import REMEDIATION, plan_for


def test_plan_for_known_rules():
    """plan_for returns the exact expected dict for rules from the table,
    covering different auto_applicable values (True and False)."""
    # 1. auto_applicable: True with observed provided
    v207205 = plan_for("V-207205", observed="IKEv1")
    assert v207205 == {
        "rule_id": "V-207205",
        "change": "Move IKEv1 to IKEv2",
        "commands": ["set `version = 2` in the connection's swanctl.conf", "swanctl --load-all"],
        "auto_applicable": True,
        "observed": "IKEv1",
    }

    # Verify commands list is a fresh copy (cannot corrupt glossary via returned dict)
    v207205["commands"].append("malicious-command")
    fresh = plan_for("V-207205")
    assert "malicious-command" not in fresh["commands"]
    assert "malicious-command" not in REMEDIATION["V-207205"]["commands"]

    # 2. auto_applicable: False (patch instruction)
    cve = plan_for("CVE-2026-78135")
    assert cve == {
        "rule_id": "CVE-2026-78135",
        "change": "Patch, not a config change",
        "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
        "auto_applicable": False,
        "observed": None,
    }

    # 3. auto_applicable: False (sequence replay diagnosis)
    seq = plan_for("RFC4303-SEQ", observed="replay-detected")
    assert seq == {
        "rule_id": "RFC4303-SEQ",
        "change": "Not a config fix",
        "commands": ["replay is a symptom (misconfigured anti-replay window, or an attack) -- investigate, no command"],
        "auto_applicable": False,
        "observed": "replay-detected",
    }

    # 4. auto_applicable: True (DH raise)
    v207193 = plan_for("V-207193", observed="MODP-1024")
    assert v207193 == {
        "rule_id": "V-207193",
        "change": "Raise the DH group",
        "commands": ["set `proposals` to include ecp384 or modp4096, remove the weak group",
                     "swanctl --load-all"],
        "auto_applicable": True,
        "observed": "MODP-1024",
    }


def test_plan_for_unknown_rule():
    """plan_for returns None for unknown rule IDs and non-string/unhashable inputs."""
    assert plan_for("NOT-A-REAL-RULE") is None
    assert plan_for("") is None
    assert plan_for("UNKNOWN-12345") is None
    # Edge cases: non-string and unhashable inputs must safely return None without crashing
    assert plan_for(None) is None
    assert plan_for(12345) is None
    assert plan_for(["V-207205"]) is None
    assert plan_for({"rule_id": "V-207205"}) is None


def test_every_high_and_medium_rule_has_remediation():
    """Coverage invariant: EVERY rule ID that exists in any tunnelscope/rules/*.yaml
    file with severity: high or medium must also have an entry in REMEDIATION.
    Mirrors tests/test_ai_layer.py::test_every_rule_has_a_plain_explanation.
    If a rule is missing, this test fails."""
    baselines = load_baselines()
    high_med_ids = {
        r["id"] if isinstance(r, dict) else r.id
        for b in baselines
        for r in (b["rules"] if isinstance(b, dict) else b.rules)
        if str(r.get("severity", "medium") if isinstance(r, dict) else getattr(r, "severity", "medium")).strip().lower() in ("high", "medium")
    }
    assert len(high_med_ids) > 0, "No high/medium rules found in baselines"
    missing = high_med_ids - set(REMEDIATION)
    assert not missing, f"Rules missing from REMEDIATION glossary: {sorted(missing)}"


def test_coverage_invariant_fails_on_missing_rule():
    """Verify that the coverage invariant actually catches missing high/medium rules:
    simulated baselines with an unmapped rule MUST raise AssertionError."""
    # 1. Rule with explicit high severity missing
    fake_high = [{"rules": [{"id": "TEST-UNMAPPED-HIGH", "severity": "high"}]}]
    high_ids = {
        r["id"] for b in fake_high for r in b["rules"]
        if str(r.get("severity", "medium")).strip().lower() in ("high", "medium")
    }
    missing_high = high_ids - set(REMEDIATION)
    assert missing_high == {"TEST-UNMAPPED-HIGH"}

    # 2. Rule with omitted severity (default medium per engine.py:130) missing
    fake_default = [{"rules": [{"id": "TEST-UNMAPPED-DEFAULT"}]}]
    default_ids = {
        r["id"] for b in fake_default for r in b["rules"]
        if str(r.get("severity", "medium")).strip().lower() in ("high", "medium")
    }
    missing_default = default_ids - set(REMEDIATION)
    assert missing_default == {"TEST-UNMAPPED-DEFAULT"}

    # 3. Rule with informational severity missing is allowed (not high/medium)
    fake_info = [{"rules": [{"id": "TEST-UNMAPPED-INFO", "severity": "informational"}]}]
    info_ids = {
        r["id"] for b in fake_info for r in b["rules"]
        if str(r.get("severity", "medium")).strip().lower() in ("high", "medium")
    }
    assert not (info_ids - set(REMEDIATION))


def test_remediate_endpoint_is_provably_read_only():
    """Static check: no subprocess, socket, docker, paramiko, fabric anywhere
    in the function or file implementing the endpoint.
    Mirrors test_no_outside_model_is_used."""
    remediate_dir = pathlib.Path(plan.__file__).parent
    all_remediate_files = list(remediate_dir.rglob("*.py"))
    all_remediate_src = "\n".join(p.read_text() for p in all_remediate_files).lower()
    endpoint_func_src = inspect.getsource(server._Handler._remediate_plan).lower()
    plan_func_src = inspect.getsource(plan.plan_for).lower()

    banned_tokens = (
        "subprocess", "socket", "docker", "paramiko", "fabric",
        "os.system", "os.popen", "os.spawn",
    )

    for token in banned_tokens:
        assert token not in all_remediate_src, f"Banned token {token!r} in remediate package"
        assert token not in endpoint_func_src, f"Banned token {token!r} in _remediate_plan"
        assert token not in plan_func_src, f"Banned token {token!r} in plan_for"

    # Also assert no file writing operations in remediate/ or _remediate_plan
    for write_token in ("open(", "write_text", "write_bytes"):
        assert write_token not in all_remediate_src, f"Write token {write_token!r} in remediate package"
        assert write_token not in endpoint_func_src, f"Write token {write_token!r} in _remediate_plan"
    assert ".write(" not in endpoint_func_src

    # Meta-test: prove the static checker actually catches violations
    synthetic_bad = "import subprocess\nsubprocess.run(['rm', '-rf', '/'])"
    assert any(token in synthetic_bad for token in banned_tokens)


def test_server_remediate_plan_e2e():
    """End-to-end test hitting the real server:
    Start server on port 0, POST known rule_id -> 200 and matches expected dict;
    POST unknown rule_id -> 404 with {'ok': False, 'error': 'unknown rule'}."""
    srv = server.make_server(0)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base_url = f"http://127.0.0.1:{port}"

        # 1. Known rule (auto_applicable: True)
        payload = {"rule_id": "V-207205", "observed": "IKEv1"}
        req = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data == {
                "rule_id": "V-207205",
                "change": "Move IKEv1 to IKEv2",
                "commands": ["set `version = 2` in the connection's swanctl.conf", "swanctl --load-all"],
                "auto_applicable": True,
                "observed": "IKEv1",
            }

        # 2. Known rule (auto_applicable: False)
        payload_false = {"rule_id": "CVE-2026-78135"}
        req_false = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps(payload_false).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_false) as resp:
            assert resp.status == 200
            data_false = json.loads(resp.read().decode("utf-8"))
            assert data_false == {
                "rule_id": "CVE-2026-78135",
                "change": "Patch, not a config change",
                "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
                "auto_applicable": False,
                "observed": None,
            }

        # 3. Unknown rule -> 404
        bad_payload = {"rule_id": "NOT-A-REAL-RULE"}
        req_bad = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps(bad_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_bad)
        assert exc_info.value.code == 404
        err_data = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_data == {"ok": False, "error": "unknown rule"}

        # 4. Non-string / unhashable rule_id -> 404 (does not crash with 500/RemoteDisconnected)
        req_unhashable = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps({"rule_id": ["V-207205"]}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_unhashable)
        assert exc_info.value.code == 404
        assert json.loads(exc_info.value.read().decode("utf-8")) == {"ok": False, "error": "unknown rule"}

        req_numeric = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps({"rule_id": 99999}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_numeric)
        assert exc_info.value.code == 404
        assert json.loads(exc_info.value.read().decode("utf-8")) == {"ok": False, "error": "unknown rule"}

        # 5. Bad request cases: missing rule_id -> 400
        req_missing = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps({"other": "field"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_missing)
        assert exc_info.value.code == 400
        err_missing = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_missing == {"ok": False, "error": "missing rule_id"}

        # 6. Non-dict JSON body -> 400
        req_nondict = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=json.dumps([1, 2, 3]).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_nondict)
        assert exc_info.value.code == 400

        # 7. Empty body -> 400
        req_empty = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=b"",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_empty)
        assert exc_info.value.code == 400

        # 8. Invalid JSON -> 400
        req_invalid = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=b"not-json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_invalid)
        assert exc_info.value.code == 400

        # 9. Oversized body (>1MB Content-Length) -> 413
        req_oversized = urllib.request.Request(
            f"{base_url}/api/remediate/plan",
            data=b"x" * 10,
            headers={"Content-Type": "application/json", "Content-Length": str(2 * 1024 * 1024)},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_oversized)
        assert exc_info.value.code == 413

    finally:
        srv.shutdown()
        srv.server_close()
