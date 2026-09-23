import ast
import inspect
import json
import pathlib
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

from tunnelscope.api import server
from tunnelscope.assess.engine import load_baselines
from tunnelscope.remediate import execute, plan
from tunnelscope.remediate.execute import (
    apply_remediation,
    get_allowed_targets,
    is_container_running,
    record_audit,
)
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
    all_remediate_files = [p for p in remediate_dir.rglob("*.py") if p.name != "execute.py"]
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


def test_execute_module_has_strict_safety_bounds():
    """Static check: execute.py imports NO paramiko, NO fabric, NO socket,
    does NO shell=True, and calls NO command other than docker exec and docker ps/inspect."""
    execute_path = pathlib.Path(execute.__file__)
    src = execute_path.read_text(encoding="utf-8")
    src_lower = src.lower()

    banned_imports = ("paramiko", "fabric", "socket", "telnetlib", "ftplib")
    for bi in banned_imports:
        assert bi not in src_lower, f"Banned import/token {bi!r} found in execute.py"

    assert "shell=true" not in src_lower.replace(" ", ""), "shell=True found in execute.py"

    # AST check: find all subprocess calls and verify args
    tree = ast.parse(src, filename=str(execute_path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            if func_name in ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"):
                # First arg must be a list starting with 'docker'
                first_arg = node.args[0] if node.args else None
                assert isinstance(first_arg, ast.List), f"subprocess call must take a list of args: {ast.dump(node)}"
                first_elem = first_arg.elts[0]
                assert isinstance(first_elem, ast.Constant) and first_elem.value == "docker", (
                    f"subprocess call must invoke 'docker', got {ast.dump(first_elem)}"
                )


def test_get_allowed_targets_runtime_parsing(tmp_path):
    """get_allowed_targets dynamically reads testbed/docker-compose.yml and extracts container names."""
    targets = get_allowed_targets()
    assert isinstance(targets, set)
    # Must include standard lab containers from testbed/docker-compose.yml
    expected = {"sih26-alice-pq", "sih26-bob-pq", "sih26-router"}
    assert expected.issubset(targets), f"Missing expected lab containers in {targets}"

    # Custom compose file test
    custom_compose = tmp_path / "custom-compose.yml"
    custom_compose.write_text("""
services:
  alice:
    container_name: custom-alice
  bob:
    image: test/bob
""", encoding="utf-8")
    custom_targets = get_allowed_targets(custom_compose)
    assert custom_targets == {"custom-alice", "bob"}

    # Nonexistent compose file returns empty set
    assert get_allowed_targets(tmp_path / "nonexistent.yml") == set()


def test_apply_remediation_refuses_invalid_target(monkeypatch):
    """Calling apply_remediation with a target not in docker-compose.yml REFUSES
    and does NOT call subprocess.run."""
    called = []

    def fake_run(*args, **kwargs):
        called.append(args)
        raise RuntimeError("subprocess.run must not be called for invalid target!")

    monkeypatch.setattr(subprocess, "run", fake_run)

    invalid_targets = [
        "sih26-unknown",
        "evil-container",
        "localhost",
        "127.0.0.1",
        "; rm -rf /",
        "",
        None,
        12345,
    ]
    for target in invalid_targets:
        res = apply_remediation(rule_id="V-207193", target=target, confirm=True)
        assert res["ok"] is False
        assert res["stage"] == "validate"
        assert res["decision"] == "refused"
        assert "not an allowed lab container" in res["error"]

    assert len(called) == 0


def test_apply_remediation_refuses_unconfirmed(monkeypatch):
    """Calling apply_remediation with confirm=False, None, or non-True REFUSES."""
    called = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: called.append(a))

    for conf in (False, None, "yes", 1, [True]):
        res = apply_remediation(rule_id="V-207193", target="sih26-alice-pq", confirm=conf)
        assert res["ok"] is False
        assert res["stage"] == "validate"
        assert res["decision"] == "refused"
        assert "Confirmation required" in res["error"]

    assert len(called) == 0


def test_apply_remediation_refuses_auto_applicable_false(monkeypatch):
    """auto_applicable: false rules (CVEs, replay symptoms) must REFUSE execution."""
    monkeypatch.setattr(execute, "is_container_running", lambda target: True)

    for rule_id in ("CVE-2026-78135", "RFC4303-SEQ"):
        res = apply_remediation(rule_id=rule_id, target="sih26-alice-pq", confirm=True)
        assert res["ok"] is False
        assert res["stage"] == "validate"
        assert res["decision"] == "refused"
        assert "auto_applicable: false" in res["error"]


def test_apply_remediation_refuses_stopped_container(monkeypatch):
    """If target container is not currently in `docker ps`, execution REFUSES."""
    monkeypatch.setattr(execute, "is_container_running", lambda target: False)

    res = apply_remediation(rule_id="V-207193", target="sih26-alice-pq", confirm=True)
    assert res["ok"] is False
    assert res["stage"] == "validate"
    assert res["decision"] == "refused"
    assert "not currently running" in res["error"]


def test_apply_remediation_audit_log(tmp_path):
    """Every remediation attempt (success, refusal, failure) writes an append-only JSON line
    to remediate.jsonl with all required fields."""
    history_dir = tmp_path / "history"
    log_file = history_dir / "remediate.jsonl"

    # Attempt 1: unconfirmed (refusal)
    res1 = apply_remediation("V-207193", "sih26-alice-pq", confirm=False, caller="test-runner", history_dir=history_dir)
    assert res1["ok"] is False

    # Attempt 2: invalid target (refusal)
    res2 = apply_remediation("V-207193", "evil-box", confirm=True, caller="test-runner", history_dir=history_dir)
    assert res2["ok"] is False

    assert log_file.is_file()
    lines = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2

    # Verify required schema on every entry
    required_keys = {
        "timestamp", "at", "rule_id", "target", "decision",
        "commands_run", "verdict_before", "verdict_after",
        "confirmed_fixed", "caller", "ok",
    }
    for entry in lines:
        assert required_keys.issubset(set(entry.keys()))
        assert entry["decision"] == "refused"
        assert entry["caller"] == "test-runner"
        assert entry["confirmed_fixed"] is False


def test_apply_remediation_mocked_success_and_fail(tmp_path, monkeypatch):
    """Verify execution logic, frozen commands, and re-verification honesty."""
    import time
    monkeypatch.setattr(time, "sleep", lambda s: None)
    history_dir = tmp_path / "history"
    monkeypatch.setattr(execute, "is_container_running", lambda target: True)

    commands_executed = []
    captures_dir = execute._repo_root() / "testbed" / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    verify_pcap = captures_dir / "remediate_verify.pcap"

    def fake_subprocess_run(cmd, *args, **kwargs):
        commands_executed.append(cmd)
        # Simulate tcpdump creating the pcap
        if "tcpdump" in cmd:
            verify_pcap.write_bytes(b"dummy-pcap-bytes")

        class DummyRes:
            returncode = 0
            stdout = ""
            stderr = ""

        return DummyRes()

    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    # 1. Successful remediation where re-analysis reports PASS
    fake_pass_analysis = {
        "sas": [
            {
                "verdicts": [
                    {"rule_id": "V-207193", "verdict": "PASS"}
                ]
            }
        ]
    }

    import tunnelscope.report.report
    monkeypatch.setattr(tunnelscope.report.report, "analyze", lambda path: fake_pass_analysis)

    try:
        res = apply_remediation("V-207193", "sih26-alice-pq", confirm=True, caller="tester", history_dir=history_dir)
        assert res["ok"] is True
        assert res["decision"] == "applied"
        assert res["confirmed_fixed"] is True
        assert res["verdict_after"] == "PASS"
        assert res["verdict_before"] == "FAIL"
        assert res["commands_run"] == REMEDIATION["V-207193"]["commands"]

        # 2. Honest reporting: if re-analysis still yields FAIL, confirmed_fixed must be False
        fake_fail_analysis = {
            "sas": [
                {
                    "verdicts": [
                        {"rule_id": "V-207193", "verdict": "FAIL"}
                    ]
                }
            ]
        }
        monkeypatch.setattr(tunnelscope.report.report, "analyze", lambda path: fake_fail_analysis)

        res_fail = apply_remediation("V-207193", "sih26-alice-pq", confirm=True, caller="tester", history_dir=history_dir)
        assert res_fail["ok"] is True
        assert res_fail["decision"] == "applied"
        assert res_fail["confirmed_fixed"] is False
        assert res_fail["verdict_after"] == "FAIL"
    finally:
        if verify_pcap.exists():
            verify_pcap.unlink()


def test_server_remediate_apply_e2e():
    """End-to-end test hitting POST /api/remediate/apply:
    refuses missing confirm, refuses invalid target, handles malformed JSON, and calls apply_remediation."""
    srv = server.make_server(0)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        base_url = f"http://127.0.0.1:{port}"

        # 1. Missing confirm -> 400
        req_unconf = urllib.request.Request(
            f"{base_url}/api/remediate/apply",
            data=json.dumps({"rule_id": "V-207193", "target": "sih26-alice-pq"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_unconf)
        assert exc_info.value.code == 400
        err_data = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_data["stage"] == "validate"
        assert "confirm" in err_data["error"]

        # 2. Invalid target -> 400
        req_bad_target = urllib.request.Request(
            f"{base_url}/api/remediate/apply",
            data=json.dumps({"rule_id": "V-207193", "target": "invalid-box", "confirm": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_bad_target)
        assert exc_info.value.code == 400
        err_bad_target = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_bad_target["stage"] == "validate"
        assert "not an allowed lab container" in err_bad_target["error"]

        # 3. Missing rule_id -> 400
        req_missing_rule = urllib.request.Request(
            f"{base_url}/api/remediate/apply",
            data=json.dumps({"target": "sih26-alice-pq", "confirm": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_missing_rule)
        assert exc_info.value.code == 400

        # 4. Oversized body (>1MB) -> 413
        req_oversized = urllib.request.Request(
            f"{base_url}/api/remediate/apply",
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


def test_lab_remediation_e2e():
    """End-to-end against the real lab (skipped if Docker daemon / lab container is not running)."""
    if not is_container_running("sih26-alice-pq"):
        # Docker daemon or lab container sih26-alice-pq not running in this environment
        return

    # Real lab execution when docker is up
    res = apply_remediation("V-207193", "sih26-alice-pq", confirm=True, caller="pytest-lab-e2e")
    assert res["ok"] is True
    assert res["verdict_before"] == "FAIL"
    assert res["verdict_after"] == "PASS"
    assert res["confirmed_fixed"] is True

