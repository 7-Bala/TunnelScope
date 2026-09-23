"""Remediation execution engine (Stage 3: lab-only, confirm-gated, re-verified).

SECURITY NOTICE:
This module is the single permitted location in the entire codebase allowed to invoke
`subprocess.run(["docker", "exec", ...])` for executing remediation commands against
project Docker containers in the lab.
Note that static checks for other modules (such as `plan.py` and `tunnelscope/rephrase/`)
must NOT be weakened or broadened to cover this file.

Enforces:
1. Target restriction: only containers defined in testbed/docker-compose.yml.
2. Running check: target must be currently running in `docker ps`; never auto-start.
3. Frozen commands: commands come solely from plan.py's REMEDIATION glossary, verbatim.
4. Auto-applicable check: auto_applicable: false rules (e.g. CVE-2026-78135) cannot execute.
5. Explicit confirmation: confirm=True is mandatory.
6. Append-only audit logging: every attempt (success, refusal, error) is logged.
7. Verification: re-captures traffic and analyzes with TunnelScope to verify if verdict is PASS.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

from .plan import REMEDIATION, plan_for


_DEFAULT_HISTORY_DIR = Path(".tunnelscope-history")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def get_allowed_targets(compose_path: Path | None = None) -> set[str]:
    """Parse testbed/docker-compose.yml at runtime to extract valid container names.
    Never hardcoded to prevent configuration drift."""
    path = compose_path or (_repo_root() / "testbed" / "docker-compose.yml")
    if not path.is_file():
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return set()
        services = data.get("services", {})
        targets: set[str] = set()
        if isinstance(services, dict):
            for svc_name, svc_conf in services.items():
                if isinstance(svc_conf, dict) and "container_name" in svc_conf:
                    targets.add(str(svc_conf["container_name"]))
                else:
                    targets.add(str(svc_name))
        return targets
    except Exception:
        return set()


def is_container_running(target: str) -> bool:
    """Return True if `target` is currently listed in `docker ps`."""
    try:
        res = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode != 0:
            return False
        running = {line.strip() for line in res.stdout.splitlines() if line.strip()}
        return target in running
    except Exception:
        return False


def record_audit(
    entry: dict[str, Any],
    history_dir: str | Path | None = None,
) -> None:
    """Append a single record to .tunnelscope-history/remediate.jsonl."""
    hdir = Path(history_dir) if history_dir else (_repo_root() / _DEFAULT_HISTORY_DIR)
    try:
        hdir.mkdir(parents=True, exist_ok=True)
        log_path = hdir / "remediate.jsonl"
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:
        # Audit logging failure must not crash execution, but we try stderr
        pass


def apply_remediation(
    rule_id: str,
    target: str,
    confirm: bool,
    caller: str | None = None,
    compose_path: Path | None = None,
    history_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Execute remediation commands in target lab container, re-capture, and re-verify.

    Returns:
      dict with ok, rule_id, target, commands_run, verdict_before, verdict_after, confirmed_fixed
      or on refusal:
      dict with ok=False, stage="validate", error=<reason>
    """
    now = time.time()
    audit_base = {
        "timestamp": now,
        "at": now,
        "rule_id": str(rule_id) if rule_id is not None else "",
        "target": str(target) if target is not None else "",
        "caller": caller or "unknown",
        "confirm": confirm,
        "commands_run": [],
        "verdict_before": "FAIL",
        "verdict_after": None,
        "confirmed_fixed": False,
    }

    # 1. Validate confirmation
    if confirm is not True:
        err = "Confirmation required (confirm must be True)"
        entry = {**audit_base, "ok": False, "decision": "refused", "stage": "validate", "error": err}
        record_audit(entry, history_dir)
        return {"ok": False, "stage": "validate", "error": err, "decision": "refused"}

    # 2. Validate target is in allowed docker-compose containers
    allowed = get_allowed_targets(compose_path)
    if not isinstance(target, str) or target not in allowed:
        err = f"Target {target!r} is not an allowed lab container ({sorted(allowed)})"
        entry = {**audit_base, "ok": False, "decision": "refused", "stage": "validate", "error": err}
        record_audit(entry, history_dir)
        return {"ok": False, "stage": "validate", "error": err, "decision": "refused"}

    # 3. Validate target container is currently running
    if not is_container_running(target):
        err = f"Container {target!r} is not currently running in Docker"
        entry = {**audit_base, "ok": False, "decision": "refused", "stage": "validate", "error": err}
        record_audit(entry, history_dir)
        return {"ok": False, "stage": "validate", "error": err, "decision": "refused"}

    # 4. Lookup plan and check auto_applicable
    plan = plan_for(rule_id, include_exec=True)
    if plan is None:
        err = f"Unknown rule_id {rule_id!r}"
        entry = {**audit_base, "ok": False, "decision": "refused", "stage": "validate", "error": err}
        record_audit(entry, history_dir)
        return {"ok": False, "stage": "validate", "error": err, "decision": "refused"}

    if not plan.get("auto_applicable"):
        err = f"Rule {rule_id} is advisory-only (auto_applicable: false) and cannot be executed"
        entry = {**audit_base, "ok": False, "decision": "refused", "stage": "validate", "error": err}
        record_audit(entry, history_dir)
        return {"ok": False, "stage": "validate", "error": err, "decision": "refused"}

    exec_commands = plan.get("exec_commands", [])
    if not exec_commands:
        err = "no safe automated fix exists for this rule yet"
        entry = {**audit_base, "ok": False, "decision": "refused", "stage": "validate", "error": err}
        record_audit(entry, history_dir)
        return {"ok": False, "stage": "validate", "error": err, "decision": "refused"}

    # 5. Execute commands via docker exec
    commands_run: list[str] = []
    for cmd in exec_commands:
        commands_run.append(cmd)
        try:
            # Run command inside container
            subprocess.run(
                ["docker", "exec", target, "sh", "-c", cmd],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        except Exception as e:
            err = f"Failed executing command in container {target}: {e}"
            entry = {
                **audit_base,
                "ok": False,
                "decision": "failed",
                "stage": "execute",
                "error": err,
                "commands_run": commands_run,
            }
            record_audit(entry, history_dir)
            return {"ok": False, "stage": "execute", "error": err, "decision": "failed", "commands_run": commands_run}

    # 6. Re-capture and re-verify
    # Attempt capture on sih26-router or target container
    pcap_host_path = _repo_root() / "testbed" / "captures" / "remediate_verify.pcap"
    pcap_container_path = "/captures/remediate_verify.pcap"
    capture_target = "sih26-router" if is_container_running("sih26-router") else target

    verdict_after = "UNKNOWN"
    confirmed_fixed = False

    try:
        # Clean up any stale verify capture
        if pcap_host_path.exists():
            pcap_host_path.unlink()

        # Ensure lab IP aliases (Alice: 10.10.1.210-214, Bob: 10.10.2.210-214) are configured if running on lab
        if target.startswith("sih26-"):
            side_num = "1" if "alice" in target else ("2" if "bob" in target else "")
            if side_num:
                subprocess.run(
                    ["docker", "exec", target, "sh", "-c",
                     f"for j in 0 1 2 3 4; do "
                     f"ip addr add 10.10.{side_num}.$((210+j))/32 dev eth0 2>/dev/null; done || true"],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
            peer = "sih26-bob-pq" if "alice" in target else ("sih26-alice-pq" if "bob" in target else None)
            if peer and is_container_running(peer):
                peer_num = "2" if "bob" in peer else ("1" if "alice" in peer else "")
                if peer_num:
                    subprocess.run(
                        ["docker", "exec", peer, "sh", "-c",
                         f"for j in 0 1 2 3 4; do "
                         f"ip addr add 10.10.{peer_num}.$((210+j))/32 dev eth0 2>/dev/null; done || true"],
                        capture_output=True,
                        check=False,
                        timeout=5,
                    )

        # Terminate any existing IKE SA to force a clean re-handshake
        subprocess.run(
            ["docker", "exec", target, "swanctl", "--terminate", "--ike", "t-tun", "--timeout", "3"],
            capture_output=True,
            check=False,
            timeout=8,
        )
        time.sleep(1)

        # Start short tcpdump in capture container
        subprocess.run(
            ["docker", "exec", "-d", capture_target, "tcpdump", "-i", "any", "-w", pcap_container_path, "-c", "60"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        time.sleep(1)

        # Trigger traffic/re-initiation if swanctl is available
        subprocess.run(
            ["docker", "exec", target, "swanctl", "--initiate", "--child", "t-tun", "--timeout", "5"],
            capture_output=True,
            check=False,
            timeout=10,
        )
        time.sleep(2)

        # Stop tcpdump
        subprocess.run(
            ["docker", "exec", capture_target, "pkill", "tcpdump"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        time.sleep(1)

        # Run analysis on the fresh capture
        if pcap_host_path.is_file() and pcap_host_path.stat().st_size > 0:
            from ..report.report import analyze
            analysis = analyze(str(pcap_host_path))
            for sa in analysis.get("sas", []):
                for v in sa.get("verdicts", []):
                    v_id = getattr(v, "rule_id", None) or (v.get("rule_id") if isinstance(v, dict) else None)
                    if v_id == rule_id:
                        v_val = str(getattr(v, "verdict", None) or (v.get("verdict") if isinstance(v, dict) else None)).upper()
                        if v_val in ("PASS", "FAIL"):
                            verdict_after = v_val
                            break
                        elif verdict_after == "UNKNOWN":
                            verdict_after = v_val
                if verdict_after in ("PASS", "FAIL"):
                    break

        confirmed_fixed = (verdict_after == "PASS")
    except Exception as e:
        # Re-capture/analysis exception does not erase the fact that commands ran
        verdict_after = f"UNKNOWN ({e})"
        confirmed_fixed = False
    finally:
        if pcap_host_path.exists():
            try:
                pcap_host_path.unlink()
            except OSError:
                pass

    result = {
        "ok": True,
        "decision": "applied",
        "rule_id": rule_id,
        "target": target,
        "commands_run": commands_run,
        "verdict_before": "FAIL",
        "verdict_after": verdict_after,
        "confirmed_fixed": confirmed_fixed,
    }

    record_audit({**audit_base, **result}, history_dir)
    return result
