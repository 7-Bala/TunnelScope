"""Remediation execution engine (Stage 3: lab-only, confirm-gated, re-verified).

SECURITY NOTICE:
This module is the single permitted location in the codebase allowed to run
`docker exec` against project lab containers. Static checks for other modules (such as
`plan.py` and `tunnelscope/rephrase/`) must NOT be weakened or broadened to cover this file.

What happens on apply, in order. Every step that can refuse runs before anything changes.
 1. Validate: confirm is True, the target is a container named in testbed/docker-compose.yml
    and currently running, the rule has an automated fix.
 2. Command check (plan.validate_command_safety): an allowlist. Plan commands are never given
    to a shell: sed runs with an argument list, and the reload is swanctl with an argument list.
 3. Dry run: the sed scripts run on scratch copies of the real config files in the container,
    and the actual resulting diff is checked (it must change something, and only proposals /
    version settings). Then the changed files are loaded by strongSwan in a throwaway clone of
    the container's image with no network (clone_load_check): every connection that loaded
    before must still load, so an invented or misspelt algorithm is refused. Nothing is loaded
    into the running daemon. Fails closed.
 4. Baseline: capture a handshake and record every rule's verdict BEFORE the change. The target
    rule must be FAIL; otherwise nothing is applied (already fixed, or not observable).
 5. Snapshot every config file (target, and the lab peer if the peer step applies), then arm a
    commit-confirmed watchdog inside the container that restores the snapshot by itself after
    WATCHDOG_TIMEOUT_S unless disarmed.
 6. Apply the commands.
 7. Verify: capture again. Confirmed fixed only if the target rule is PASS, the tunnel
    negotiated, and no rule that was not failing before is failing now.
 8. Otherwise roll back immediately and check the restored files byte for byte. The watchdog's
    own restores are recorded in the audit log the next time this module runs (reconcile).
Every attempt, refusal, rollback and watchdog restore is appended to remediate.jsonl.
"""
from __future__ import annotations

import difflib
import io
import json
import re
import subprocess
import tarfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

from .plan import (
    CONFIG_GLOBS,
    LAB_CONNECTION,
    LAB_PEERS,
    PEER_PREP_TARGETS,
    is_reload_command,
    peer_commands_for,
    plan_for,
    sed_script_of,
    validate_command_safety,
)


_DEFAULT_HISTORY_DIR = Path(".tunnelscope-history")
SNAP_SUFFIX = ".ts_snapshot"
MANIFEST = "/tmp/.tunnelscope_snapshot_manifest"
WATCHDOG_MARKER = "/tmp/.tunnelscope_watchdog_fired"
DRYRUN_DIR = "/tmp/.tunnelscope_dryrun"
# Longer than the worst case of steps 6-8 (command timeouts plus the verification capture),
# so the watchdog never races a verification that is still running.
WATCHDOG_TIMEOUT_S = 180
CAPTURE_PACKETS = "60"

_ALLOWED_DIFF_LINE = re.compile(r"^\s*(proposals|esp_proposals|ah_proposals|version)\s*=")
_BAD = ("FAIL", "CONTRADICTORY")
# Strongest evidence wins when a rule is judged on several SAs of one capture.
_RANK = {"FAIL": 3, "CONTRADICTORY": 2, "PASS": 1, "NOT_OBSERVABLE": 0, "UNKNOWN": 0}

_LIST_CONFIGS_SCRIPT = f"ls -1 {CONFIG_GLOBS} 2>/dev/null"
_WRITE_MANIFEST_SCRIPT = 'printf "%s\\n" "$@" > "$0"'
# $1 = seconds, $2 = token. Restores only if the manifest still belongs to this apply.
_WATCHDOG_SCRIPT = (
    'sleep "$1"; m="' + MANIFEST + '"; '
    '[ -f "$m" ] || exit 0; [ "$(head -n 1 "$m")" = "$2" ] || exit 0; '
    'tail -n +2 "$m" | while IFS= read -r f; do [ -f "$f' + SNAP_SUFFIX + '" ] && cp -p "$f' + SNAP_SUFFIX + '" "$f"; done; '
    'first=$(tail -n +2 "$m" | head -n 1); '
    '{ [ -n "$first" ] && swanctl --load-all --file "$first"; } || swanctl --load-all; '
    'swanctl --terminate --ike ' + LAB_CONNECTION + ' --timeout 3; swanctl --initiate --child ' + LAB_CONNECTION + ' --timeout 5; '
    'tail -n +2 "$m" | while IFS= read -r f; do rm -f "$f' + SNAP_SUFFIX + '"; done; rm -f "$m"; '
    'printf "%s %s\\n" "$2" "$(date +%s)" > "' + WATCHDOG_MARKER + '"'
)
_LAB_ALIAS_SCRIPT = 'for j in 0 1 2 3 4; do ip addr add "10.10.$1.$((210+j))/32" dev eth0 2>/dev/null; done; true'
_LAB_SIDE = {"sih26-alice-pq": "1", "sih26-bob-pq": "2"}

_APPLY_LOCK = threading.Lock()
# What the last dry run on this thread found beyond its (ok, error, diffs) result (the clone
# check). Kept out of the return value so the dry run's call shape stays the same.
_DRY_RUN_REPORT = threading.local()


def _take_dry_run_report() -> dict[str, Any]:
    rep = getattr(_DRY_RUN_REPORT, "last", None) or {}
    _DRY_RUN_REPORT.last = {}
    return rep


class _Refusal(Exception):
    def __init__(self, stage: str, error: str):
        super().__init__(error)
        self.stage = stage
        self.error = error


# ------------------------------------------------------------------ container access

def _exec(target: str, argv: list[str], timeout: float = 10, detach: bool = False) -> subprocess.CompletedProcess:
    """The one way this module touches a container: `docker exec` with an argument list."""
    flags = ["-d"] if detach else []
    return subprocess.run(
        ["docker", "exec", *flags, target, *argv],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def list_config_files(target: str) -> list[str]:
    """Config files present in the container, in `ls` order (the reload uses the first)."""
    res = _exec(target, ["sh", "-c", _LIST_CONFIGS_SCRIPT], timeout=5)
    seen: list[str] = []
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if line and line not in seen:
            seen.append(line)
    return seen


def read_file(target: str, path: str) -> str | None:
    res = _exec(target, ["cat", path], timeout=5)
    return res.stdout if res.returncode == 0 else None


def _reload(target: str, files: list[str]) -> subprocess.CompletedProcess:
    """plan.RELOAD_COMMAND, run without a shell."""
    if files:
        res = _exec(target, ["swanctl", "--load-all", "--file", files[0]], timeout=15)
        if res.returncode == 0:
            return res
    return _exec(target, ["swanctl", "--load-all"], timeout=15)


def _run_plan_command(target: str, cmd: str, files: list[str]) -> subprocess.CompletedProcess:
    script = sed_script_of(cmd)
    if script is not None:
        return _exec(target, ["sed", "-i", "-E", script, *files], timeout=15)
    if is_reload_command(cmd):
        return _reload(target, files)
    raise RuntimeError(f"no executor for command {cmd!r}")  # unreachable after validate_command_safety


def _captures_dir() -> Path:
    """Host side of the ./captures:/captures volume every lab container mounts."""
    return _repo_root() / "testbed" / "captures"


# ------------------------------------------------------------------ validation helpers

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


def running_containers() -> set[str]:
    try:
        res = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if res.returncode != 0:
            return set()
        return {line.strip() for line in res.stdout.splitlines() if line.strip()}
    except Exception:
        return set()


def is_container_running(target: str) -> bool:
    """Return True if `target` is currently listed in `docker ps`."""
    return target in running_containers()


def lab_targets(compose_path: Path | None = None) -> list[dict[str, Any]]:
    """Allowed targets with their running state, for the dashboard's target picker."""
    running = running_containers()
    return [{"name": t, "running": t in running} for t in sorted(get_allowed_targets(compose_path))]


def record_audit(entry: dict[str, Any], history_dir: str | Path | None = None) -> None:
    """Append a single record to .tunnelscope-history/remediate.jsonl."""
    hdir = Path(history_dir) if history_dir else (_repo_root() / _DEFAULT_HISTORY_DIR)
    try:
        hdir.mkdir(parents=True, exist_ok=True)
        with open(hdir / "remediate.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
    except Exception:
        pass  # logging must never stop a rollback


def _peer_for(target: str) -> str | None:
    return LAB_PEERS.get(target) if target in PEER_PREP_TARGETS else None


def _validate(rule_id: Any, target: Any, compose_path: Path | None) -> tuple[dict, str | None]:
    """Steps 1-2 (no container is touched). Returns (plan, peer) or raises _Refusal."""
    allowed = get_allowed_targets(compose_path)
    if not isinstance(target, str) or target not in allowed:
        raise _Refusal("validate", f"Target {target!r} is not an allowed lab container ({sorted(allowed)})")
    if not is_container_running(target):
        raise _Refusal("validate", f"Container {target!r} is not currently running in Docker")
    plan = plan_for(rule_id, include_exec=True)
    if plan is None:
        raise _Refusal("validate", f"Unknown rule_id {rule_id!r}")
    if not plan.get("auto_applicable"):
        raise _Refusal("validate", f"Rule {rule_id} is advisory-only (auto_applicable: false) and cannot be executed")
    if not plan.get("exec_commands"):
        raise _Refusal("validate", "no safe automated fix exists for this rule yet")
    peer = _peer_for(target)
    if peer and not is_container_running(peer):
        raise _Refusal("validate", f"Lab peer {peer!r} must be running so the tunnel can be re-negotiated and verified")
    for cmd in plan["exec_commands"] + (peer_commands_for(plan) if peer else []):
        safe, reason = validate_command_safety(cmd)
        if not safe:
            raise _Refusal("lint", f"Command safety check failed: {reason}")
    return plan, peer


# ------------------------------------------------------------------ dry run (Layer 4)

def _connection_span(lines: list[str], name: str = LAB_CONNECTION) -> tuple[int, int] | None:
    """Line indices (first, last) of the top-level connection `name` in a swanctl.conf, found by
    brace matching, independently of the sed range the plan uses."""
    opener = re.compile(r"^\s*" + re.escape(name) + r"\s*\{\s*$")
    depth, start = 0, None
    for i, line in enumerate(lines):
        code = line.split("#", 1)[0]
        if start is None and depth == 1 and opener.match(code):
            start = i
        depth += code.count("{") - code.count("}")
        if start is not None and depth == 1:
            return start, i
    return None


def perform_sandboxed_dry_run(target: str, commands: list[str], allow_no_change: bool = False,
                              report: dict[str, Any] | None = None) -> tuple[bool, str | None, dict[str, str]]:
    """Run the plan's sed scripts on scratch copies of the container's real config files and
    check the actual diff, then load the changed files in a clone of the image. Returns
    (ok, error, {file: unified diff}); `report`, if given, receives the clone check result.
    Never loads anything into the running daemon; fails closed on any error."""
    _DRY_RUN_REPORT.last = {}
    try:
        files = list_config_files(target)
        if not files:
            return False, "no swanctl configuration file was found in the container, so the change cannot be checked", {}
        _exec(target, ["rm", "-rf", DRYRUN_DIR], timeout=5)
        if _exec(target, ["mkdir", "-p", DRYRUN_DIR], timeout=5).returncode != 0:
            return False, "could not create the dry-run scratch directory", {}
        scratch = {}
        for i, f in enumerate(files):
            s = f"{DRYRUN_DIR}/{i}.conf"
            if _exec(target, ["cp", "-p", f, s], timeout=5).returncode != 0:
                return False, f"could not copy {f} for the dry run", {}
            scratch[f] = s
        for cmd in commands:
            script = sed_script_of(cmd)
            if script is None:
                continue  # the reload would touch the live daemon; it is not dry-run
            res = _exec(target, ["sed", "-i", "-E", script, *scratch.values()], timeout=15)
            if res.returncode != 0:
                return False, f"sed rejected the script: {(res.stderr or '').strip()}", {}
        diffs: dict[str, str] = {}
        changed: dict[str, tuple[str, str]] = {}
        problems: list[str] = []
        for f, s in scratch.items():
            before, after = read_file(target, f), read_file(target, s)
            if before is None or after is None:
                return False, f"could not read {f} back during the dry run", {}
            if before == after:
                continue
            changed[f] = (before, after)
            b, a = before.splitlines(), after.splitlines()
            if len(b) != len(a):
                problems.append(f"{f}: the change adds or removes lines")
            span = _connection_span(b)
            outside = [i + 1 for i, (bl, al) in enumerate(zip(b, a))
                       if bl != al and (span is None or not span[0] <= i <= span[1])]
            if outside:
                problems.append(f"{f}: the change reaches outside the {LAB_CONNECTION} connection "
                                f"(line {', '.join(map(str, outside[:5]))}), which would not be verified")
            if before.count("{") != after.count("{") or before.count("}") != after.count("}"):
                problems.append(f"{f}: the change alters the block structure")
            for bl, al in zip(b, a):
                if bl != al:
                    for line in (bl, al):
                        if not _ALLOWED_DIFF_LINE.match(line):
                            problems.append(f"{f}: the change touches a line that is not a proposals/version setting: {line.strip()!r}")
            diffs[f] = "".join(difflib.unified_diff(
                before.splitlines(True), after.splitlines(True), fromfile=f, tofile=f + " (after)"))
        if problems:
            return False, "; ".join(problems[:5]), diffs
        if not diffs and not allow_no_change:
            return False, ("the commands would change nothing in this container's configuration "
                           "(the setting may already be compliant, or the plan does not match this config)"), {}
        if changed:
            clone = clone_load_check(target, {f: b for f, (b, _) in changed.items()},
                                     {f: a for f, (_, a) in changed.items()})
            _DRY_RUN_REPORT.last = {"clone_check": clone}
            if report is not None:
                report["clone_check"] = clone
            if not clone["ok"]:
                return False, f"the changed configuration does not load in a clone of {target}: {clone['reason']}", diffs
        return True, None, diffs
    except Exception as e:
        return False, f"the dry run could not complete: {e}", {}
    finally:
        try:
            _exec(target, ["rm", "-rf", DRYRUN_DIR], timeout=5)
        except Exception:
            pass


# ------------------------------------------------------------------ clone load check (Layer 4, T-100)

CLONE_LABEL = "tunnelscope.clone=1"
CLONE_TIMEOUT_S = 60
CLONE_MAX_AGE_S = 180
# Fixed script run in the clone. The files arrive as a tar on stdin; nothing is interpolated.
# Exit codes are never used (a pipe once hid swanctl's): the output text is parsed instead.
_CLONE_SCRIPT = (
    "mkdir -p /probe /var/run/charon && tar -x -C /probe || { echo TS_ERR tar; exit 0; }; "
    "C=/usr/libexec/ipsec/charon; [ -x $C ] || C=/usr/lib/ipsec/charon; $C >/tmp/charon.log 2>&1 & "
    "i=0; until swanctl --stats >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 100 ] && { echo TS_ERR charon; exit 0; }; sleep 0.1; done; "
    "for f in $(ls /probe/c | sort); do echo \"TS_FILE $f\"; swanctl --load-conns --file /probe/c/$f 2>&1; "
    "echo TS_END; swanctl --load-conns --file /probe/empty.conf >/dev/null 2>&1; done; "
    "echo TS_LOG; grep -E 'not recognized|invalid' /tmp/charon.log; echo TS_DONE"
)
_CLONE_NAME = re.compile(r"tunnelscope-clone-(\d+)-[0-9a-f]+")
_LOADED = re.compile(r"^loaded connection '([^']+)'", re.M)
_LOAD_FAILED = re.compile(r"^loading connection '([^']+)' failed", re.M)
_NOT_RECOGNIZED = re.compile(r"algorithm '([^']+)' not recognized")


def _docker(argv: list[str], stdin: bytes | None = None, timeout: float = 10) -> subprocess.CompletedProcess:
    """Docker commands that are not `docker exec` into a lab container: image lookup and the
    throwaway clone. Argument lists only."""
    return subprocess.run(["docker", *argv], input=stdin, capture_output=True, check=False, timeout=timeout)


def image_of(target: str) -> str | None:
    """The image id (not the tag) the running container was created from."""
    try:
        r = _docker(["inspect", "--format", "{{.Image}}", target])
    except Exception:
        return None
    out = (r.stdout or b"").decode(errors="replace").strip()
    return out if r.returncode == 0 and out.startswith("sha256:") else None


def sweep_clones(max_age_s: int = CLONE_MAX_AGE_S) -> list[str]:
    """Remove clones left behind by a crash (their names carry their start time)."""
    removed = []
    try:
        r = _docker(["ps", "-a", "--filter", "label=" + CLONE_LABEL, "--format", "{{.Names}}"])
        now = int(time.time())
        for name in (r.stdout or b"").decode(errors="replace").split():
            m = _CLONE_NAME.fullmatch(name)
            if m and now - int(m.group(1)) > max_age_s:
                _docker(["rm", "-f", name])
                removed.append(name)
    except Exception:
        pass
    return removed


def _clone_tar(pairs: list[tuple[str, str]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name: str, text: str) -> None:
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        add("empty.conf", "connections {\n}\n")
        for i, (before, after) in enumerate(pairs):
            add(f"c/{i:03d}-a-before", before)
            add(f"c/{i:03d}-b-after", after)
    return buf.getvalue()


def _parse_clone_output(out: str) -> dict[str, Any] | None:
    if "TS_DONE" not in out or "TS_ERR" in out:
        return None
    body, _, log = out.partition("TS_LOG")
    blocks = {}
    for chunk in body.split("TS_FILE ")[1:]:
        head, _, rest = chunk.partition("\n")
        text, ended, _ = rest.partition("TS_END")
        if not ended:
            return None
        blocks[head.strip()] = {"loaded": _LOADED.findall(text), "failed": _LOAD_FAILED.findall(text)}
    return {"blocks": blocks, "rejected_keywords": sorted(set(_NOT_RECOGNIZED.findall(log)))}


def clone_load_check(target: str, before: dict[str, str], after: dict[str, str]) -> dict[str, Any]:
    """Load the before and after version of every changed config file in a throwaway clone of
    the target's image (no network, removed afterwards) and compare. ok only if, for every file,
    each connection that loaded before still loads, none newly fails, and the lab connection
    loads. Never touches the running daemon. Fails closed."""
    t0 = time.monotonic()
    res: dict[str, Any] = {"ok": False, "reason": None, "image": None, "files": {}, "rejected_keywords": []}
    changed = [f for f in after if before.get(f) != after[f]]
    if not changed:
        res.update(ok=True, note="nothing changed, so nothing was loaded")
        return res
    image = image_of(target)
    res["image"] = image
    if not image:
        res["reason"] = f"could not identify the image of {target} (is Docker running?)"
        return res
    sweep_clones()
    name = f"tunnelscope-clone-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    try:
        r = _docker(["run", "--rm", "-i", "--name", name, "--network", "none", "--cap-add", "NET_ADMIN",
                     "--label", CLONE_LABEL, "--entrypoint", "sh", image, "-c", _CLONE_SCRIPT],
                    stdin=_clone_tar([(before.get(f, ""), after[f]) for f in changed]), timeout=CLONE_TIMEOUT_S)
        out = (r.stdout or b"").decode(errors="replace")
    except subprocess.TimeoutExpired:
        _docker(["rm", "-f", name])
        res["reason"] = f"the clone did not finish within {CLONE_TIMEOUT_S} s"
        return res
    except Exception as e:
        res["reason"] = f"the clone could not be started: {e}"
        return res
    finally:
        res["seconds"] = round(time.monotonic() - t0, 2)
    parsed = _parse_clone_output(out)
    if parsed is None:
        res["reason"] = "the clone did not report a complete result, so the change is not trusted"
        return res
    res["rejected_keywords"] = parsed["rejected_keywords"]
    problems = []
    for i, f in enumerate(changed):
        b = parsed["blocks"].get(f"{i:03d}-a-before")
        a = parsed["blocks"].get(f"{i:03d}-b-after")
        if b is None or a is None:
            res["reason"] = "the clone did not report a complete result, so the change is not trusted"
            return res
        res["files"][f] = {"before": {"loaded": len(b["loaded"]), "failed": len(b["failed"])},
                           "after": {"loaded": len(a["loaded"]), "failed": len(a["failed"])}}
        lost = sorted(set(b["loaded"]) - set(a["loaded"]))
        if lost:
            problems.append(f"{f}: connection(s) {', '.join(lost[:5])} loaded before the change and do not load after it")
        if len(a["failed"]) > len(b["failed"]):
            problems.append(f"{f}: {len(a['failed']) - len(b['failed'])} more connection(s) fail to load after the change")
        if _connection_span(after[f].splitlines()) is not None and LAB_CONNECTION not in a["loaded"]:
            problems.append(f"{f}: the lab connection {LAB_CONNECTION} does not load after the change")
    if problems:
        rk = res["rejected_keywords"]
        res["reason"] = "; ".join(problems[:5]) + (f" (strongSwan did not recognise: {', '.join(rk)})" if rk else "")
        return res
    res["ok"] = True
    return res


# ------------------------------------------------------------------ snapshot, watchdog, rollback

def snapshot_configs(target: str, token: str) -> dict[str, str]:
    """Copy every config file to <file>.ts_snapshot and write the manifest (token, files).
    Returns {file: original content}. Raises if anything fails, before any change is made."""
    if read_file(target, MANIFEST) is not None:
        raise RuntimeError("a previous remediation on this container is still pending "
                           "(snapshot manifest present, watchdog may be armed); resolve it before another change")
    files = list_config_files(target)
    if not files:
        raise RuntimeError("no config files to snapshot")
    originals: dict[str, str] = {}
    for f in files:
        content = read_file(target, f)
        if content is None:
            raise RuntimeError(f"could not read {f}")
        originals[f] = content
        if _exec(target, ["cp", "-p", f, f + SNAP_SUFFIX], timeout=5).returncode != 0:
            raise RuntimeError(f"could not snapshot {f}")
    if _exec(target, ["sh", "-c", _WRITE_MANIFEST_SCRIPT, MANIFEST, token, *files], timeout=5).returncode != 0:
        raise RuntimeError("could not write the snapshot manifest")
    manifest = read_file(target, MANIFEST)
    if not manifest or manifest.splitlines()[0] != token:
        raise RuntimeError("snapshot manifest did not read back correctly")
    return originals


def arm_commit_confirmed_watchdog(target: str, token: str, timeout_s: int = WATCHDOG_TIMEOUT_S) -> None:
    """Detached timer inside the container: restores the snapshot unless disarmed first."""
    _exec(target, ["sh", "-c", _WATCHDOG_SCRIPT, "tunnelscope-watchdog", str(int(timeout_s)), token], timeout=5, detach=True)


def disarm_watchdog(target: str, token: str) -> bool:
    """Accept the change: drop the manifest (the watchdog then does nothing) and the snapshots.
    False if the manifest is gone or belongs to another apply (the watchdog already acted)."""
    manifest = read_file(target, MANIFEST)
    if not manifest or manifest.splitlines()[0] != token:
        return False
    _exec(target, ["rm", "-f", MANIFEST], timeout=5)
    for f in [x for x in manifest.splitlines()[1:] if x]:
        _exec(target, ["rm", "-f", f + SNAP_SUFFIX], timeout=5)
    return True


def _manifest_token(target: str) -> str | None:
    manifest = read_file(target, MANIFEST)
    return manifest.splitlines()[0] if manifest else None


def watchdog_fired(target: str, token: str) -> bool:
    marker = read_file(target, WATCHDOG_MARKER)
    return bool(marker) and marker.split()[0] == token


def rollback_snapshot(target: str, expected: dict[str, str] | None = None) -> dict[str, Any]:
    """Restore every file in the manifest from its snapshot and reload. If `expected` is given,
    read the files back and compare them byte for byte. Snapshots are deleted only when the
    restore is verified (or cannot be checked); a failed restore keeps them for the watchdog."""
    manifest = read_file(target, MANIFEST)
    if not manifest:
        return {"restored": False, "verified": False, "detail": "no snapshot manifest (nothing to restore)"}
    files = [x for x in manifest.splitlines()[1:] if x]
    copied = all(_exec(target, ["cp", "-p", f + SNAP_SUFFIX, f], timeout=5).returncode == 0 for f in files)
    _reload(target, files)
    verified = None
    if expected is not None:
        verified = copied and all(read_file(target, f) == expected.get(f) for f in files)
    if verified is not False:
        _exec(target, ["rm", "-f", MANIFEST], timeout=5)
        for f in files:
            _exec(target, ["rm", "-f", f + SNAP_SUFFIX], timeout=5)
    return {"restored": copied, "verified": verified, "files": files,
            "detail": "restored" if verified is not False else "restore could not be verified; snapshot kept for the watchdog"}


def reconcile_watchdog_events(history_dir: str | Path | None = None, compose_path: Path | None = None) -> list[dict]:
    """Record watchdog restores (which happen inside a container, outside this process) in the
    audit log, then clear their markers."""
    events = []
    for t in sorted(get_allowed_targets(compose_path)):
        if not is_container_running(t):
            continue
        marker = read_file(t, WATCHDOG_MARKER)
        if not marker or not marker.strip():
            continue
        parts = marker.split()
        now = time.time()
        entry = {
            "timestamp": now, "at": now, "ok": True, "decision": "watchdog_rollback", "stage": "watchdog",
            "rule_id": "", "target": t, "token": parts[0], "fired_at": parts[1] if len(parts) > 1 else None,
            "caller": "watchdog", "confirm": None, "commands_run": [], "verdict_before": None,
            "verdict_after": None, "confirmed_fixed": False, "rolled_back": True,
        }
        record_audit(entry, history_dir)
        _exec(t, ["rm", "-f", WATCHDOG_MARKER], timeout=5)
        events.append(entry)
    return events


# ------------------------------------------------------------------ capture and verdicts

def _verdicts_of(sas: list[Any]) -> dict[str, str]:
    agg: dict[str, str] = {}
    for sa in sas:
        vs = sa.get("verdicts", []) if isinstance(sa, dict) else getattr(sa, "verdicts", [])
        for v in vs:
            rid = v.get("rule_id") if isinstance(v, dict) else getattr(v, "rule_id", None)
            val = v.get("verdict") if isinstance(v, dict) else getattr(v, "verdict", None)
            val = str(getattr(val, "value", val) or "UNKNOWN").upper()
            if not rid:
                continue
            if rid not in agg or _RANK.get(val, 0) > _RANK.get(agg[rid], 0):
                agg[rid] = val
    return agg


def _prepare_lab_network(target: str, peer: str | None) -> list[str]:
    """Lab-only: the t-tun connection uses extra addresses that a container restart drops."""
    done = []
    for c in (target, peer):
        if c in _LAB_SIDE:
            _exec(c, ["sh", "-c", _LAB_ALIAS_SCRIPT, "lab-alias", _LAB_SIDE[c]], timeout=5)
            done.append(f"{c}: ensured 10.10.{_LAB_SIDE[c]}.210-214 addresses")
    return done


def _capture_verdicts(target: str, phase: str) -> tuple[dict[str, str], int]:
    """Re-negotiate the lab tunnel while capturing on the router, then analyse the capture.
    Returns ({rule_id: verdict}, number of SAs)."""
    host = _captures_dir() / f"remediate_{phase}.pcap"
    inside = f"/captures/remediate_{phase}.pcap"
    capture_on = "sih26-router" if is_container_running("sih26-router") else target
    try:
        if host.exists():
            host.unlink()
        _exec(target, ["swanctl", "--terminate", "--ike", LAB_CONNECTION, "--timeout", "3"], timeout=8)
        time.sleep(1)
        _exec(capture_on, ["tcpdump", "-i", "any", "-w", inside, "-c", CAPTURE_PACKETS], timeout=5, detach=True)
        time.sleep(1)
        _exec(target, ["swanctl", "--initiate", "--child", LAB_CONNECTION, "--timeout", "5"], timeout=10)
        time.sleep(2)
        _exec(capture_on, ["pkill", "tcpdump"], timeout=5)
        time.sleep(1)
        if not host.is_file() or host.stat().st_size == 0:
            return {}, 0
        from ..report import report as _report
        sas = _report.analyze(str(host)).get("sas", [])
        return _verdicts_of(sas), len(sas)
    finally:
        if host.exists():
            try:
                host.unlink()
            except OSError:
                pass


def _check_service_restored(target: str, before: dict[str, str]) -> dict[str, Any]:
    """Restoring the files and reloading is not enough: an SA negotiated with the bad settings
    keeps them until it is re-negotiated. Re-negotiate now, capture, and compare with the
    baseline: the tunnel must be up and no rule may be worse than before the change."""
    try:
        verdicts, n = _capture_verdicts(target, "post_rollback")
    except Exception as e:
        return {"tunnel_up": False, "matches_baseline": False, "detail": f"post-rollback capture failed: {e}"}
    worse = sorted(r for r, v in verdicts.items() if v in _BAD and before.get(r) not in _BAD)
    return {"tunnel_up": n > 0, "matches_baseline": n > 0 and not worse, "worse_than_baseline": worse}


# ------------------------------------------------------------------ preview and apply

def preview_remediation(rule_id: str, target: str, caller: str | None = None,
                        compose_path: Path | None = None, history_dir: str | Path | None = None) -> dict[str, Any]:
    """Validate and dry-run only: the real diff the operator sees before approving. No config
    file, running daemon or tunnel is changed."""
    now = time.time()
    base = {"timestamp": now, "at": now, "rule_id": str(rule_id), "target": str(target),
            "caller": caller or "unknown", "decision": "preview"}
    try:
        plan, peer = _validate(rule_id, target, compose_path)
        _take_dry_run_report()
        ok, err, diffs = perform_sandboxed_dry_run(target, plan["exec_commands"])
        report = _take_dry_run_report()
        if not ok:
            raise _Refusal("dry_run", f"Dry run failed: {err}")
        peer_info = None
        if peer:
            pok, perr, pdiffs = perform_sandboxed_dry_run(peer, peer_commands_for(plan), allow_no_change=True)
            preport = _take_dry_run_report()
            if not pok:
                raise _Refusal("dry_run", f"Dry run failed on the lab peer {peer}: {perr}")
            peer_info = {"container": peer, "diff": pdiffs, "clone_check": preport.get("clone_check"),
                         "why": "both ends of a tunnel must agree on a proposal, so the other end gets the same change"}
        res = {"ok": True, "rule_id": rule_id, "target": target, "diff": diffs, "peer": peer_info,
               "clone_check": report.get("clone_check")}
        record_audit({**base, "ok": True, "files_changed": sorted(diffs),
                      "peer_files_changed": sorted(peer_info["diff"]) if peer_info else []}, history_dir)
        return res
    except _Refusal as r:
        record_audit({**base, "ok": False, "stage": r.stage, "error": r.error}, history_dir)
        return {"ok": False, "stage": r.stage, "error": r.error, "decision": "refused"}


def apply_remediation(
    rule_id: str,
    target: str,
    confirm: bool,
    caller: str | None = None,
    compose_path: Path | None = None,
    history_dir: str | Path | None = None,
    watchdog_timeout_s: int = WATCHDOG_TIMEOUT_S,
) -> dict[str, Any]:
    """Execute a remediation in a lab container, then prove it or undo it (see module doc).

    Returns ok/decision/rule_id/target/commands_run/verdict_before/verdict_after/confirmed_fixed/
    rolled_back plus token, reason, regressions, dry_run_diff, peer, rollback_verified;
    or on refusal {ok: False, stage, error, decision: "refused"}."""
    token = uuid.uuid4().hex[:12]
    now = time.time()
    audit_base = {
        "timestamp": now,
        "at": now,
        "token": token,
        "rule_id": str(rule_id) if rule_id is not None else "",
        "target": str(target) if target is not None else "",
        "caller": caller or "unknown",
        "confirm": confirm,
        "commands_run": [],
        "verdict_before": None,
        "verdict_after": None,
        "confirmed_fixed": False,
    }

    def refuse(stage: str, err: str, **extra: Any) -> dict[str, Any]:
        record_audit({**audit_base, **extra, "ok": False, "decision": "refused", "stage": stage, "error": err}, history_dir)
        return {"ok": False, "stage": stage, "error": err, "decision": "refused", **extra}

    if confirm is not True:
        return refuse("validate", "Confirmation required (confirm must be True)")
    try:
        plan, peer = _validate(rule_id, target, compose_path)
    except _Refusal as r:
        return refuse(r.stage, r.error)

    if not _APPLY_LOCK.acquire(blocking=False):
        return refuse("validate", "another remediation is already running; try again when it finishes")
    try:
        return _apply_locked(rule_id, target, plan, peer, token, audit_base, refuse,
                             history_dir, compose_path, watchdog_timeout_s)
    finally:
        _APPLY_LOCK.release()


def _apply_locked(rule_id, target, plan, peer, token, audit_base, refuse,
                  history_dir, compose_path, watchdog_timeout_s) -> dict[str, Any]:
    reconcile_watchdog_events(history_dir, compose_path)
    exec_commands = plan["exec_commands"]
    peer_commands = peer_commands_for(plan) if peer else []

    # 3. Dry run on scratch copies of the real files
    _take_dry_run_report()
    ok, err, dry_diff = perform_sandboxed_dry_run(target, exec_commands)
    dry_report = _take_dry_run_report()
    if not ok:
        return refuse("dry_run", f"Pre-flight sandbox dry-run validation failed: {err}")
    peer_dry_diff: dict[str, str] = {}
    if peer:
        ok, err, peer_dry_diff = perform_sandboxed_dry_run(peer, peer_commands, allow_no_change=True)
        dry_report["peer"] = _take_dry_run_report()
        if not ok:
            return refuse("dry_run", f"Pre-flight sandbox dry-run validation failed on the lab peer {peer}: {err}")

    # 4. Baseline: what fails before anything changes
    lab_prep = _prepare_lab_network(target, peer)
    try:
        before, n_before = _capture_verdicts(target, "baseline")
    except Exception as e:
        return refuse("baseline", f"Could not capture a baseline; nothing was changed: {e}")
    if n_before == 0:
        return refuse("baseline", f"No IKE SA was negotiated on {LAB_CONNECTION} before the change, so the fix "
                                  "could not be verified afterwards; nothing was changed")
    vb = before.get(rule_id)
    if vb == "PASS":
        return refuse("baseline", f"{rule_id} already passes on a fresh capture; nothing to fix", verdict_before=vb)
    if vb != "FAIL":
        return refuse("baseline", f"{rule_id} is {vb or 'not judged'} on a fresh capture (it must be FAIL), so a fix "
                                  "could not be proven; nothing was changed", verdict_before=vb)

    # 5. Snapshot and arm the watchdogs
    try:
        originals = snapshot_configs(target, token)
    except Exception as e:
        return refuse("snapshot", f"Could not take a pre-change snapshot; nothing was changed: {e}", verdict_before=vb)
    peer_originals: dict[str, str] = {}
    if peer:
        try:
            peer_originals = snapshot_configs(peer, token)
        except Exception as e:
            disarm_watchdog(target, token)
            return refuse("snapshot", f"Could not snapshot the lab peer {peer}; nothing was changed: {e}", verdict_before=vb)
    arm_commit_confirmed_watchdog(target, token, watchdog_timeout_s)
    if peer:
        arm_commit_confirmed_watchdog(peer, token, watchdog_timeout_s)

    def undo() -> dict[str, Any]:
        rb = {"target": rollback_snapshot(target, originals)}
        if peer:
            rb["peer"] = rollback_snapshot(peer, peer_originals)
        rb["verified"] = all(x.get("verified") is True for x in rb.values() if isinstance(x, dict))
        rb["service"] = _check_service_restored(target, before)
        return rb

    # 6. Apply
    commands_run: list[str] = []
    peer_commands_run: list[str] = []
    try:
        for cmd in peer_commands:
            peer_commands_run.append(cmd)
            res = _run_plan_command(peer, cmd, list(peer_originals))
            if res.returncode != 0:
                raise RuntimeError(f"peer command failed ({res.returncode}): {(res.stderr or '').strip()}")
        for cmd in exec_commands:
            commands_run.append(cmd)
            res = _run_plan_command(target, cmd, list(originals))
            if res.returncode != 0:
                raise RuntimeError(f"command failed ({res.returncode}): {(res.stderr or '').strip()}")
    except Exception as e:
        rb = undo()
        result = {"ok": False, "stage": "execute", "decision": "failed", "error": f"Failed executing in the lab: {e}",
                  "commands_run": commands_run, "rolled_back": rb["target"]["restored"],
                  "rollback_verified": rb["verified"], "service_restored": rb["service"], "verdict_before": vb}
        record_audit({**audit_base, **result, "peer_commands_run": peer_commands_run, "rollback": rb}, history_dir)
        return result

    # 7. Verify against the baseline
    verify_error = None
    try:
        after, n_after = _capture_verdicts(target, "verify")
    except Exception as e:
        after, n_after, verify_error = {}, 0, str(e)
    va = after.get(rule_id)
    regressions = sorted(r for r, v in after.items() if r != rule_id and v in _BAD and before.get(r) not in _BAD)

    confirmed = False
    rb: dict[str, Any] | None = None
    if n_after == 0:
        verdict_after = "REGRESSION"
        reason = f"no IKE SA was negotiated after the change (tunnel outage){': ' + verify_error if verify_error else ''}"
    elif va != "PASS":
        verdict_after = va or "UNKNOWN"
        reason = f"{rule_id} is {verdict_after} after the change, not PASS"
    elif regressions:
        verdict_after = "REGRESSION"
        reason = f"{rule_id} passes, but these rules were not failing before and are now: {', '.join(regressions)}"
    else:
        verdict_after = "PASS"
        reason = f"{rule_id} passes on a fresh capture and no other rule got worse"
        # Check both snapshots are intact BEFORE disarming either: if one watchdog already
        # restored its side, disarming the other would delete the snapshot we need to undo it.
        intact = _manifest_token(target) == token and (not peer or _manifest_token(peer) == token)
        if intact and disarm_watchdog(target, token) and (not peer or disarm_watchdog(peer, token)) \
                and not watchdog_fired(target, token) and not (peer and watchdog_fired(peer, token)):
            confirmed = True
        else:
            verdict_after = "REVERTED_BY_WATCHDOG"
            reason = "the watchdog restored the snapshot before the change could be confirmed"

    # 8. Roll back anything not confirmed
    if not confirmed:
        rb = undo()
        if verdict_after == "REVERTED_BY_WATCHDOG":
            rb["verified"] = (all(read_file(target, f) == c for f, c in originals.items())
                              and all(read_file(peer, f) == c for f, c in peer_originals.items()))
    reconcile_watchdog_events(history_dir, compose_path)

    result = {
        "ok": True,
        "decision": "applied",
        "rule_id": rule_id,
        "target": target,
        "token": token,
        "commands_run": commands_run,
        "verdict_before": vb,
        "verdict_after": verdict_after,
        "confirmed_fixed": confirmed,
        "reason": reason,
        "regressions": regressions,
        "rolled_back": not confirmed,
        "rollback_verified": None if confirmed else bool(rb and rb.get("verified")),
        # after a rollback: the tunnel re-negotiated on the restored settings and no rule is worse than the baseline
        "service_restored": None if confirmed else (rb or {}).get("service"),
        "dry_run_diff": dry_diff,
        "clone_check": dry_report.get("clone_check"),
        "peer": ({"container": peer, "commands_run": peer_commands_run, "dry_run_diff": peer_dry_diff,
                  "clone_check": dry_report.get("peer", {}).get("clone_check")}
                 if peer else None),
        "lab_prep": lab_prep,
        "watchdog_timeout_s": watchdog_timeout_s,
    }
    record_audit({**audit_base, **result, "rollback": rb, "verdicts_before": before, "verdicts_after": after}, history_dir)
    return result
