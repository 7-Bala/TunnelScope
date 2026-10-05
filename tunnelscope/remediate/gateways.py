"""Real VPN gateways the fix loop may change (DEC-063), and the consent that must come first.

Owner decision 2026-09-27: TunnelScope may apply a fix to a real strongSwan gateway, not only to the
lab, over SSH, with the same safety steps as the lab (execute.py: dry run on copies, an isolated
load check, human approval of the exact diff, a baseline capture, snapshot + watchdog, verify, or
roll back byte for byte). Two extra gates exist only for real gateways, both checked by code:

  1. Terms and risks, accepted once per gateway: the operator types an exact sentence; the
     acceptance is tied to this text (its sha256) and to the gateway's registered definition, so a
     new text or a changed host/user/connection needs a new acceptance.
  2. Per change: the preview lists the risks of THIS change and an acknowledgement sentence; apply
     is refused unless that sentence is sent back exactly, with the digest of the previewed diff.

This module only reads and checks. Writing the registry and the consent log happens in execute.py,
the one module in this package allowed to change anything.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

PREFIX = "gw:"
REGISTRY_FILE = "gateways.yaml"
CONSENT_FILE = "consents.jsonl"
DEFAULT_GLOBS = ("/etc/swanctl/swanctl.conf", "/etc/swanctl/conf.d/*.conf")

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_GLOB = re.compile(r"^/[A-Za-z0-9_./*-]+\.conf$")

TERMS_VERSION = "2026-09-27.1"
TERMS_TITLE = "TunnelScope live gateway changes: terms and risks"
# Plain language on purpose: the person accepting must understand every line. Changing any word
# changes TERMS_SHA256, so every gateway then needs a new acceptance.
TERMS = (
    "What TunnelScope will do. It logs in to this gateway over SSH with the key you configured, "
    "edits only the proposals or version lines of the one registered connection, reloads strongSwan, "
    "and briefly restarts the tunnel to check that the fix worked.",
    "The tunnel will go down for a short time. Every check restarts the tunnel, so traffic through it "
    "stops for a few seconds, before and after the change. Use a maintenance window.",
    "The tunnel may stay down for up to three minutes. If the other end does not accept the new "
    "settings, the tunnel cannot come back until the change is rolled back. The automatic rollback "
    "normally runs within seconds; if TunnelScope loses contact, a timer on the gateway restores the "
    "old files after 180 seconds.",
    "Rollback restores the configuration files byte for byte and reloads strongSwan. It cannot undo "
    "effects outside this gateway, such as sessions that dropped while the tunnel was down. If the "
    "gateway restarts during a change, the backup copies (*.ts_snapshot) stay on disk and must be "
    "restored by hand.",
    "The other end of the tunnel must agree. TunnelScope changes the other end only if it is also "
    "registered and accepted here. If someone else runs the other end, agree the change with them first.",
    "AI-drafted fixes can be wrong. They are checked by code, tried on a copy and test-loaded before "
    "you approve them, but in our tests the AI got 12 to 13 fixes right out of 16. If cloud drafting "
    "is switched on, the rule text and this connection's proposal line are sent to the AI provider.",
    "You are responsible. You confirm that you are allowed to change this gateway, that you have a "
    "tested way to reach it if the tunnel fails, and that you will review every change before you "
    "approve it. TunnelScope is provided as is, without warranty; have your organisation review these "
    "terms before use on production systems.",
    "Everything is recorded. This acceptance, every preview, every change and every rollback is "
    "written to the local audit log with the time and who approved it.",
)
TERMS_SHA256 = hashlib.sha256((TERMS_VERSION + "\n" + TERMS_TITLE + "\n" + "\n".join(TERMS)).encode()).hexdigest()


def terms() -> dict[str, Any]:
    return {"version": TERMS_VERSION, "title": TERMS_TITLE, "clauses": list(TERMS), "sha256": TERMS_SHA256}


def accept_phrase(name: str) -> str:
    """What the operator must type to accept the terms for one gateway."""
    return f"I ACCEPT THE RISKS FOR {name}"


def ack_phrase(rule_id: str, name: str) -> str:
    """What the operator must type to approve one change on one gateway."""
    return f"APPLY {rule_id} ON {name}"


def is_gateway(target: Any) -> bool:
    return isinstance(target, str) and target.startswith(PREFIX)


def name_of(target: str) -> str:
    return target[len(PREFIX):]


def registry_path(history_dir: str | Path | None) -> Path:
    env = os.environ.get("TUNNELSCOPE_GATEWAYS")
    if env:
        return Path(env).expanduser()
    return Path(history_dir or ".tunnelscope-history") / REGISTRY_FILE


def validate_entry(name: Any, entry: Any) -> dict[str, Any]:
    """A normalised gateway definition, or ValueError saying what is wrong."""
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(f"gateway name {name!r} must be letters, digits, '.', '_' or '-'")
    if not isinstance(entry, dict):
        raise ValueError(f"gateway {name}: definition must be a mapping")
    host = entry.get("host")
    if not isinstance(host, str) or not _HOST.match(host):
        raise ValueError(f"gateway {name}: host must be a hostname or IP address")
    user = entry.get("user", "root")
    if not isinstance(user, str) or not _USER.match(user):
        raise ValueError(f"gateway {name}: user must be a plain login name")
    port = entry.get("port", 22)
    if not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError(f"gateway {name}: port must be 1-65535")
    conn = entry.get("connection")
    if not isinstance(conn, str) or not _NAME.match(conn):
        raise ValueError(f"gateway {name}: connection must be the swanctl connection name")
    child = entry.get("child", conn)
    if not isinstance(child, str) or not _NAME.match(child):
        raise ValueError(f"gateway {name}: child must be a swanctl child SA name")
    globs = entry.get("config_globs", list(DEFAULT_GLOBS))
    if isinstance(globs, str):
        globs = globs.split()
    if not isinstance(globs, list) or not globs or not all(isinstance(g, str) and _GLOB.match(g) for g in globs):
        raise ValueError(f"gateway {name}: config_globs must be absolute paths ending in .conf")
    iface = entry.get("capture_interface", "any")
    if not isinstance(iface, str) or not _IFACE.match(iface):
        raise ValueError(f"gateway {name}: capture_interface must be an interface name")
    ident = entry.get("identity_file")
    if ident is not None and (not isinstance(ident, str) or "\n" in ident):
        raise ValueError(f"gateway {name}: identity_file must be a path")
    known = entry.get("known_hosts_file")
    if known is not None and (not isinstance(known, str) or "\n" in known):
        raise ValueError(f"gateway {name}: known_hosts_file must be a path")
    peer = entry.get("peer")
    if peer is not None and (not isinstance(peer, str) or not _NAME.match(peer) or peer == name):
        raise ValueError(f"gateway {name}: peer must name another registered gateway")
    return {"name": name, "host": host, "user": user, "port": port, "connection": conn, "child": child,
            "config_globs": list(globs), "capture_interface": iface, "identity_file": ident,
            "known_hosts_file": known, "peer": peer, "sudo": bool(entry.get("sudo", False)),
            "allow_ai_drafts": bool(entry.get("allow_ai_drafts", False))}


def load_registry(history_dir: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Every valid gateway in the registry file ({} if there is none). An invalid entry is left out;
    `registry_problems` says why."""
    return _load(history_dir)[0]


def registry_problems(history_dir: str | Path | None = None) -> list[str]:
    return _load(history_dir)[1]


def _load(history_dir) -> tuple[dict[str, dict[str, Any]], list[str]]:
    path = registry_path(history_dir)
    if not path.is_file():
        return {}, []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        return {}, [f"{path}: not valid YAML ({type(e).__name__})"]
    gws = data.get("gateways", {}) if isinstance(data, dict) else {}
    out, problems = {}, []
    for name, entry in (gws.items() if isinstance(gws, dict) else []):
        try:
            out[str(name)] = validate_entry(str(name), entry)
        except ValueError as e:
            problems.append(str(e))
    for name, g in list(out.items()):
        if g["peer"] and g["peer"] not in out:
            problems.append(f"gateway {name}: peer {g['peer']!r} is not registered")
            out.pop(name)
    return out, problems


def get(target: str, history_dir: str | Path | None = None) -> dict[str, Any] | None:
    return load_registry(history_dir).get(name_of(target)) if is_gateway(target) else None


def fingerprint(gw: dict[str, Any]) -> str:
    """What an acceptance is tied to: where the gateway is, who logs in, what may change."""
    keep = {k: gw.get(k) for k in ("name", "host", "port", "user", "connection", "child", "config_globs",
                                   "peer", "sudo", "allow_ai_drafts")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True).encode()).hexdigest()


def consents(history_dir: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(history_dir or ".tunnelscope-history") / CONSENT_FILE
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict):
            out.append(e)
    return out


def consent_status(gw: dict[str, Any], history_dir: str | Path | None = None) -> dict[str, Any]:
    """{accepted: bool, reason, by, at} for the latest acceptance or withdrawal for this gateway."""
    last = None
    for e in consents(history_dir):
        if e.get("gateway") == gw["name"]:
            last = e
    if last is None:
        return {"accepted": False, "reason": "the terms and risks have not been accepted for this gateway"}
    if last.get("decision") == "withdrawn":
        return {"accepted": False, "reason": "the acceptance for this gateway was withdrawn", "at": last.get("at")}
    if last.get("terms_sha256") != TERMS_SHA256:
        return {"accepted": False, "reason": "the terms have changed since they were accepted; accept the new version"}
    if last.get("gateway_fingerprint") != fingerprint(gw):
        return {"accepted": False, "reason": "the gateway's definition changed since the terms were accepted; accept again"}
    return {"accepted": True, "reason": None, "by": last.get("accepted_by"), "at": last.get("at")}


def change_risks(gw: dict[str, Any], rule_id: str, *, generated: bool, cloud_backend: bool,
                 peer: dict[str, Any] | None) -> list[str]:
    """The risks of one change, shown in the preview and repeated in the audit log."""
    risks = [
        f"The tunnel '{gw['connection']}' on {gw['name']} ({gw['host']}) restarts about three times during this "
        "change (baseline check, verification, and once more if it is rolled back). Traffic stops for a few seconds each time.",
        "If verification fails, the old configuration is restored automatically and checked byte for byte; "
        "if TunnelScope loses contact, the gateway restores it by itself after 180 seconds.",
    ]
    if peer:
        risks.append(f"The same change is made on the other end, {peer['name']} ({peer['host']}), so both ends agree.")
    else:
        risks.append("Only this end is changed. If the other end does not accept the new settings, the tunnel fails "
                     "verification and the change is rolled back.")
    if generated:
        risks.append("This fix was drafted by AI. It passed every code check and the dry run, but AI drafts are "
                     "not yet reliable enough to trust without reading the change (12-13 of 16 right in our tests).")
        if cloud_backend:
            risks.append("The draft came from a cloud AI model: the rule text and this connection's proposal "
                         "line were sent to the provider.")
    risks.append(f"You are approving {rule_id} on a real gateway, not the lab.")
    return risks
