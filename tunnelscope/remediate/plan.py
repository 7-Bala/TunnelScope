"""Remediation plan generator (Stage 1: read-only, no execution).

Maps rule IDs to deterministic, standard-referenced remediation steps.
Purely advisory text lookup -- strictly offline, no execution.
"""
from __future__ import annotations

REMEDIATION = {
    "V-207205": {
        "change": "Move IKEv1 to IKEv2",
        "commands": ["set `version = 2` in the connection's swanctl.conf", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/version\\s*=\\s*1/version = 2/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "V-207193": {
        "change": "Raise the DH group",
        "commands": ["set `proposals` to include ecp384 or modp4096, remove the weak group",
                      "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/modp(1024|1536|2048)/modp4096/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "V-207223": {
        "change": "Raise integrity to SHA-384+",
        "commands": ["set proposal integrity to sha384 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/-(sha1|sha256|md5)-/-sha384-/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8247-DH-MUST": {
        "change": "Drop a forbidden DH group that was picked",
        "commands": ["remove the forbidden group from `proposals`", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/modp(768|1024|1536)/modp3072/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8247-DH-OFFER": {
        "change": "Drop a forbidden DH group still offered",
        "commands": ["remove the forbidden group from the OTHER endpoint's proposal list",
                      "swanctl --load-all on that endpoint"],
        "auto_applicable": True,
        "exec_commands": [],
    },
    "RFC8247-ENCR": {
        "change": "Handshake cipher to AES-GCM",
        "commands": ["set the IKE proposal to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/proposals\\s*=\\s*(3des|des|aes128|aes256)-[a-zA-Z0-9_-]+/proposals = aes256gcm16-prfsha256-modp3072/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "CVE-2026-78135": {
        "change": "Patch, not a config change",
        "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
        "auto_applicable": False,
        "exec_commands": [],
    },
    "DST-PQ-KE": {
        "change": "Add hybrid PQ key exchange",
        "commands": ["set proposals to include ke1_ke2 = ke1_mlkem768 (or vendor equivalent)",
                      "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E '/proposals\\s*=/ { /mlkem/! s/proposals\\s*=\\s*([^;\\n]+)/proposals = \\1-ke1_mlkem768/ }' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "DST-PQ-DOWNGRADE": {
        "change": "Stop allowing classical-only fallback",
        "commands": ["remove the classical-only proposal from the list entirely (no fallback offered)",
                      "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [],
    },
    "RFC4301-CONFIDENTIALITY": {
        "change": "AH to ESP",
        "commands": ["change `esp_proposals` in place of `ah_proposals`", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [],
    },
    "RFC8221-AH-INTEG": {
        "change": "AH integrity off MD5",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/ah_proposals\\s*=\\s*.*md5.*/ah_proposals = sha256/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8221-AH-LEGACY": {
        "change": "AH integrity off legacy 96-bit",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/ah_proposals\\s*=\\s*.*(sha1|md5).*/ah_proposals = sha256/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8221-ESP-3DES": {
        "change": "ESP cipher off 3DES",
        "commands": ["set `esp_proposals` to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
        "exec_commands": [
            "sed -i -E 's/esp_proposals\\s*=\\s*.*3des.*/esp_proposals = aes256gcm16/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC4303-SEQ": {
        "change": "Not a config fix",
        "commands": ["replay is a symptom (misconfigured anti-replay window, or an attack) -- investigate, no command"],
        "auto_applicable": False,
        "exec_commands": [],
    },
}


def plan_for(rule_id: str, observed=None, include_exec: bool = False) -> dict | None:
    """Return a deterministic remediation plan for `rule_id`, or None if unknown."""
    if not isinstance(rule_id, str):
        return None
    entry = REMEDIATION.get(rule_id)
    if not entry:
        return None
    res = {
        "rule_id": str(rule_id),
        "change": entry["change"],
        "commands": list(entry["commands"]),
        "auto_applicable": entry["auto_applicable"],
        "observed": observed,
    }
    if include_exec:
        res["exec_commands"] = list(entry.get("exec_commands", []))
    return res
