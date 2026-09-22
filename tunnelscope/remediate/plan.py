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
    },
    "V-207193": {
        "change": "Raise the DH group",
        "commands": ["set `proposals` to include ecp384 or modp4096, remove the weak group",
                      "swanctl --load-all"],
        "auto_applicable": True,
    },
    "V-207223": {
        "change": "Raise integrity to SHA-384+",
        "commands": ["set proposal integrity to sha384 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8247-DH-MUST": {
        "change": "Drop a forbidden DH group that was picked",
        "commands": ["remove the forbidden group from `proposals`", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8247-DH-OFFER": {
        "change": "Drop a forbidden DH group still offered",
        "commands": ["remove the forbidden group from the OTHER endpoint's proposal list",
                      "swanctl --load-all on that endpoint"],
        "auto_applicable": True,
    },
    "RFC8247-ENCR": {
        "change": "Handshake cipher to AES-GCM",
        "commands": ["set the IKE proposal to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "CVE-2026-78135": {
        "change": "Patch, not a config change",
        "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
        "auto_applicable": False,
    },
    "DST-PQ-KE": {
        "change": "Add hybrid PQ key exchange",
        "commands": ["set proposals to include ke1_ke2 = ke1_mlkem768 (or vendor equivalent)",
                      "swanctl --load-all"],
        "auto_applicable": True,
    },
    "DST-PQ-DOWNGRADE": {
        "change": "Stop allowing classical-only fallback",
        "commands": ["remove the classical-only proposal from the list entirely (no fallback offered)",
                      "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC4301-CONFIDENTIALITY": {
        "change": "AH to ESP",
        "commands": ["change `esp_proposals` in place of `ah_proposals`", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8221-AH-INTEG": {
        "change": "AH integrity off MD5",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8221-AH-LEGACY": {
        "change": "AH integrity off legacy 96-bit",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC8221-ESP-3DES": {
        "change": "ESP cipher off 3DES",
        "commands": ["set `esp_proposals` to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
    },
    "RFC4303-SEQ": {
        "change": "Not a config fix",
        "commands": ["replay is a symptom (misconfigured anti-replay window, or an attack) -- investigate, no command"],
        "auto_applicable": False,
    },
}


def plan_for(rule_id: str, observed=None) -> dict | None:
    """Return a deterministic remediation plan for `rule_id`, or None if unknown."""
    if not isinstance(rule_id, str):
        return None
    entry = REMEDIATION.get(rule_id)
    if entry is None:
        return None
    return {
        "rule_id": rule_id,
        "change": entry["change"],
        "commands": list(entry["commands"]),
        "auto_applicable": entry["auto_applicable"],
        "observed": observed,
    }
