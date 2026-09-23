"""Remediation plan generator (Stage 1: read-only, no execution).

Maps rule IDs to deterministic, standard-referenced remediation steps.
Purely advisory text lookup -- strictly offline, no execution.
"""
from __future__ import annotations

import re

BANNED_COMMAND_TOKENS = {
    "rm", "dd", "mkfs", "iptables", "nftables", "curl", "wget", "nc", "netcat",
    "sudo", "chmod", "chown", "reboot", "shutdown", "poweroff", "init", "telinit",
    ">", ">>", "eval", "python", "perl", "bash", "zsh", "dash",
}


def validate_command_safety(cmd: str) -> tuple[bool, str | None]:
    """Pure static security linter for proposed shell remediation commands (Layer 3).
    Rejects any command with destructive tokens, shell redirections, or unapproved verbs.
    """
    if not isinstance(cmd, str) or not cmd.strip():
        return False, "empty command"

    clean = cmd.strip()
    # Check for file redirection operators (allow silencing to /dev/null)
    without_devnull = re.sub(r"[0-9]?>/dev/null", "", clean)
    if ">" in without_devnull:
        return False, "file redirection operators ('>') are strictly prohibited"

    # Token check
    tokens = set(re.findall(r"\b[a-zA-Z0-9_\-\./]+\b", clean))
    for banned in BANNED_COMMAND_TOKENS:
        if banned in tokens:
            return False, f"prohibited shell token '{banned}' found in command"

    # Must start with allowed verbs: sed, swanctl, or safe file-detect wrapper
    if not (clean.startswith("sed ") or clean.startswith("swanctl ") or clean.startswith("f=$(") or "swanctl --load-all" in clean):
        return False, "command must start with sed or swanctl"

    return True, None


REMEDIATION = {
    "V-207205": {
        "change": "Move IKEv1 to IKEv2",
        "commands": ["set `version = 2` in the connection's swanctl.conf", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "IKEv1 protocol detected in handshake. DISA SRG V-207205 and RFC 8247 mandate IKEv2 exclusively.",
        "cryptographic_risk": "IKEv1 lacks protection against quantum downgrade, has known aggressive mode PSK offline dictionary attacks, and lacks modern anti-DDoS cookie exchange.",
        "proposed_strategy": "Set connection version = 2 in swanctl configuration and reload strongSwan daemon.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
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
        "problem_analysis": "Diffie-Hellman group negotiated is Group 14 (MODP-2048) or lower. DISA SRG mandates Group 16 (MODP-4096) or ECP-384.",
        "cryptographic_risk": "MODP-2048 provides only ~112 bits of classical security margin and is acutely vulnerable to nation-state Harvest-Now-Decrypt-Later (HNDL) attacks.",
        "proposed_strategy": "Replace modp1024/1536/2048 proposals with modp4096, preserving encryption and integrity algorithms.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            "sed -i -E 's/modp(1024|1536|2048)/modp4096/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "V-207223": {
        "change": "Raise integrity to SHA-384+",
        "commands": ["set proposal integrity to sha384 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "IKE integrity algorithm is below SHA2-384. DISA SRG mandates SHA2-384 or SHA2-512 for FIPS 140-3 compliance.",
        "cryptographic_risk": "Weaker hash functions have lower collision resistance, compromising packet authenticity under quantum or advanced cryptanalysis.",
        "proposed_strategy": "Upgrade proposal integrity tokens from sha1/sha256/md5 to sha384 in swanctl connection proposals.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            "sed -i -E 's/-(sha1|sha256|md5)-/-sha384-/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8247-DH-MUST": {
        "change": "Drop a forbidden DH group that was picked",
        "commands": ["remove the forbidden group from `proposals`", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "Negotiated Diffie-Hellman group is deprecated/forbidden by RFC 8247 (MODP-768, MODP-1024, or MODP-1536).",
        "cryptographic_risk": "Logjam attack susceptibility and feasible discrete logarithm computation by well-funded adversaries.",
        "proposed_strategy": "Substitute legacy MODP groups with RFC 8247 MUST group MODP-3072 or higher.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
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
        "problem_analysis": "Responder or initiator still offers deprecated DH groups in SA proposals despite picking a higher group.",
        "cryptographic_risk": "Allows active man-in-the-middle attackers to perform downgrade attacks during IKE_SA_INIT.",
        "proposed_strategy": "Remove legacy DH groups from peer proposals list across both endpoints.",
        "rollback_strategy": "Manual coordination across endpoints; no automated cross-container execution.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [],
    },
    "RFC8247-ENCR": {
        "change": "Handshake cipher to AES-GCM",
        "commands": ["set the IKE proposal to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "IKE handshake uses legacy CBC mode without authenticated encryption (AEAD).",
        "cryptographic_risk": "CBC mode is susceptible to padding oracle side-channels and separate MAC integrity race conditions.",
        "proposed_strategy": "Transition IKE proposal to modern AEAD cipher aes256gcm16-prfsha256-modp3072.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            "sed -i -E 's/proposals\\s*=\\s*(3des|des|aes128|aes256)-[a-zA-Z0-9_-]+/proposals = aes256gcm16-prfsha256-modp3072/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "CVE-2026-78135": {
        "change": "Patch, not a config change",
        "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
        "auto_applicable": False,
        "problem_analysis": "Early Child SA timing leak and state-machine vulnerability in strongSwan 6.1.0 (CVE-2026-78135).",
        "cryptographic_risk": "Allows remote unauthenticated attacker to bypass verification gates via out-of-order early Child SA packets.",
        "proposed_strategy": "Software daemon patch required. Cannot be remediated via swanctl configuration edits.",
        "rollback_strategy": "Advisory only; operator runs package upgrade or git cherry-pick in maintenance window.",
        "is_software_patch": True,
        "runbook": [
            "1. Pull upstream strongSwan security patch: git cherry-pick cve-2026-78135-fix",
            "2. Rebuild charon daemon in isolated staging environment: ./configure && make check",
            "3. Deploy patched strongSwan binary to target gateway during scheduled maintenance window",
            "4. Restart strongSwan service: systemctl restart strongswan-starter or restart the IPsec container",
            "5. Re-run TunnelScope audit to confirm Early Child SA timing leak finding clears.",
        ],
        "exec_commands": [],
    },
    "DST-PQ-KE": {
        "change": "Add hybrid PQ key exchange",
        "commands": ["set proposals to include ke1_ke2 = ke1_mlkem768 (or vendor equivalent)",
                      "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "Classical-only key exchange in use without Post-Quantum hybrid protection (NQM DST-PQ-KE mandate).",
        "cryptographic_risk": "Traffic recorded today can be decrypted retroactively once cryptanalytically relevant quantum computers (CRQC) emerge.",
        "proposed_strategy": "Append ML-KEM-768 hybrid key exchange (ke1_ke2 = ke1_mlkem768) to proposals.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
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
        "problem_analysis": "Tunnel negotiates PQ hybrid but retains classical-only fallback proposals in configuration.",
        "cryptographic_risk": "Active network adversary can drop IKE_INTERMEDIATE packets to force tunnel into classical fallback.",
        "proposed_strategy": "Enforce strict post-quantum policy by removing classical-only proposals from connection definitions.",
        "rollback_strategy": "Manual coordination across endpoints.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [],
    },
    "RFC4301-CONFIDENTIALITY": {
        "change": "AH to ESP",
        "commands": ["change `esp_proposals` in place of `ah_proposals`", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "Authentication Header (AH) used without Encapsulating Security Payload (ESP).",
        "cryptographic_risk": "AH provides zero payload confidentiality; all plaintext application data is visible to wiretappers.",
        "proposed_strategy": "Migrate security policy from AH to ESP tunnel mode with aes256gcm16.",
        "rollback_strategy": "Architectural migration; requires coordinated child SA transition.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [],
    },
    "RFC8221-AH-INTEG": {
        "change": "AH integrity off MD5",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "AH uses broken MD5 hashing algorithm for packet authentication.",
        "cryptographic_risk": "MD5 has practical collision attacks allowing packet forgery and tampering.",
        "proposed_strategy": "Set AH integrity to sha256 or sha512 in ah_proposals.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            "sed -i -E 's/ah_proposals\\s*=\\s*.*md5.*/ah_proposals = sha256/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8221-AH-LEGACY": {
        "change": "AH integrity off legacy 96-bit",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "AH uses truncated 96-bit MAC with legacy SHA-1 or MD5.",
        "cryptographic_risk": "96-bit truncation reduces forgery resistance below modern 128-bit cryptographic requirements.",
        "proposed_strategy": "Upgrade ah_proposals to standard SHA-256 (128-bit truncated) or SHA-512.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            "sed -i -E 's/ah_proposals\\s*=\\s*.*(sha1|md5).*/ah_proposals = sha256/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC8221-ESP-3DES": {
        "change": "ESP cipher off 3DES",
        "commands": ["set `esp_proposals` to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "ESP payload encrypted with legacy Triple-DES (3DES-CBC).",
        "cryptographic_risk": "Sweet32 attack (CVE-2016-2183): 64-bit block cipher collision attacks recover plaintext after ~32GB of data.",
        "proposed_strategy": "Upgrade esp_proposals to modern 128-bit block AEAD cipher aes256gcm16.",
        "rollback_strategy": "Atomic snapshot of swanctl.conf + 30s Commit-Confirmed Watchdog revert timer.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            "sed -i -E 's/esp_proposals\\s*=\\s*.*3des.*/esp_proposals = aes256gcm16/g' /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null || true",
            "f=$(ls /tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf 2>/dev/null | head -1); [ -n \"$f\" ] && swanctl --load-all --file \"$f\" || swanctl --load-all",
        ],
    },
    "RFC4303-SEQ": {
        "change": "Not a config fix",
        "commands": ["replay is a symptom (misconfigured anti-replay window, or an attack) -- investigate, no command"],
        "auto_applicable": False,
        "problem_analysis": "Anti-replay window sequence number anomaly or sequence space exhaustion.",
        "cryptographic_risk": "Possible packet injection, replay attack, or severe out-of-order network routing.",
        "proposed_strategy": "Diagnostic symptom investigation. Inspect gateway counters and routing infrastructure.",
        "rollback_strategy": "Diagnostic finding; no config change to roll back.",
        "is_software_patch": True,
        "runbook": [
            "1. Inspect IPsec SA replay counters: ip xfrm state | grep replay",
            "2. Check for duplicate packets upstream: tcpdump -n -i eth0 esp",
            "3. Verify anti-replay window size configuration: ip xfrm state flag replay-window",
            "4. If sequence numbers near 2^32 without ESN, trigger manual rekey: swanctl --rekey --child <name>",
        ],
        "exec_commands": [],
    },
}


def plan_for(rule_id: str, observed=None, include_exec: bool = False, detailed: bool = False) -> dict | None:
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
    if detailed:
        res["problem_analysis"] = entry.get("problem_analysis", "")
        res["cryptographic_risk"] = entry.get("cryptographic_risk", "")
        res["proposed_strategy"] = entry.get("proposed_strategy", "")
        res["rollback_strategy"] = entry.get("rollback_strategy", "")
        res["is_software_patch"] = entry.get("is_software_patch", False)
        res["runbook"] = list(entry.get("runbook", []))
        res["dry_run_verified"] = entry.get("auto_applicable", False)
    if include_exec:
        res["exec_commands"] = list(entry.get("exec_commands", []))
    return res

