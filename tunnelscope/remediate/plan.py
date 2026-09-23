"""Remediation plan generator (Stage 1: read-only, no execution).

Maps rule IDs to deterministic, standard-referenced remediation steps.
Purely advisory text lookup -- strictly offline, no execution.

Every plan and every command here is written by hand and reviewed. No language model
generates any of it (DEC-033 designs a guarded generator; it is not built). The command
checker below is written for that future case anyway: it must hold even if the text it
is given came from a model that is wrong or has been manipulated.
"""
from __future__ import annotations

import re

# The config files a remediation may touch inside a lab container, and the only reload
# command allowed. Every automated command must be one of exactly two shapes:
#   sed -i -E '<script>' <CONFIG_GLOBS> 2>/dev/null || true
#   <RELOAD_COMMAND>   (or the short form "swanctl --load-all")
# The execution engine does not hand these strings to a shell. It extracts the sed script
# and runs sed / swanctl directly with an argument list, so shell syntax in a command
# cannot take effect even if a check below were ever wrong.
CONFIG_GLOBS = "/tmp/exp15-*.conf /tmp/*.conf /etc/swanctl/conf.d/*.conf"
RELOAD_COMMAND = (
    'f=$(ls ' + CONFIG_GLOBS + ' 2>/dev/null | head -1); '
    '[ -n "$f" ] && swanctl --load-all --file "$f" || swanctl --load-all'
)
RELOAD_SHORT = "swanctl --load-all"
_SED_PREFIX = "sed -i -E '"
_SED_SUFFIX = "' " + CONFIG_GLOBS + " 2>/dev/null || true"

# Second line of defence. The template and grammar checks are what actually decide;
# this list only gives a clearer message for the obvious cases.
BANNED_COMMAND_TOKENS = {
    "rm", "dd", "mkfs", "iptables", "nftables", "curl", "wget", "nc", "netcat", "ncat", "socat",
    "sudo", "su", "chmod", "chown", "chgrp", "reboot", "shutdown", "poweroff", "init", "telinit", "halt",
    ">", ">>", "eval", "exec", "python", "python2", "python3", "perl", "ruby", "lua", "php", "node",
    "bash", "sh", "zsh", "dash", "ash", "busybox", "kill", "pkill", "killall",
    "cat", "tee", "cp", "mv", "ln", "unlink", "rmdir", "touch",
    "env", "export", "source", "useradd", "usermod", "userdel", "groupadd",
    "apt", "apt-get", "apk", "yum", "dnf", "pacman",
    "awk", "gawk", "mawk", "nawk", "xargs", "find", "base64", "xxd", "openssl", "crontab",
}


class SedScriptError(ValueError):
    """A sed script outside the allowed grammar."""


_SUBST_FLAGS_ALLOWED = set("gI")
_REPL_ESCAPES_ALLOWED = set("0123456789/&\\.-")


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _check_brackets(regex: str) -> None:
    """Reject a regex whose bracket expressions are unbalanced. sed and this parser might
    otherwise disagree about where the regex ends (a '/' inside [...]), and any
    disagreement between the checker and the real tool is a way past the checker."""
    i, in_bracket = 0, False
    while i < len(regex):
        c = regex[i]
        if not in_bracket:
            if c == "\\":
                i += 2
                continue
            if c == "[":
                in_bracket = True
                i += 1
                if i < len(regex) and regex[i] == "^":
                    i += 1
                if i < len(regex) and regex[i] == "]":
                    i += 1
                continue
            i += 1
            continue
        if regex.startswith("[:", i) or regex.startswith("[=", i) or regex.startswith("[.", i):
            close = regex.find(regex[i + 1] + "]", i + 2)
            if close < 0:
                raise SedScriptError("unterminated character class in regex")
            i = close + 2
            continue
        if c == "]":
            in_bracket = False
        i += 1
    if in_bracket:
        raise SedScriptError("unterminated bracket expression in regex (a '/' inside [...] is not allowed)")


def _scan_delimited(s: str, i: int, *, repl: bool = False) -> tuple[str, int]:
    """Read from s[i] up to the next unescaped '/'. Returns (text, index of that '/')."""
    out = []
    while i < len(s):
        c = s[i]
        if c == "\\":
            if i + 1 >= len(s):
                raise SedScriptError("dangling backslash")
            nxt = s[i + 1]
            if repl and nxt not in _REPL_ESCAPES_ALLOWED:
                raise SedScriptError(f"escape '\\{nxt}' is not allowed in a replacement")
            out.append(s[i:i + 2])
            i += 2
            continue
        if c == "/":
            return "".join(out), i
        out.append(c)
        i += 1
    raise SedScriptError("unterminated '/' expression")


def _parse_address(s: str, i: int) -> tuple[dict, int]:
    regex, j = _scan_delimited(s, i + 1)
    _check_brackets(regex)
    return {"regex": regex}, j + 1


def _parse_command(s: str, i: int, depth: int) -> tuple[dict, int]:
    i = _skip_ws(s, i)
    node: dict = {"addr1": None, "addr2": None, "negate": False}
    if i < len(s) and s[i] == "/":
        node["addr1"], i = _parse_address(s, i)
        i = _skip_ws(s, i)
        if i < len(s) and s[i] == ",":
            i = _skip_ws(s, i + 1)
            if i >= len(s) or s[i] != "/":
                raise SedScriptError("a range must end with a /regex/ address (line numbers are not allowed)")
            node["addr2"], i = _parse_address(s, i)
            i = _skip_ws(s, i)
        if i < len(s) and s[i] == "!":
            node["negate"] = True
            i = _skip_ws(s, i + 1)
    if i >= len(s):
        raise SedScriptError("missing command")
    c = s[i]
    if c == "{":
        if depth >= 1:
            raise SedScriptError("nested { } blocks are not allowed")
        body, i = _parse_command(s, i + 1, depth + 1)
        i = _skip_ws(s, i)
        if i >= len(s) or s[i] != "}":
            raise SedScriptError("a { } block must hold exactly one command and end with '}'")
        node.update(kind="block", body=body)
        return node, i + 1
    if c == "s":
        if i + 1 >= len(s) or s[i + 1] != "/":
            raise SedScriptError("a substitution must use '/' as its delimiter")
        regex, j = _scan_delimited(s, i + 2)
        _check_brackets(regex)
        repl, k = _scan_delimited(s, j + 1, repl=True)
        i = k + 1
        flags = ""
        while i < len(s) and s[i].isalnum():
            flags += s[i]
            i += 1
        for f in flags:
            if f not in _SUBST_FLAGS_ALLOWED:
                raise SedScriptError(f"sed flag '{f}' is not allowed (only g and I; 'e' runs a shell, 'w' writes a file)")
        node.update(kind="s", regex=regex, repl=repl, flags=flags)
        return node, i
    raise SedScriptError(
        f"sed command '{c}' is not allowed (only s/// substitutions, optionally inside one /regex/ address block)"
    )


def parse_sed_script(script: str) -> dict:
    """Parse a sed script under the allowed grammar and return its command tree.

        script := command
        command := [ /re/ [ , /re/ ] ] [ ! ] ( s/re/replacement/[gI]* | { command } )

    One command only (no ';' chaining), '/' delimiters only, no line-number addresses,
    no 'e'/'w'/'r'/'R'/'W' or any other sed command, no nested blocks, and replacement
    escapes limited to back-references and literal punctuation."""
    if not isinstance(script, str) or not script.strip():
        raise SedScriptError("empty sed script")
    for bad, why in (("'", "a quote"), ("`", "a backtick"), ("$(", "command substitution"),
                     ("\n", "a newline"), ("\r", "a carriage return"), ("\x00", "a NUL byte")):
        if bad in script:
            raise SedScriptError(f"sed script contains {why}")
    node, i = _parse_command(script, 0, depth=0)
    i = _skip_ws(script, i)
    if i != len(script):
        raise SedScriptError(f"unexpected text after the command: {script[i:i + 24]!r} (one command only; ';' chaining is not allowed)")
    return node


def sed_script_of(cmd: str) -> str | None:
    """The sed script inside an allowed sed command, or None if `cmd` is not in the sed template."""
    if isinstance(cmd, str) and cmd.startswith(_SED_PREFIX) and cmd.endswith(_SED_SUFFIX):
        return cmd[len(_SED_PREFIX):len(cmd) - len(_SED_SUFFIX)]
    return None


def is_reload_command(cmd: str) -> bool:
    return cmd in (RELOAD_COMMAND, RELOAD_SHORT)


def sed_command(script: str) -> str:
    """Build a command string in the allowed sed template (used for the lab-peer step)."""
    return _SED_PREFIX + script + _SED_SUFFIX


def validate_command_safety(cmd: str) -> tuple[bool, str | None]:
    """Static command checker (Layer 3). An allowlist: a command passes only if it is the
    fixed reload command, or the fixed sed template whose script parses under
    `parse_sed_script`. The banned-token list runs first only for clearer messages."""
    if not isinstance(cmd, str) or not cmd.strip():
        return False, "empty command"

    clean = cmd.strip()
    without_devnull = re.sub(r"[0-9]?>\s*/dev/null", "", clean)
    if ">" in without_devnull:
        return False, "file redirection operators ('>') are strictly prohibited"

    for t in re.findall(r"\b[a-zA-Z0-9_\-\./]+\b", clean):
        if t in BANNED_COMMAND_TOKENS or re.match(r"^python[0-9.]*$", t):
            return False, f"prohibited shell token '{t}' found in command"

    if is_reload_command(cmd):
        return True, None
    script = sed_script_of(cmd)
    if script is None:
        return False, ("command must start with sed or swanctl and match an allowed template exactly "
                       "(a sed substitution on the lab config files, or the fixed swanctl reload)")
    try:
        parse_sed_script(script)
    except SedScriptError as e:
        return False, f"sed script not allowed: {e}"
    return True, None


# Every automated fix changes ONE connection: the lab tunnel whose handshake is captured before
# and after, so every line that changes is a line that gets verified. The lab configs are
# generated (testbed/scripts/gen_exp15_conf.py) with each connection opening at exactly four
# spaces ("    t-tun {") and closing with "    }", and nested blocks indented deeper, so this
# range selects exactly that connection. A file-wide edit would also rewrite the other 37
# experiment connections in the same file (and rename auth IDs such as "a-s-modp1024"), none of
# which is verified. The dry run independently refuses any change outside this connection.
LAB_CONNECTION = "t-tun"
_CONNECTION_RANGE = "/^    " + LAB_CONNECTION + " \\{/,/^    \\}/"
_IKE_PROPOSALS = "/^[[:space:]]*proposals[[:space:]]*=/"


def _in_connection(command: str) -> str:
    """A sed command in the allowed template, limited to the lab connection."""
    return sed_command(_CONNECTION_RANGE + " { " + command + " }")


# Both ends of a tunnel must agree on a proposal, so the same fix is also applied to the other
# end of the lab tunnel (the responder). It is shown in the preview, snapshotted, and rolled back
# with the target. (Until 2026-09-23 the peer got a fixed acceptance list whose range ended at the
# first "}", i.e. inside the local {} block, so on the real lab config it changed nothing.)
LAB_PEERS = {"sih26-alice-pq": "sih26-bob-pq", "sih26-bob-pq": "sih26-alice-pq"}
PEER_PREP_TARGETS = {"sih26-alice-pq", "sih26-bob-pq"}


def peer_commands_for(plan: dict) -> list[str]:
    return list(plan.get("exec_commands", []))


_ROLLBACK_TEXT = (
    "Snapshot of every swanctl config file first (and of the lab peer's, if it is touched), "
    "plus a Commit-Confirmed Watchdog inside the container that restores the snapshot on its own "
    "if the change is not verified within 180 s. A failed or regressing verification restores "
    "immediately, and the restored files are checked byte for byte against the originals."
)


REMEDIATION = {
    "V-207205": {
        "change": "Move IKEv1 to IKEv2",
        "commands": ["set `version = 2` in the connection's swanctl.conf", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "IKEv1 protocol detected in handshake. DISA SRG V-207205 and RFC 8247 mandate IKEv2 exclusively.",
        "cryptographic_risk": "IKEv1 lacks protection against quantum downgrade, has known aggressive mode PSK offline dictionary attacks, and lacks modern anti-DDoS cookie exchange.",
        "proposed_strategy": "Set connection version = 2 in swanctl configuration and reload strongSwan daemon.",
        "config_diff": "- version = 1\n+ version = 2",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(r"s/^([[:space:]]*version[[:space:]]*=[[:space:]]*)1[[:space:]]*$/\12/"),
            RELOAD_COMMAND,
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
        "config_diff": "- proposals = aes256-sha256-modp2048\n+ proposals = aes256-sha256-modp4096",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(_IKE_PROPOSALS + r" s/modp(1024|1536|2048)/modp4096/g"),
            RELOAD_COMMAND,
        ],
    },
    "V-207223": {
        "change": "Raise integrity to SHA-384+",
        "commands": ["set proposal integrity to sha384 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "IKE integrity algorithm is below SHA2-384. DISA SRG mandates SHA2-384 or SHA2-512 for FIPS 140-3 compliance.",
        "cryptographic_risk": "Weaker hash functions have lower collision resistance, compromising packet authenticity under quantum or advanced cryptanalysis.",
        "proposed_strategy": "Upgrade proposal integrity tokens from sha1/sha256/md5 to sha384 in swanctl connection proposals.",
        "config_diff": "- proposals = aes256-sha256-modp4096\n+ proposals = aes256-sha384-modp4096",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(_IKE_PROPOSALS + r" s/-(sha1|sha256|md5)-/-sha384-/g"),
            RELOAD_COMMAND,
        ],
    },
    "RFC8247-DH-MUST": {
        "change": "Drop a forbidden DH group that was picked",
        "commands": ["remove the forbidden group from `proposals`", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "Negotiated Diffie-Hellman group is deprecated/forbidden by RFC 8247 (MODP-768, MODP-1024, or MODP-1536).",
        "cryptographic_risk": "Logjam attack susceptibility and feasible discrete logarithm computation by well-funded adversaries.",
        "proposed_strategy": "Substitute legacy MODP groups with RFC 8247 MUST group MODP-3072 or higher.",
        "config_diff": "- proposals = aes256-sha256-modp1024\n+ proposals = aes256-sha256-modp3072",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(_IKE_PROPOSALS + r" s/modp(768|1024|1536)/modp3072/g"),
            RELOAD_COMMAND,
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
        "config_diff": "- proposals = aes256-sha256-modp3072, aes256-sha256-modp1024\n+ proposals = aes256-sha256-modp3072",
        "rollback_strategy": "Manual coordination across endpoints; no automated cross-container execution.",
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [],
    },
    "RFC8247-ENCR": {
        "change": "Handshake cipher to AES",
        "commands": ["in the IKE proposal, replace the non-AES cipher with aes256 (AES-GCM is preferred where both ends support it)",
                     "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "The IKE handshake is encrypted with a cipher that is not AES or ChaCha20 (for example 3DES). RFC 8247 approves AES (GCM preferred, CBC acceptable) and ChaCha20.",
        "cryptographic_risk": "Legacy ciphers such as 3DES have a 64-bit block size (Sweet32 birthday attacks on long-lived SAs) and are deprecated by RFC 8247.",
        "proposed_strategy": "In the IKE `proposals` line only, replace the non-AES encryption algorithm of each proposal with aes256, keeping its integrity algorithm and DH group unchanged. ESP proposals are not touched.",
        "config_diff": "- proposals = 3des-sha256-modp4096\n+ proposals = aes256-sha256-modp4096",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        # Before 2026-09-23 this rewrote every line containing "proposals" (including
        # esp_proposals, where an IKE PRF is invalid), replaced already-compliant AES
        # proposals, and lowered modp4096 to modp3072, breaking V-207193. Now: the IKE line of
        # the lab connection only, and only the non-AES cipher token.
        "exec_commands": [
            _in_connection(_IKE_PROPOSALS + r" s/(=[[:space:]]*|,[[:space:]]*)(3des|des|blowfish|cast|twofish|serpent|camellia)[0-9]*-/\1aes256-/g"),
            RELOAD_COMMAND,
        ],
    },
    "CVE-2026-78135": {
        "change": "Patch, not a config change",
        "commands": ["this is a software-patch instruction, not a config diff -- no auto-apply"],
        "auto_applicable": False,
        "problem_analysis": "Early Child SA timing leak and state-machine vulnerability in strongSwan 6.1.0 (CVE-2026-78135).",
        "cryptographic_risk": "Allows remote unauthenticated attacker to bypass verification gates via out-of-order early Child SA packets.",
        "proposed_strategy": "Software daemon patch required. Cannot be remediated via swanctl configuration edits.",
        "config_diff": "# Software patch required: strongSwan 6.1.0 early Child SA state machine\n# No configuration file modification",
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
        "config_diff": "- proposals = aes256-sha384-modp4096\n+ proposals = aes256-sha384-modp4096-ke1_mlkem768",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(_IKE_PROPOSALS + r" s/^([[:space:]]*proposals[[:space:]]*=.*[^[:space:]])[[:space:]]*$/\1-ke1_mlkem768/"),
            RELOAD_COMMAND,
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
        "config_diff": "- proposals = aes256-sha384-modp4096-ke1_mlkem768, aes256-sha384-modp4096\n+ proposals = aes256-sha384-modp4096-ke1_mlkem768",
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
        "config_diff": "- ah_proposals = sha256\n+ esp_proposals = aes256gcm16",
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
        "config_diff": "- ah_proposals = md5\n+ ah_proposals = sha256",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(r"s/ah_proposals[[:space:]]*=[[:space:]]*.*md5.*/ah_proposals = sha256/g"),
            RELOAD_COMMAND,
        ],
    },
    "RFC8221-AH-LEGACY": {
        "change": "AH integrity off legacy 96-bit",
        "commands": ["set AH integrity to sha256 or sha512", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "AH uses truncated 96-bit MAC with legacy SHA-1 or MD5.",
        "cryptographic_risk": "96-bit truncation reduces forgery resistance below modern 128-bit cryptographic requirements.",
        "proposed_strategy": "Upgrade ah_proposals to standard SHA-256 (128-bit truncated) or SHA-512.",
        "config_diff": "- ah_proposals = sha1\n+ ah_proposals = sha256",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(r"s/ah_proposals[[:space:]]*=[[:space:]]*.*(sha1|md5).*/ah_proposals = sha256/g"),
            RELOAD_COMMAND,
        ],
    },
    "RFC8221-ESP-3DES": {
        "change": "ESP cipher off 3DES",
        "commands": ["set `esp_proposals` to aes256gcm16", "swanctl --load-all"],
        "auto_applicable": True,
        "problem_analysis": "ESP payload encrypted with legacy Triple-DES (3DES-CBC).",
        "cryptographic_risk": "Sweet32 attack (CVE-2016-2183): 64-bit block cipher collision attacks recover plaintext after ~32GB of data.",
        "proposed_strategy": "Upgrade esp_proposals to modern 128-bit block AEAD cipher aes256gcm16.",
        "config_diff": "- esp_proposals = 3des-sha1\n+ esp_proposals = aes256gcm16",
        "rollback_strategy": _ROLLBACK_TEXT,
        "is_software_patch": False,
        "runbook": [],
        "exec_commands": [
            _in_connection(r"s/esp_proposals[[:space:]]*=[[:space:]]*.*3des.*/esp_proposals = aes256gcm16/g"),
            RELOAD_COMMAND,
        ],
    },
    "RFC4303-SEQ": {
        "change": "Not a config fix",
        "commands": ["replay is a symptom (misconfigured anti-replay window, or an attack) -- investigate, no command"],
        "auto_applicable": False,
        "problem_analysis": "Anti-replay window sequence number anomaly or sequence space exhaustion.",
        "cryptographic_risk": "Possible packet injection, replay attack, or severe out-of-order network routing.",
        "proposed_strategy": "Diagnostic symptom investigation. Inspect gateway counters and routing infrastructure.",
        "config_diff": "# Diagnostic investigation required: anti-replay window and sequence numbers\n# No configuration file modification",
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
        res["config_diff"] = entry.get("config_diff", "")
        res["rollback_strategy"] = entry.get("rollback_strategy", "")
        res["is_software_patch"] = entry.get("is_software_patch", False)
        res["runbook"] = list(entry.get("runbook", []))
        # config_diff is a hand-written illustration, not read from any configuration. The real
        # change is shown by the preview (a dry run on the chosen container) before applying.
        res["config_diff_is_example"] = True
        res["scope"] = (f"Only the {LAB_CONNECTION} connection is changed, on the chosen lab container and on the "
                        "other end of the lab tunnel, because that is the tunnel captured and verified.")
        res["automated_fix_available"] = bool(entry.get("auto_applicable")) and bool(entry.get("exec_commands"))
    if include_exec:
        res["exec_commands"] = list(entry.get("exec_commands", []))
    return res

