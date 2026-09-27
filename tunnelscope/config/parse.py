"""T-120: parse IPsec configuration files into one normalised crypto model.

Formats: strongSwan `swanctl.conf` and `ipsec.conf` (Libreswan / strongSwan stroke style). Algorithm names are
the same IANA-derived names TunnelScope's wire findings use (`AES-CBC-256`, `AES-GCM-16-256`,
`HMAC-SHA2-256-128`, `PRF-HMAC-SHA2-256`, `MODP-2048`, `ML-KEM-768` ...), so a configuration can be compared
with what a capture shows (roadmap T-121).

Rule of this module, as everywhere in TunnelScope: syntax it does not understand is reported in `unknown`,
never guessed. A proposal with an unknown token is kept, with the token listed.
"""
from __future__ import annotations

import re
from pathlib import Path

KE = {"modp768": "MODP-768", "modp1024": "MODP-1024", "modp1536": "MODP-1536", "modp2048": "MODP-2048",
      "modp3072": "MODP-3072", "modp4096": "MODP-4096", "modp6144": "MODP-6144", "modp8192": "MODP-8192",
      "modp1024s160": "MODP-1024-S160", "modp2048s224": "MODP-2048-S224", "modp2048s256": "MODP-2048-S256",
      "ecp256": "ECP-256", "ecp384": "ECP-384", "ecp521": "ECP-521",
      "curve25519": "Curve25519", "x25519": "Curve25519", "curve448": "Curve448", "x448": "Curve448",
      "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
      "ml_kem_512": "ML-KEM-512", "ml_kem_768": "ML-KEM-768", "ml_kem_1024": "ML-KEM-1024",
      # Libreswan spellings
      "dh2": "MODP-1024", "dh5": "MODP-1536", "dh14": "MODP-2048", "dh15": "MODP-3072", "dh16": "MODP-4096",
      "dh19": "ECP-256", "dh20": "ECP-384", "dh21": "ECP-521", "dh31": "Curve25519"}
INTEG = {"md5": "HMAC-MD5-96", "sha1": "HMAC-SHA1-96", "sha": "HMAC-SHA1-96",
         "sha256": "HMAC-SHA2-256-128", "sha2_256": "HMAC-SHA2-256-128", "sha2": "HMAC-SHA2-256-128",
         "sha384": "HMAC-SHA2-384-192", "sha2_384": "HMAC-SHA2-384-192",
         "sha512": "HMAC-SHA2-512-256", "sha2_512": "HMAC-SHA2-512-256", "aesxcbc": "AES-XCBC-96"}
PRF = {"prfmd5": "PRF-HMAC-MD5", "prfsha1": "PRF-HMAC-SHA1", "prfsha256": "PRF-HMAC-SHA2-256",
       "prfsha384": "PRF-HMAC-SHA2-384", "prfsha512": "PRF-HMAC-SHA2-512"}
# strongSwan: "if no PRF is configured, the algorithms defined for integrity are proposed as PRF"
PRF_FROM_INTEG = {"HMAC-MD5-96": "PRF-HMAC-MD5", "HMAC-SHA1-96": "PRF-HMAC-SHA1",
                  "HMAC-SHA2-256-128": "PRF-HMAC-SHA2-256", "HMAC-SHA2-384-192": "PRF-HMAC-SHA2-384",
                  "HMAC-SHA2-512-256": "PRF-HMAC-SHA2-512"}
IGNORED = {"esn", "noesn"}


def _encr(tok: str) -> str | None:
    """strongSwan (aes256, aes256gcm16, aes128ctr) and Libreswan (aes_gcm256, aes_ctr128) cipher tokens."""
    if tok in ("3des", "des", "null", "chacha20poly1305", "chacha20_poly1305"):
        return {"3des": "3DES", "des": "DES", "null": "NULL"}.get(tok, "ChaCha20-Poly1305")
    m = re.fullmatch(r"aes(128|192|256)(gcm|ccm)(8|12|16|64|96|128)?", tok)       # strongSwan AEAD
    if m:
        icv = {"64": "8", "96": "12", "128": "16"}.get(m.group(3), m.group(3) or "16")
        return f"AES-{m.group(2).upper()}-{icv}-{m.group(1)}"
    m = re.fullmatch(r"aes_(gcm|ccm)(?:_([abc]|8|12|16))?(128|192|256)?", tok)     # Libreswan AEAD
    if m:
        icv = {"a": "8", "b": "12", "c": "16"}.get(m.group(2), m.group(2) or "16")
        return f"AES-{m.group(1).upper()}-{icv}-{m.group(3) or '128'}"
    m = re.fullmatch(r"aes(?:_?(ctr))?(128|192|256)?", tok) or re.fullmatch(r"aes(128|192|256)(ctr)", tok)
    if m:
        g = m.groups()
        mode = "CTR" if "ctr" in g else "CBC"
        size = next((x for x in g if x and x.isdigit()), "128")
        return f"AES-{mode}-{size}"
    return None


def parse_proposal(text: str, kind: str) -> dict:
    """One proposal string. kind 'ike' | 'esp' | 'ah'. Returns lists (a proposal may name several of each)."""
    p: dict = {"encr": [], "integ": [], "prf": [], "ke": [], "addke": {}, "unknown": [], "text": text}
    for tok in re.split(r"[-;+]", text.strip().lower()):
        if not tok or tok in IGNORED:
            continue
        m = re.fullmatch(r"(?:ke([1-7])_|addke([1-7])=)(\w+)", tok)   # strongSwan ke1_x, Libreswan addke1=x
        if m and m.group(3) in KE:
            p["addke"].setdefault(int(m.group(1) or m.group(2)), []).append(KE[m.group(3)])
        elif tok in KE:
            p["ke"].append(KE[tok])
        elif tok in PRF:
            p["prf"].append(PRF[tok])
        elif tok in INTEG:
            p["integ"].append(INTEG[tok])
        elif kind != "ah" and _encr(tok):
            p["encr"].append(_encr(tok))
        else:
            p["unknown"].append(tok)
    if kind == "ike" and not p["prf"] and p["integ"]:
        p["prf"] = [PRF_FROM_INTEG[i] for i in p["integ"] if i in PRF_FROM_INTEG]
        p["prf_implied_by_integ"] = True
    return p


def parse_proposals(value: str, kind: str) -> list[dict]:
    return [parse_proposal(v, kind) for v in value.split(",") if v.strip() and v.strip() != "default"]


# ---------------------------------------------------------------- swanctl.conf
def _swanctl_tree(text: str) -> dict:
    # braces may share a line with settings (`local { auth = psk` ... `id = x }`): put each on its own line
    text = "\n".join(re.sub(r"\{", "{\n", re.sub(r"\}", "\n}\n", ln.split("#", 1)[0])) for ln in text.splitlines())
    root: dict = {}
    stack = [root]
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.endswith("{"):
            node: dict = {}
            stack[-1][line[:-1].strip()] = node
            stack.append(node)
        elif line == "}":
            if len(stack) > 1:
                stack.pop()
        elif "=" in line:
            k, v = line.split("=", 1)
            stack[-1][k.strip()] = v.strip().strip('"')
        else:
            stack[-1].setdefault("_unparsed", []).append(line)
    return root


CONN_KEYS = {"local_addrs", "remote_addrs", "version", "proposals", "ppk_id", "ppk_required", "local", "remote",
             "children", "rekey_time", "reauth_time", "over_time", "rand_time", "dpd_delay", "dpd_timeout",
             "encap", "mobike", "fragmentation", "send_certreq", "send_cert", "keyingtries", "unique", "if_id_in",
             "if_id_out", "pools", "aggressive", "pull", "local_port", "remote_port"}
CHILD_KEYS = {"local_ts", "remote_ts", "mode", "esp_proposals", "ah_proposals", "rekey_time", "life_time",
              "rand_time", "rekey_bytes", "life_bytes", "rekey_packets", "life_packets", "start_action",
              "dpd_action", "close_action", "tfc_padding", "replay_window", "policies", "updown", "ipcomp",
              "if_id_in", "if_id_out", "mark_in", "mark_out", "hw_offload", "copy_df", "copy_ecn", "copy_dscp",
              "sha256_96", "inactivity", "reqid", "priority", "interface", "iptfs_fragmentation", "iptfs_max_queue",
              "iptfs_drop_time", "iptfs_reorder_window", "iptfs_init_delay", "iptfs_packet_size", "iptfs_dont_frag"}


def _swanctl(text: str, source: str) -> list[dict]:
    tree = _swanctl_tree(text)
    out = []
    for name, c in (tree.get("connections") or {}).items():
        if not isinstance(c, dict):
            continue
        unknown = [f"{k} = {v}" for k, v in c.items() if k not in CONN_KEYS and not isinstance(v, dict)]
        unknown += c.get("_unparsed", [])
        version = {"1": "IKEv1", "2": "IKEv2"}.get(c.get("version", "0"))
        children = []
        for cname, ch in (c.get("children") or {}).items():
            if not isinstance(ch, dict):
                continue
            unknown += [f"children.{cname}.{k} = {v}" for k, v in ch.items()
                        if k not in CHILD_KEYS and not isinstance(v, dict)]
            esp = parse_proposals(ch["esp_proposals"], "esp") if "esp_proposals" in ch else []
            ah = parse_proposals(ch["ah_proposals"], "ah") if "ah_proposals" in ch else []
            children.append({"name": cname, "mode": ch.get("mode", "tunnel"), "esp_proposals": esp, "ah_proposals": ah,
                             "pfs": (any(p["ke"] for p in esp + ah) if (esp or ah) else None),
                             "rekey_time": ch.get("rekey_time"), "life_time": ch.get("life_time"),
                             "local_ts": ch.get("local_ts"), "remote_ts": ch.get("remote_ts"),
                             "defaults_used": [x for x in ("esp_proposals",) if x not in ch and "ah_proposals" not in ch]})
        auth = {side: (c.get(side) or {}).get("auth") for side in ("local", "remote")}
        out.append({"source": source, "format": "strongswan-swanctl", "name": name, "ike_version": version,
                    "local_addrs": c.get("local_addrs"), "remote_addrs": c.get("remote_addrs"),
                    "ike_proposals": parse_proposals(c["proposals"], "ike") if "proposals" in c else [],
                    "ike_proposals_default": "proposals" not in c,
                    "auth": auth, "children": children,
                    "ppk": ({"id": c["ppk_id"], "required": c.get("ppk_required", "no") == "yes"}
                            if "ppk_id" in c else None),
                    "unknown": unknown})
    return out


# ------------------------------------------------------------------ ipsec.conf
IPSEC_KEYS = {"left", "right", "leftid", "rightid", "leftsubnet", "rightsubnet", "authby", "keyexchange", "ike",
              "esp", "ah", "phase2", "phase2alg", "pfs", "type", "ikelifetime", "ipsec-lifetime", "salifetime",
              "lifetime", "keylife", "rekey", "auto", "also", "leftcert", "rightcert", "leftauth", "rightauth",
              "ikev2", "fragmentation", "dpddelay", "dpdtimeout", "dpdaction", "leftsourceip", "rightsourceip",
              "mobike", "rekeymargin", "keyingtries", "ikelifetime", "margintime", "leftprotoport", "rightprotoport",
              "intermediate"}


def _ipsec_conf(text: str, source: str) -> list[dict]:
    conns, cur = [], None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line[0].isspace():
            cur = None
            m = re.match(r"conn\s+(\S+)", line)
            if m and m.group(1) != "%default":
                cur = {"_name": m.group(1)}
                conns.append(cur)
            continue
        if cur is not None and "=" in line:
            k, v = line.strip().split("=", 1)
            cur[k.strip()] = v.strip().strip('"')
    out = []
    for c in conns:
        kx = c.get("keyexchange", c.get("ikev2", ""))
        version = ("IKEv2" if kx in ("ikev2", "insist", "yes", "propose", "permit") else
                   "IKEv1" if kx in ("ikev1", "no", "never") else None)
        esp_key = next((k for k in ("esp", "phase2alg") if k in c), None)
        esp = parse_proposals(c[esp_key], "esp") if esp_key else []
        ah = parse_proposals(c["ah"], "ah") if "ah" in c else []
        pfs = {"yes": True, "no": False}.get(c.get("pfs", ""), None)
        if pfs is None and esp:
            pfs = any(p["ke"] for p in esp) or None
        mode = {"tunnel": "tunnel", "transport": "transport"}.get(c.get("type", "tunnel"), c.get("type"))
        out.append({"source": source, "format": "ipsec.conf", "name": c["_name"], "ike_version": version,
                    "local_addrs": c.get("left"), "remote_addrs": c.get("right"),
                    "ike_proposals": parse_proposals(c["ike"], "ike") if "ike" in c else [],
                    "ike_proposals_default": "ike" not in c,
                    "auth": {"local": c.get("authby", c.get("leftauth")), "remote": c.get("authby", c.get("rightauth"))},
                    "children": [{"name": c["_name"], "mode": mode, "esp_proposals": esp, "ah_proposals": ah, "pfs": pfs,
                                  "rekey_time": c.get("ipsec-lifetime", c.get("salifetime", c.get("lifetime"))),
                                  "life_time": None, "local_ts": c.get("leftsubnet"), "remote_ts": c.get("rightsubnet"),
                                  "defaults_used": [] if (esp_key or ah) else ["esp"]}],
                    "ppk": None,
                    "unknown": [f"{k} = {v}" for k, v in c.items() if k != "_name" and k not in IPSEC_KEYS]})
    return out


def parse_config(text: str, source: str = "<text>") -> dict:
    """-> {"format", "tunnels": [...], "unknown_format": bool}. The format is detected from the text."""
    if re.search(r"^\s*connections\s*\{", text, re.M):
        return {"source": source, "format": "strongswan-swanctl", "tunnels": _swanctl(text, source)}
    if re.search(r"^conn\s+\S+", text, re.M):
        return {"source": source, "format": "ipsec.conf", "tunnels": _ipsec_conf(text, source)}
    return {"source": source, "format": None, "tunnels": [],
            "unknown": ["not a recognised IPsec configuration format (swanctl.conf, ipsec.conf)"]}


def parse_file(path: str | Path) -> dict:
    return parse_config(Path(path).read_text(errors="replace"), str(path))
