"""EXP-50 RouterOS device check (PREREG addendum B). One CHR VM must be up with its REST port on 127.0.0.1:8081 (see the commands in RESULT.md).

    python3 experiments/exp50-vendor-fixes/chr_check.py [label]

For each MikroTik template: create the weak state through REST, run the template's command text UNCHANGED through /rest/execute, read the setting back
through REST, run the template's verify command. Writes results/summary-mikrotik.json.
"""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
from tunnelscope.remediate.vendors import TEMPLATES  # noqa: E402

BASE = "http://127.0.0.1:8081/rest/"
AUTH = "Basic " + base64.b64encode(b"admin:").decode()
NAMES = {"<profile>": "p50", "<peer>": "peer50", "<proposal>": "pr50"}
# rule -> (weak state: (REST path, field, value))
WEAK = {"V-207205": ("ip/ipsec/peer", "exchange-mode", "main"), "V-207193": ("ip/ipsec/profile", "dh-group", "modp2048"),
        "V-207223": ("ip/ipsec/profile", "hash-algorithm", "sha256"), "RFC8247-DH-MUST": ("ip/ipsec/profile", "dh-group", "modp1024"),
        "RFC8247-DH-OFFER": ("ip/ipsec/profile", "dh-group", "modp1024,modp2048"), "RFC8247-ENCR": ("ip/ipsec/profile", "enc-algorithm", "3des"),
        "RFC4301-CONFIDENTIALITY": ("ip/ipsec/policy", "ipsec-protocols", "ah"), "RFC8221-AH-INTEG": ("ip/ipsec/proposal", "auth-algorithms", "md5"),
        "RFC8221-AH-LEGACY": ("ip/ipsec/proposal", "auth-algorithms", "sha1"), "RFC8221-ESP-3DES": ("ip/ipsec/proposal", "enc-algorithms", "3des")}


def ros(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            return True, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return False, {"http": e.code, "body": e.read().decode(errors="replace")[:300]}


def ex(cmd):
    return ros("POST", "execute", {"script": cmd})


def reset():
    for path in ("ip/ipsec/policy", "ip/ipsec/identity", "ip/ipsec/peer", "ip/ipsec/proposal", "ip/ipsec/profile"):
        ok, items = ros("GET", path)
        for it in (items or []) if ok else []:
            if it.get("default") != "true" and it.get("dynamic") != "true":
                ros("DELETE", f"{path}/{it['.id']}")
    for path, body in (("ip/ipsec/profile", {"name": "p50"}), ("ip/ipsec/proposal", {"name": "pr50"}),
                       ("ip/ipsec/peer", {"name": "peer50", "address": "10.99.0.2/32", "profile": "p50"}),
                       ("ip/ipsec/policy", {"src-address": "10.1.1.0/24", "dst-address": "10.2.2.0/24", "tunnel": "yes", "peer": "peer50", "proposal": "pr50"})):
        ok, r = ros("PUT", path, body)
        assert ok, (path, r)


def item(path, field):
    ok, items = ros("GET", path)
    name = {"ip/ipsec/profile": "p50", "ip/ipsec/proposal": "pr50", "ip/ipsec/peer": "peer50"}.get(path)
    for it in items:
        if name is None or it.get("name") == name:
            return it, it.get(field)
    return None, None


def norm(v):
    return ",".join(sorted(str(v).split(","))) if v is not None else None


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "mikrotik"
    out = {"version": ros("GET", "system/resource")[1]["version"], "rules": {}, "probes": {}}
    for rule, t in TEMPLATES["mikrotik"].items():
        reset()
        path, field, weak = WEAK[rule]
        ident = {"ip/ipsec/profile": "p50", "ip/ipsec/proposal": "pr50", "ip/ipsec/peer": "peer50"}.get(path)
        it, _ = item(path, field)
        ok_w, r_w = ros("PATCH", f"{path}/{it['.id']}", {field: weak})
        _, weak_read = item(path, field)
        runs, errors = [], []
        for cmd in t["commands"]:
            for k, v in NAMES.items():
                cmd = cmd.replace(k, v)
            ok, r = ex(cmd)
            runs.append({"cmd": cmd, "ok": ok, "ret": r})
            if not ok:
                errors.append(r)
        _, after = item(path, field)
        want = t["edits"][0]["set"][field]
        verify = t["verify"]
        for k, v in NAMES.items():
            verify = verify.replace(k, v)
        ok_v, rv = ex(verify.split("; ")[0])
        row = {"weak_set": ok_w, "weak_read": weak_read, "commands": runs, "after_read": after, "expected": want, "verify_cmd": verify.split("; ")[0],
               "verify_ok": ok_v, "verify_shows_value": ok_v and want in json.dumps(rv),
               "pass": bool(ok_w and norm(weak_read) == norm(weak) and not errors and norm(after) == norm(want) and norm(after) != norm(weak_read)
                            and ok_v and want in json.dumps(rv))}
        out["rules"][rule] = row
        print(f"{rule:26} weak={weak_read!s:22} after={after!s:14} expected={want!s:14} errors={len(errors)} verify={row['verify_shows_value']} PASS={row['pass']}")
    # probes: the documentation says no sha384; PQ names
    reset()
    it, _ = item("ip/ipsec/profile", "hash-algorithm")
    for v in ("sha384",):
        ok, r = ros("PATCH", f"ip/ipsec/profile/{it['.id']}", {"hash-algorithm": v})
        out["probes"][f"profile hash-algorithm={v}"] = {"accepted": ok, "read_back": item("ip/ipsec/profile", "hash-algorithm")[1], "reply": r if not ok else None}
    ok, r = ex("/ip ipsec profile set [ find name=p50 ] hash-algorithm=sha384")
    out["probes"]["cli: /ip ipsec profile set hash-algorithm=sha384"] = {"accepted": ok, "reply": r if not ok else None}
    for val in ("mlkem768", "ml-kem-768", "kyber768"):
        for path, name, field in (("ip/ipsec/profile", "p50", "dh-group"), ("ip/ipsec/proposal", "pr50", "pfs-group")):
            it, _ = item(path, field)
            ok, r = ros("PATCH", f"{path}/{it['.id']}", {field: val})
            out["probes"][f"{field}={val}"] = {"accepted": ok, "reply": (r if not ok else None)}
    json.dump(out, open(os.path.join(HERE, "results", f"summary-{label}.json"), "w"), indent=1, sort_keys=True)
    print("pass:", sum(1 for r in out["rules"].values() if r["pass"]), "of", len(out["rules"]))


if __name__ == "__main__":
    main()
