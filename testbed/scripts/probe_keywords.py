#!/usr/bin/env python3
"""Build tunnelscope/remediate/strongswan_keywords.json from the lab itself (T-100).

Nothing in the output is typed by hand:
  * candidate keywords come from the strings compiled into the lab image's libstrongswan, the
    EXP-15 arm configs (testbed/configs/exp15/arms.json) and the hand-written fixes in
    tunnelscope/remediate/plan.py;
  * whether a keyword is accepted, and what kind of algorithm it is, comes from strongSwan: each
    candidate is added to a known-good proposal and loaded in a throwaway, network-less clone of
    the lab image; `swanctl --list-conns --raw` then reports the transform types and names it
    added (e.g. ke=[MODP_3072]);
  * what TunnelScope reports on the wire for a strongSwan algorithm comes from running TunnelScope
    on the EXP-15 captures, whose configs are known exactly (arms.json) and whose negotiated
    algorithms the daemon itself recorded (*.groundtruth.json).

Both lab images (alice-pq, bob-pq) are probed; the file is written only if they agree.

Usage: .venv/bin/python testbed/scripts/probe_keywords.py   (Docker running; lab images built)
"""
from __future__ import annotations

import datetime as dt
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

OUT = ROOT / "tunnelscope" / "remediate" / "strongswan_keywords.json"
IMAGES = ["testbed-alice-pq", "testbed-bob-pq"]
KEYWORD_SHAPE = re.compile(
    r"(modp|ecp|curve|mlkem|x25519|x448|aes|sha|md5|3des|des|blowfish|cast|camellia|chacha|prf|"
    r"esn|noesn|null|twofish|serpent)[a-z0-9_]*")

# Known-good bases per context. Two of each, so a candidate that is already part of one base
# still shows up as an addition on the other.
BASES = {
    "ike": ["aes128-sha1-modp1024", "camellia256-sha512-ecp521"],
    "ike_aead": ["aes128gcm16-prfsha1-modp1024", "chacha20poly1305-prfsha512-ecp521"],
    "esp": ["aes128-sha1", "camellia256-sha512"],
    "esp_aead": ["aes128gcm16", "chacha20poly1305"],
    "ah": ["sha1", "sha512"],
}
LINE = {"ike": "proposals", "ike_aead": "proposals", "esp": "esp_proposals",
        "esp_aead": "esp_proposals", "ah": "ah_proposals"}


def conf(line_key: str, value: str) -> str:
    child_line = f"                {line_key} = {value}\n" if line_key != "proposals" else ""
    ike_line = f"        proposals = {value}\n" if line_key == "proposals" else ""
    return ("connections {\n    p {\n        version = 2\n        remote_addrs = 192.0.2.1\n"
            + ike_line +
            "        local {\n            auth = psk\n        }\n        remote {\n            auth = psk\n        }\n"
            "        children {\n            p {\n" + child_line + "            }\n        }\n    }\n}\n")


PROBE_SCRIPT = (
    "mkdir -p /probe /var/run/charon && tar -x -C /probe || { echo TS_ERR tar; exit 0; }; "
    "C=/usr/libexec/ipsec/charon; [ -x $C ] || C=/usr/lib/ipsec/charon; $C >/tmp/charon.log 2>&1 & "
    "i=0; until swanctl --stats >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 100 ] && { echo TS_ERR charon; exit 0; }; sleep 0.1; done; "
    "for f in $(ls /probe/c | sort -n); do echo \"TS_FILE $f\"; swanctl --load-conns --file /probe/c/$f 2>&1; "
    "echo TS_RAW; swanctl --list-conns --raw 2>&1; swanctl --load-conns --file /probe/empty.conf >/dev/null 2>&1; done; "
    "echo TS_DONE"
)


def image_strings(image: str) -> set[str]:
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c",
                        "strings /usr/lib/ipsec/libstrongswan.so.0"], capture_output=True, text=True, timeout=120)
    return {s for s in r.stdout.split() if KEYWORD_SHAPE.fullmatch(s)}


def seed_tokens() -> set[str]:
    toks: set[str] = set()
    for arm in json.loads((ROOT / "testbed/configs/exp15/arms.json").read_text()).values():
        for field in ("ike", "child"):
            toks.update(re.split(r"[-,\s]+", arm[field]))
    from tunnelscope.remediate.plan import REMEDIATION
    for entry in REMEDIATION.values():
        for cmd in entry.get("exec_commands", []):
            toks.update(re.findall(r"[a-z0-9_]+", cmd))   # anything that is not a keyword is rejected below
    return {t for t in toks if KEYWORD_SHAPE.fullmatch(t)}


def run_probe(image: str, files: list[tuple[str, str]]) -> dict[int, tuple[str, str]]:
    """Load every (line_key, value) in one clone. Returns {index: (load output, raw list-conns)}."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name: str, text: str) -> None:
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        add("empty.conf", "connections {\n}\n")
        for i, (key, value) in enumerate(files):
            add(f"c/{i}", conf(key, value))
    r = subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "--cap-add", "NET_ADMIN",
                        "--label", "tunnelscope.clone=1", "--entrypoint", "sh", image, "-c", PROBE_SCRIPT],
                       input=buf.getvalue(), capture_output=True, timeout=1800)
    out = r.stdout.decode(errors="replace")
    if "TS_DONE" not in out:
        raise SystemExit(f"probe did not finish on {image}: {out[-500:]} {r.stderr.decode()[-500:]}")
    res: dict[int, tuple[str, str]] = {}
    for block in out.split("TS_FILE ")[1:]:
        head, _, rest = block.partition("\n")
        load, _, raw = rest.partition("TS_RAW\n")
        res[int(head.strip())] = (load, raw.replace("TS_DONE", ""))
    return res


RAW_PROPOSAL = re.compile(r"(\d+) \{([^{}]*)\}")
RAW_FIELD = re.compile(r"(\w+)=\[([^\]]*)\]")


def parse_raw(raw: str, section: str) -> list[dict[str, list[str]]]:
    m = re.search(section + r" \{((?:\d+ \{[^{}]*\}\s*)*)\}", raw)
    if not m:
        return []
    return [{k: v.split() for k, v in RAW_FIELD.findall(body)} for _, body in RAW_PROPOSAL.findall(m.group(1))]


def added(base: list[dict], new: list[dict]) -> dict[str, list[str]]:
    if not base or not new:
        return {}
    out = {}
    for k, names in new[0].items():
        extra = [n for n in names if n not in base[0].get(k, [])]
        if extra:
            out[k] = extra
    return out


def classify(image: str, candidates: list[str]) -> dict[str, dict]:
    jobs: list[tuple[str, str, str | None, str]] = []   # (context, base, token or None, line value)
    for ctx, bases in BASES.items():
        for b in bases:
            jobs.append((ctx, b, None, b))
            for t in candidates:
                jobs.append((ctx, b, t, f"{b}-{t}"))
    res = run_probe(image, [(LINE[c], v) for c, _, _, v in jobs])
    section = {"ike": "proposals", "ike_aead": "proposals", "esp": "esp_proposals",
               "esp_aead": "esp_proposals", "ah": "ah_proposals"}
    base_raw = {}
    for i, (ctx, b, t, _) in enumerate(jobs):
        if t is None:
            load, raw = res[i]
            if "successfully loaded 1 connections" not in load:
                raise SystemExit(f"{image}: base {b!r} ({ctx}) did not load: {load.strip()}")
            base_raw[(ctx, b)] = parse_raw(raw, section[ctx])
    kw: dict[str, dict] = {t: {"accepted": False, "contexts": {}} for t in candidates}
    for i, (ctx, b, t, _) in enumerate(jobs):
        if t is None:
            continue
        load, raw = res[i]
        if "successfully loaded 1 connections" not in load:
            continue
        add = added(base_raw[(ctx, b)], parse_raw(raw, section[ctx]))
        if not add:
            continue
        family = ctx.replace("_aead", "")
        prev = kw[t]["contexts"].get(family)
        kind = {"types": sorted(add), "names": {k: v for k, v in sorted(add.items())},
                "aead": ctx.endswith("_aead")}
        if prev is None or len(kind["types"]) > len(prev["types"]):
            kw[t]["contexts"][family] = kind
        kw[t]["accepted"] = True
    return kw


def evidence_map() -> dict:
    """strongSwan names -> what TunnelScope reports, from the EXP-15 captures (configs known)."""
    from tunnelscope.report.report import analyze
    arms = json.loads((ROOT / "testbed/configs/exp15/arms.json").read_text())
    ike: dict[str, dict] = {}
    lines: dict[str, dict] = {"esp_proposals": {}, "ah_proposals": {}, "version": {}}
    # each arm's `version` setting, read from the generated config the captures were taken with
    conf = (ROOT / "testbed/configs/exp15/alice.conf").read_text().splitlines()
    arm_version: dict[str, str] = {}
    current = None
    for line in conf:
        m = re.match(r"^    ([^\s{}#]+) \{\s*$", line)
        if m:
            current = m.group(1)
        v = re.match(r"^\s*version\s*=\s*(\S+)", line)
        if v and current and current not in arm_version:
            arm_version[current] = v.group(1)
    attr_of = {"encr": "ike_encr", "integ": "ike_integ", "prf": "ike_prf", "ke": "ike_dh_group"}
    for pcap in sorted((ROOT / "testbed/captures/exp15").glob("*.pcap")):
        arm = pcap.stem
        gt = json.loads(pcap.with_suffix(".groundtruth.json").read_text())
        sas = analyze(str(pcap))["sas"]
        if not sas or arm not in arms:
            continue
        f = sas[0]["record"].findings
        val = lambda k: f[k].value if k in f else None
        src = str(pcap.relative_to(ROOT))
        # the negotiated IKE algorithms, as the daemon printed them (list-sas line 4)
        algs = gt["alice_list_sas"].splitlines()[3].strip().split("/")
        for name in algs:
            norm = name.replace("-", "_")
            if norm.startswith("KE1_"):
                ike[norm] = {"attribute": "pq_key_exchange", "value": val("pq_key_exchange"), "source": src}
                continue
            kind = ("prf" if norm.startswith("PRF_") else "integ" if norm.startswith(("HMAC_", "AES_XCBC", "AES_CMAC"))
                    else "ke" if norm.startswith(("MODP_", "ECP_", "CURVE_", "ML_KEM")) else "encr")
            v = val(attr_of[kind])
            if v is None:
                continue
            old = ike.get(norm)
            if old and old["value"] != v:
                raise SystemExit(f"captures disagree on {norm}: {old['value']} vs {v}")
            ike[norm] = {"attribute": attr_of[kind], "value": v, "source": src}
        if arm in arm_version and val("ike_version") is not None:
            lines["version"].setdefault(arm_version[arm], []).append(
                {"attribute": "ike_version", "value": val("ike_version"), "source": src})
        proto, child = arms[arm]["proto"], arms[arm]["child"]
        key = "esp_proposals" if proto == "esp" else "ah_proposals"
        attr = "esp_cipher_family" if proto == "esp" else "ah_integrity"
        v = val(attr)
        if v is not None:
            lines[key].setdefault(child, []).append({"attribute": attr, "value": v, "source": src})
    return {"ike": dict(sorted(ike.items())), **lines}


def main() -> None:
    cands = set(seed_tokens())
    for img in IMAGES:
        cands |= image_strings(img)
    cands = sorted(cands)
    results = {}
    for img in IMAGES:
        kw = classify(img, cands)
        # second pass: additional key exchanges (ke1_..ke2_) of every accepted key-exchange keyword
        ke = [t for t, v in kw.items() if v["accepted"] and v["contexts"].get("ike", {}).get("types") == ["ke"]]
        kw.update(classify(img, [f"ke{n}_{t}" for n in (1, 2) for t in ke]))
        results[img] = kw
    a, b = (results[i] for i in IMAGES)
    if a != b:
        diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
        raise SystemExit(f"the two lab images disagree on {len(diff)} keywords, e.g. {diff[:10]}")
    ids = {}
    for img in IMAGES:
        ids[img] = subprocess.run(["docker", "image", "inspect", img, "--format", "{{.Id}}"],
                                  capture_output=True, text=True).stdout.strip()
    vr = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "swanctl", IMAGES[0],
                         "--version"], capture_output=True, text=True)
    m = re.search(r"strongSwan (\d+\.\d+\.\d+)", vr.stdout + vr.stderr)   # printed with the usage text
    if not m:
        raise SystemExit(f"could not read the strongSwan version: {(vr.stdout + vr.stderr)[:200]!r}")
    ver = f"strongSwan {m.group(1)}"
    doc = {
        "generated_by": "testbed/scripts/probe_keywords.py",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "strongswan_version": ver,
        "images": ids,
        "candidate_sources": ["strings in /usr/lib/ipsec/libstrongswan.so.0 of the lab images",
                              "testbed/configs/exp15/arms.json", "hand-written exec_commands in plan.py",
                              "ke1_/ke2_ prefixes of accepted key-exchange keywords"],
        "keywords": {k: a[k] for k in sorted(a) if a[k]["accepted"]},
        "rejected": sorted(k for k in a if not a[k]["accepted"]),
        "evidence": evidence_map(),
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=False) + "\n")
    print(f"candidates {len(cands)}, accepted {len(doc['keywords'])}, rejected {len(doc['rejected'])}")
    print(f"evidence: ike {len(doc['evidence']['ike'])} names, esp {len(doc['evidence']['esp_proposals'])} values, "
          f"ah {len(doc['evidence']['ah_proposals'])} values, version {sorted(doc['evidence']['version'])}")
    print(f"images: {ids}")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
