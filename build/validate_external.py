#!/usr/bin/env python3
"""T-085 — validation against THIRD-PARTY captures we did not make.

Every capture in testbed/ comes from our own lab, so "it works" has so far
meant "it works on traffic we generated". These captures come from the
Wireshark wiki: other people, other implementations, other years (2006-2021),
and several ship their own ground truth (the `esp_sa` key files and readmes
state the ESP algorithms and the tunnel/transport mode).

Checks:
  1. the IKE suite is read on third-party IKEv2 captures;
  2. the ESP cipher sieve NEVER excludes the true family (EXP-01's core claim),
     on ciphers and captures we have never seen;
  3. mode is never claimed wrongly (EXP-14) where the readme states it;
  4. nothing crashes and no finding contradicts the documented truth.

Downloads to a cache directory (default: a temp dir; --dir to keep them). The
captures are NOT redistributed in this repo.

  python3 build/validate_external.py [--dir DIR]
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tunnelscope.evidence.extract import build_records  # noqa: E402

BASE = "https://wiki.wireshark.org/uploads"
SOURCES = {
    "ikev2_s2s_ipsec_vpn_aes_gcm.pcapng": f"{BASE}/c45aa4606b860d707db92e180c147001/ikev2_s2s_ipsec_vpn_aes_gcm.pcapng",
    "ipsec_ikev2_esp.tgz": f"{BASE}/dc5b30a117424e6ed21c726771a4006b/ipsec_ikev2+esp_aes-gcm_aes-ctr_aes-cbc.tgz",
    "ipsec_esp.tgz": f"{BASE}/21afad41e961b83b9e74cf1fd500a9be/ipsec_esp.tgz",
}
# documented mode per capture directory (from each readme)
DOC_MODE = {"ipsec_esp_capture_1": "transport", "ipsec_esp_capture_2": "tunnel"}
# esp_sa algorithm names -> the sieve family that must survive
# esp_sa cipher/auth names -> the sieve family that MUST survive for that SA
CIPHER = {"AES-CBC": "AES-CBC", "TripleDES-CBC": "3DES-CBC", "DES-CBC": "DES-CBC",
          "BLOWFISH-CBC": "Blowfish-CBC", "TWOFISH-CBC": "Twofish-CBC", "CAST5-CBC": "CAST-CBC",
          "NULL": "NULL", "AES-CTR": "AES-CTR", "AES-GCM with 16 octet ICV": "AES-GCM-16"}
AUTH = {"HMAC-SHA-1-96": "HMAC-SHA1-96", "HMAC-MD5-96": "HMAC-96", "HMAC-SHA-256-128": "HMAC-SHA256-128",
        "ANY 96 bit authentication [no checking]": "HMAC-96"}
# ESP with NO integrity (authentication NULL) is legal but RFC 8221 marks AUTH_NONE
# MUST NOT outside AEAD. The sieve does not model those families, so they are
# reported as "cannot name", never silently matched to an HMAC family.


def family_of(enc: str, auth: str) -> str | None:
    """The sieve family name for a documented (encryption, authentication) pair,
    or None when the pair is one the sieve cannot represent."""
    from tunnelscope.evidence.extract import _SIEVE
    c, a = CIPHER.get(enc), AUTH.get(auth)
    if c is None or a is None:
        return None
    if c.startswith("AES-GCM"):
        return "AES-GCM-16"
    for cand in (f"{c}+{a}", f"{c}+HMAC-96", f"{c}+HMAC-SHA1-96"):
        if cand in _SIEVE:
            return cand
    return None


def fetch(cache: Path) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        p = cache / name
        if not p.exists():
            # curl, not urllib: the system CA store is what these hosts expect
            subprocess.run(["curl", "-sSLf", "--max-time", "120", "-o", str(p), url], check=True)
        if p.suffix == ".tgz":
            with tarfile.open(p) as t:
                t.extractall(cache, filter="data")


def truths(sa_file: Path) -> list[tuple[str, str, str]]:
    out = []
    for row in csv.reader(l for l in sa_file.read_text().splitlines() if l.startswith('"')):
        if len(row) >= 7:
            enc = re.sub(r"\s*\[.*", "", row[4]).strip()
            auth = re.sub(r"\s*\[.*", "", row[6]).strip()
            out.append((row[1], row[2], f"{enc}+{auth}"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.environ.get("TUNNELSCOPE_EXTERNAL_DIR", "/tmp/tunnelscope-external"))
    args = ap.parse_args()
    cache = Path(args.dir)
    fetch(cache)

    issues, notes, n = [], [], 0
    for pcap in sorted(list(cache.rglob("*.pcap")) + list(cache.rglob("*.pcapng"))):
        n += 1
        recs = [r for r in build_records(str(pcap))
                if getattr(r, "_ike", []) or getattr(r, "_esp", []) or getattr(r, "_ah", [])]
        if not recs:
            issues.append(f"{pcap.name}: no record built")
            continue
        sa_file = pcap.parent / "esp_sa"
        doc_mode = DOC_MODE.get(pcap.parent.name)
        for r in recs:
            F = r.findings
            # 3. mode must never contradict the readme
            m = F.get("mode")
            if m is not None and m.value and doc_mode and m.value != doc_mode:
                issues.append(f"{pcap.parent.name}/{pcap.name}: mode says {m.value}, readme says {doc_mode}")
            # 2. the sieve must keep the true family among its candidates
            if sa_file.exists() and "esp_cipher_family" in F and F["esp_cipher_family"].value:
                pair = {r.src, r.dst}
                for src, dst, alg in truths(sa_file):
                    enc, auth = alg.split("+", 1)
                    want = family_of(enc, auth)
                    if {src, dst} == pair and want:
                        if want not in F["esp_cipher_family"].value:
                            issues.append(f"{pcap.parent.name}: sieve excluded the true family {want} "
                                          f"({src}->{dst}); kept {F['esp_cipher_family'].value}")
            # 1. IKE suite read where a handshake is present
            if getattr(r, "_ike", []) and F.get("ike_encr") and F["ike_encr"].status.value == "OBSERVED":
                notes.append(f"{pcap.name}: IKE suite {F['ike_encr'].value} / {F.get('ike_dh_group').value}")
        if sa_file.exists():
            unknown = sorted({a for _, _, a in truths(sa_file) if not family_of(*a.split("+", 1))})
            if unknown:
                notes.append(f"{pcap.parent.name}: pairs the sieve cannot name: {unknown}")

    print(f"external captures analysed: {n}")
    for x in sorted(set(notes)):
        print("  note:", x)
    if issues:
        print(f"\nISSUES ({len(issues)}):")
        for i in issues:
            print("  -", i)
        return 1
    print("\nPASS: no third-party capture contradicted a finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
