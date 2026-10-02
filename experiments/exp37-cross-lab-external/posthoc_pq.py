"""EXP-37 Part B, POST-HOC re-score. NOT pre-registered: written after the v1 results were seen.

    .venv/bin/python experiments/exp37-cross-lab-external/posthoc_pq.py --pq DIR/pq_thesis --work DIR/trimmed

Why this exists (also in RESULT.md): the v1 scorer kept one record per capture, the one with the most ESP packets.
A control-plane capture has no ESP, so that rule picked an arbitrary record (often the old SA being torn down) and
reported UNKNOWN for a handshake that is plainly in the file. Here every record is kept and a capture is judged as a
whole: its IKE negotiation is whichever record carries the suite.
Second, 24 of the 26 hybrid files end in the middle of a packet (cut at a 4096-byte boundary) and the product refuses
them. This script also writes trimmed copies (whole packets only, nothing else changed) outside the repo and scores
those separately, so "the product rejects the file" and "the product reads the handshake" are not mixed up.
Writes results/posthoc/posthoc_pq.json.
"""
import argparse
import glob
import json
import os
import re
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CLI = os.path.join(REPO, ".venv", "bin", "tunnelscope")
ASSERTED = ("OBSERVED", "INFERRED", "MEASURED")


def trim(src, dst):
    """Copy only whole packet records of a classic pcap. Returns (packets_kept, was_cut)."""
    b = open(src, "rb").read()
    magic = b[:4]
    le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    if not le and magic not in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        return 0, None
    e = "<" if le else ">"
    pos, n = 24, 0
    while pos + 16 <= len(b):
        incl = struct.unpack(e + "I", b[pos + 8:pos + 12])[0]
        if pos + 16 + incl > len(b):
            break
        pos += 16 + incl
        n += 1
    cut = pos != len(b)
    open(dst, "wb").write(b[:pos])
    return n, cut


def run_all(path):
    p = subprocess.run([CLI, "analyze", "--json", path], capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        return {"error": (p.stderr or p.stdout)[-200:]}
    d = json.loads(p.stdout)
    return {"summary": d.get("summary"), "records": [r["findings"] for r in d.get("records", [])]}


def norm(s):
    return re.sub(r"[^A-Z0-9]", "", str(s).upper())


def judge(res, truth):
    """Capture-level verdict from all records."""
    if "error" in res:
        return {"read": False, "error": res["error"][:120]}
    recs = res["records"]
    def pick(attr):
        vals = [(r.get(attr) or {}) for r in recs]
        return [v for v in vals if v.get("status") in ASSERTED and v.get("value") not in (None, "", [], {})]
    pq, enc, dh = pick("pq_key_exchange"), pick("ike_encr"), pick("ike_dh_group")
    pq_vals = [str(v["value"]) for v in pq]
    out = {"read": True, "has_ike_sa_init": (res["summary"] or {}).get("has_ike_sa_init"), "n_records": len(recs),
           "pq_values": pq_vals, "ike_encr": [str(v["value"]) for v in enc], "ike_dh": [str(v["value"]) for v in dh]}
    out["says_mlkem768"] = any("768" in norm(v) and "KEM" in norm(v) for v in pq_vals)
    out["says_pq_present"] = any(re.search(r"KEM|KYBER|ADDKE", norm(v)) for v in pq_vals)
    out["suite_matches_swanctl"] = bool(enc and dh and all("GCM" in norm(v) and "256" in norm(v) for v in out["ike_encr"])
                                         and all(re.search(r"25519", norm(v)) for v in out["ike_dh"]))
    out["truth"] = truth
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pq", required=True)
    ap.add_argument("--work", required=True)
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    caps = sorted(glob.glob(os.path.join(a.pq, "**", "*_ike_control_plane.pcap"), recursive=True))
    jobs = []
    for p in caps:
        rel = os.path.relpath(p, a.pq)
        kind = "hybrid" if rel.startswith("Hybrid") else "classical"
        sw = p.replace("_ike_control_plane.pcap", "_swanctl_after_traffic.txt")
        truth = next((l.strip() for l in open(sw) if "AES_GCM_16-256/" in l), None) if os.path.exists(sw) else None
        t = os.path.join(a.work, rel.replace("/", "__"))
        n, cut = trim(p, t)
        jobs.append((rel, kind, truth, p, t, n, cut))
    def go(j):
        rel, kind, truth, p, t, n, cut = j
        orig = judge(run_all(p), truth)
        trimmed = judge(run_all(t), truth) if cut else None
        return {"rel": rel, "kind": kind, "packets_kept": n, "was_cut": cut, "original": orig, "trimmed": trimmed}
    with ThreadPoolExecutor(4) as ex:
        rows = list(ex.map(go, jobs))
    S = {"n": len(rows), "cut_files": sum(bool(r["was_cut"]) for r in rows)}
    for view in ("original", "trimmed_or_original"):
        pick = (lambda r: r["original"]) if view == "original" else (lambda r: r["trimmed"] or r["original"])
        hy = [r for r in rows if r["kind"] == "hybrid"]
        cl = [r for r in rows if r["kind"] == "classical"]
        S[view] = {
            "hybrid": {"n": len(hy), "read": sum(pick(r)["read"] for r in hy),
                       "says_mlkem768": sum(bool(pick(r).get("says_mlkem768")) for r in hy),
                       "suite_matches_swanctl": sum(bool(pick(r).get("suite_matches_swanctl")) for r in hy)},
            "classical": {"n": len(cl), "read": sum(pick(r)["read"] for r in cl),
                          "false_pq_claims": sum(bool(pick(r).get("says_pq_present")) for r in cl),
                          "suite_matches_swanctl": sum(bool(pick(r).get("suite_matches_swanctl")) for r in cl)},
        }
    S["hybrid_not_detected_examples"] = [(r["rel"], (r["trimmed"] or r["original"]).get("pq_values")) for r in rows
                                          if r["kind"] == "hybrid" and not (r["trimmed"] or r["original"]).get("says_mlkem768")][:6]
    S["classical_suite_mismatch_examples"] = [(r["rel"], r["original"].get("ike_encr"), r["original"].get("ike_dh"), r["original"].get("pq_values"))
                                               for r in rows if r["kind"] == "classical" and not r["original"].get("suite_matches_swanctl")][:6]
    os.makedirs(os.path.join(HERE, "results", "posthoc"), exist_ok=True)
    json.dump({"summary": S, "rows": rows}, open(os.path.join(HERE, "results", "posthoc", "posthoc_pq.json"), "w"), indent=1, default=str)
    print(json.dumps(S, indent=1, default=str))


if __name__ == "__main__":
    main()
