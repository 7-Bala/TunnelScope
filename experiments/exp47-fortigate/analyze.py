"""EXP-47 scorer (bars fixed in PREREG.md, 28d7ed0). Writes results/summary-<label>.json.

    .venv/bin/python experiments/exp47-fortigate/analyze.py --label before-fix [--dir testbed/captures/exp47]

The expected values come from the arm table and the hash table of PREREG.md and are checked against the device's own
report first (an arm whose ground truth disagrees with the table is stopped, not scored). TunnelScope's output is read last.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(HERE))
from run_arms import ARMS  # noqa: E402  (the arm table is the single source)

# hash -> (IKE integrity, PRF, ESP family name in the sieve table)
HASH = {
    "md5": ("HMAC-MD5-96", "PRF-HMAC-MD5", "DES-CBC+HMAC-96", "HMAC_MD5_96", "PRF_HMAC_MD5"),
    "sha1": ("HMAC-SHA1-96", "PRF-HMAC-SHA1", "DES-CBC+HMAC-96", "HMAC_SHA1_96", "PRF_HMAC_SHA1"),
    "sha256": ("HMAC-SHA2-256-128", "PRF-HMAC-SHA2-256", "DES-CBC+HMAC-SHA256-128", "HMAC_SHA2_256_128", "PRF_HMAC_SHA2_256"),
    "sha384": ("HMAC-SHA2-384-192", "PRF-HMAC-SHA2-384", "DES-CBC+HMAC-SHA384-192", "HMAC_SHA2_384_192", "PRF_HMAC_SHA2_384"),
    "sha512": ("HMAC-SHA2-512-256", "PRF-HMAC-SHA2-512", "DES-CBC+HMAC-SHA512-256", "HMAC_SHA2_512_256", "PRF_HMAC_SHA2_512"),
}
DH = {2: ("MODP-1024", "MODP_1024"), 5: ("MODP-1536", "MODP_1536"), 14: ("MODP-2048", "MODP_2048"), 15: ("MODP-3072", "MODP_3072"),
      16: ("MODP-4096", "MODP_4096"), 19: ("ECP-256", "ECP_256"), 20: ("ECP-384", "ECP_384"), 21: ("ECP-521", "ECP_521"),
      31: ("Curve25519", "CURVE_25519"), 28: ("dh-28", "ECP_256_BP")}          # 28 has no name in the ingest table (yet)
SILLY = ("strongSwan", "Libreswan", "RouterOS", "MikroTik")                      # H5: never these for a FortiGate


def val(r, a):
    f = r.findings.get(a)
    return (f.status.value, f.value) if f is not None else ("ABSENT", None)


def ok_or_unknown(r, attr, expected, accept=None):
    st, v = val(r, attr)
    if st in ("UNKNOWN", "NOT_OBSERVABLE", "ABSENT"):
        return "unknown", v
    return ("ok" if (v == expected or (accept and accept(v))) else "WRONG"), v


def gt_check(arm, a, gt):
    """Does the device's own report agree with the PREREG table? Returns (ok, notes)."""
    notes = []
    fg_gw, fg_t, peer = gt.get("fortigate_ike_gateway", ""), gt.get("fortigate_tunnel", ""), gt.get("peer_sas", "")
    h, g = a["hash"], a["dh"]
    exp_integ, exp_prf, _, ik_integ, ik_prf = HASH[h]
    ok = True
    m = re.search(r"proposal:\s*(\S+)", fg_gw)
    if not m or m.group(1) != f"des-{h}":
        ok = False; notes.append(f"FortiGate proposal {m.group(1) if m else None} != des-{h}")
    m = re.search(r"esp=(\w+) key=(\d+)", fg_t)
    if not m or m.group(1) != "des":
        ok = False; notes.append(f"FortiGate esp {m.group(0) if m else None}")
    m = re.search(r"ah=(\w+)", fg_t)
    if not m or m.group(1) != h:
        ok = False; notes.append(f"FortiGate ah {m.group(1) if m else None} != {h}")
    ike = re.search(r"DES_CBC/(\w+)/(\w+)/(\w+)", peer)
    if a["ike"] == 2 and (not ike or ike.group(2) != ik_prf or ike.group(3) != DH[g][1] or ike.group(1) != ik_integ):
        ok = False; notes.append(f"peer IKE suite {ike.group(0) if ike else None}")
    return ok, notes


def score_arm(arm, d, pcap):
    from tunnelscope.assess.engine import assess_record, load_baselines
    from tunnelscope.evidence.extract import build_records
    a = ARMS[arm]
    recs = [r for r in build_records(pcap) if getattr(r, "_ike", []) or getattr(r, "_esp", [])]
    res = {"arm": arm, "params": a, "established": d["established"], "records": len(recs)}
    if not recs:
        res["note"] = "no IKE or ESP record in the capture"
        return res
    r = next((x for x in recs if getattr(x, "_ike", [])), recs[0])
    fail = a.get("fail")
    if fail:                                                                        # H7
        st, v = val(r, "negotiation_outcome")
        if fail == "no-proposal":
            res["H7"] = {"value": v, "status": st, "pass": st == "UNKNOWN" or v == "ike-proposal-mismatch"}
        else:
            res["H7"] = {"value": v, "status": st, "pass": v != "success"}
        res["established_by_device"] = d["established"]
        return res
    gt0 = d["ground_truth"]
    ike_sa_up = bool(re.search(r"IKE SA:[^\n]*established 1/1", gt0["fortigate_ike_gateway"])) and bool(re.search(r"ESTABLISHED, IKEv", gt0["peer_sas"]))
    res["ike_sa_established_on_both_ends"] = ike_sa_up
    if not d["established"] and not ike_sa_up:
        res["unnegotiable"] = {"fortigate": gt0["fortigate_ike_gateway"][-300:], "peer_log": gt0["peer_log"][-300:]}
        return res
    if not d["established"]:
        res["child_sa_failed"] = True                                    # ADDENDUM B: the IKE SA is scored, ESP is not
    ok, notes = gt_check(arm, a, d["ground_truth"])
    res["ground_truth_agrees_with_table"] = ok
    if not ok:
        res["ground_truth_notes"] = notes
        return res
    h, g = a["hash"], a["dh"]
    exp_integ, exp_prf, family, _, _ = HASH[h]
    out = {}
    # H1
    out["ike_version"] = ok_or_unknown(r, "ike_version", f"IKEv{a['ike']}")
    out["ike_prf"] = ok_or_unknown(r, "ike_prf", exp_prf)
    out["ike_integ"] = ok_or_unknown(r, "ike_integ", exp_integ) if a["ike"] == 2 else ("skip (IKEv1 has no integrity transform)", None)
    out["ike_dh_group"] = ok_or_unknown(r, "ike_dh_group", DH[g][0])
    out["pq_key_exchange"] = ok_or_unknown(r, "pq_key_exchange", "classical-only")
    res["H1"] = out
    res["H1_pass"] = all(v[0] in ("ok", "unknown") or str(v[0]).startswith("skip") for v in out.values())
    # H2
    st, v = val(r, "ike_encr")
    res["H2"] = {"status": st, "value": v, "pass": bool(isinstance(v, str) and re.fullmatch(r"DES(-CBC)?", v))}
    # H3
    st, v = val(r, "esp_cipher_family")
    if res.get("child_sa_failed"):
        res["H3"] = {"status": st, "pass": True, "note": "no child SA formed, nothing to be wrong about ESP"}
    elif st == "INFERRED" and isinstance(v, list):
        res["H3"] = {"status": st, "truth": family, "contains_truth": family in v, "candidates": v, "pass": family in v}
    else:
        res["H3"] = {"status": st, "pass": True, "note": "not INFERRED, so nothing to be wrong"}
    # H4
    st, v = val(r, "pfs")
    want_pfs = a.get("pfs", True)
    if arm.startswith("P") or st != "NOT_OBSERVABLE":
        res["H4"] = {"status": st, "value": v, "expected": want_pfs, "pass": st in ("UNKNOWN", "NOT_OBSERVABLE") or v == want_pfs}
    # H5
    st, v = val(r, "implementation")
    res["H5"] = {"status": st, "value": v, "pass": not (isinstance(v, str) and any(s.lower() in v.lower() for s in SILLY)) and
                 not (isinstance(v, dict) and any(s.lower() in json.dumps(v).lower() for s in SILLY))}
    # H6: verdicts equal those the same rules give on the expected values
    base = load_baselines()
    got = {x.rule_id: x.verdict for x in assess_record(r, base)}
    exp_rec = copy.deepcopy(r)
    from tunnelscope.evidence.record import Finding, Status
    def setf(attr, value):
        f = exp_rec.findings[attr]
        exp_rec.findings[attr] = Finding(attr, Status.OBSERVED, f.vantage, f.method, value=value, evidence=f.evidence)
    setf("ike_prf", exp_prf); setf("ike_dh_group", DH[g][0]); setf("ike_encr", "DES")
    if a["ike"] == 2:
        setf("ike_integ", exp_integ)
    want = {x.rule_id: x.verdict for x in assess_record(exp_rec, base)}
    diff = {k: [got.get(k), want.get(k)] for k in set(got) | set(want) if got.get(k) != want.get(k)}
    res["H6"] = {"differences": diff, "pass": not diff}
    # rekey cadence and the SPIs (reported)
    res["reported"] = {"rekey_cadence": val(r, "rekey_cadence"), "ipsec_protocols": val(r, "ipsec_protocols")}
    spis = set(re.findall(r"spi=([0-9a-f]{8})", d["ground_truth"]["fortigate_tunnel"]))
    tsh = subprocess.run(["tshark", "-n", "-r", pcap, "-Y", "esp", "-T", "fields", "-e", "esp.spi"], capture_output=True, text=True).stdout
    wire = {f"{int(x, 0):08x}" for x in tsh.split() if x}
    res["esp_spis_on_wire_match_fortigate"] = bool(spis) and spis <= wire if wire else None
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(REPO, "testbed", "captures", "exp47"))
    ap.add_argument("--label", required=True)
    a = ap.parse_args()
    arms, manifest = {}, {}
    for arm in ARMS:
        j, p = os.path.join(a.dir, f"{arm}.json"), os.path.join(a.dir, f"{arm}.pcap")
        if not (os.path.exists(j) and os.path.exists(p)):
            arms[arm] = {"arm": arm, "note": "not captured"}
            continue
        manifest[arm] = hashlib.sha256(open(p, "rb").read()).hexdigest()
        arms[arm] = score_arm(arm, json.load(open(j)), p)
    scored = [x for x in arms.values() if "H1" in x]
    summary = {
        "label": a.label, "arms": arms, "capture_sha256": manifest,
        "established_scored": len(scored),
        "H1": {"pass": all(x["H1_pass"] for x in scored), "failing_arms": [x["arm"] for x in scored if not x["H1_pass"]]},
        "H2": {"pass": all(x["H2"]["pass"] for x in scored), "failing_arms": [x["arm"] for x in scored if not x["H2"]["pass"]],
               "values": sorted({str(x["H2"]["value"]) for x in scored})},
        "H3": {"pass": all(x["H3"]["pass"] for x in scored), "failing_arms": [x["arm"] for x in scored if not x["H3"]["pass"]]},
        "H4": {"pass": all(x["H4"]["pass"] for x in scored if "H4" in x), "arms_scored": [x["arm"] for x in scored if "H4" in x],
               "failing_arms": [x["arm"] for x in scored if "H4" in x and not x["H4"]["pass"]]},
        "H5": {"pass": all(x["H5"]["pass"] for x in scored), "values": sorted({json.dumps(x["H5"]["value"])[:80] for x in scored})},
        "H6": {"pass": all(x["H6"]["pass"] for x in scored), "failing_arms": [x["arm"] for x in scored if not x["H6"]["pass"]]},
        "H7": {"arms": {k: v["H7"] for k, v in arms.items() if "H7" in v}, "pass": all(v["H7"]["pass"] for v in arms.values() if "H7" in v)},
        "unnegotiable": [k for k, v in arms.items() if "unnegotiable" in v],
        "stopped_ground_truth_disagrees": [k for k, v in arms.items() if v.get("ground_truth_agrees_with_table") is False],
    }
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    out = os.path.join(HERE, "results", f"summary-{a.label}.json")
    json.dump(summary, open(out, "w"), indent=1, sort_keys=True, default=str)
    print(json.dumps({k: v.get("pass") for k, v in summary.items() if isinstance(v, dict) and "pass" in v}), "scored arms:",
          len(scored), "unnegotiable:", summary["unnegotiable"], "stopped:", summary["stopped_ground_truth_disagrees"])
    print("written", out)


if __name__ == "__main__":
    main()
