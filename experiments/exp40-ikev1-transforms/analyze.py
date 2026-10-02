"""EXP-40 scorer (pre-registered in PREREG.md, commit 9d95710).

    .venv/bin/python experiments/exp40-ikev1-transforms/analyze.py --snapshot   # BEFORE the change: results/before.json
    .venv/bin/python experiments/exp40-ikev1-transforms/analyze.py               # AFTER: results/summary.json

Ground truth = pluto's own "ISAKMP SA established {cipher= integ= group=}" line for each arm. The expected names below
are written down BEFORE any extractor exists, in the vocabulary the IKEv2 findings already use.
"""
import argparse
import glob
import json
import os
import re
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CAPS = os.path.join(REPO, "testbed", "captures", "exp40")
RES = os.path.join(HERE, "results")
sys.path.insert(0, REPO)

CIPHER = {"AES_CBC_128": "AES-CBC-128", "AES_CBC_192": "AES-CBC-192", "AES_CBC_256": "AES-CBC-256", "3DES_CBC_192": "3DES"}
HASH = {"HMAC_SHA1": "PRF-HMAC-SHA1", "HMAC_SHA2_256": "PRF-HMAC-SHA2-256", "HMAC_SHA2_384": "PRF-HMAC-SHA2-384",
        "HMAC_SHA2_512": "PRF-HMAC-SHA2-512"}
GROUP = {"MODP1024": "MODP-1024", "MODP1536": "MODP-1536", "MODP2048": "MODP-2048", "MODP3072": "MODP-3072", "DH19": "ECP-256",
         "DH20": "ECP-384"}
FIRST_OFFER = {"ike_encr": "AES-CBC-256", "ike_prf": "PRF-HMAC-SHA2-256", "ike_dh_group": "MODP-2048"}   # e40-m-multi's first offer
NEW = ("ike_encr", "ike_prf", "ike_dh_group")


def expected(arm):
    gt = json.load(open(os.path.join(CAPS, f"{arm}.groundtruth.json")))
    for line in gt["pluto_log_T2"]:
        m = re.search(rf'"{re.escape(arm)}" #\d+: ISAKMP SA established \{{auth=\S+ cipher=(\S+) integ=(\S+) group=(\S+)\}}', line)
        if m:
            return {"ike_encr": CIPHER[m.group(1)], "ike_prf": HASH[m.group(2)], "ike_dh_group": GROUP[m.group(3)]}
    return None            # the arm did not establish


def arms():
    return sorted(os.path.basename(p)[:-len(".pcap")] for p in glob.glob(os.path.join(CAPS, "*.pcap")))


def findings(pcap):
    from tunnelscope.assess.engine import assess_record, load_baselines
    from tunnelscope.evidence.extract import build_records
    from tunnelscope.ingest import tshark
    tshark.clear_cache()
    recs = [r for r in build_records(pcap) if getattr(r, "_ike", [])]
    if not recs:
        return None, []
    r = recs[0]
    f = {k: {"status": v.status.value, "value": v.value} for k, v in r.findings.items()}
    v = [{"baseline": x.baseline, "rule": x.rule_id, "verdict": x.verdict} for x in assess_record(r, load_baselines())]
    return f, v


def cut_before_responder(src, dst):
    """Keep only the packets before the first packet from the other side: the initiator's offer and its retransmissions."""
    from tunnelscope.ingest import tshark
    tshark.clear_cache()
    rows = tshark._run_fields(src, "ip", ["ip.src"])
    first, n = rows[0][0], 0
    for r in rows:
        if r[0] != first:
            break
        n += 1
    raw = open(src, "rb").read()
    pos, kept = 24, 0
    while kept < n:
        pos += 16 + struct.unpack("<I", raw[pos + 8:pos + 12])[0]
        kept += 1
    open(dst, "wb").write(raw[:pos])
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", action="store_true")
    a = ap.parse_args()
    os.makedirs(RES, exist_ok=True)
    snap = {arm: findings(os.path.join(CAPS, arm + ".pcap")) for arm in arms()}
    if a.snapshot:
        json.dump({k: {"findings": v[0], "verdicts": v[1]} for k, v in snap.items()}, open(os.path.join(RES, "before.json"), "w"), indent=1)
        print("snapshot of", len(snap), "arms written (taken before the extractor exists)")
        return
    before = json.load(open(os.path.join(RES, "before.json")))
    S = {"arms": {}}
    p1, p2, p3, p5, p6 = [], [], [], [], []
    for arm in arms():
        f, v = snap[arm]
        exp = expected(arm)
        row = {"expected": exp}
        if exp is None:
            S["arms"][arm] = {**row, "note": "arm did not establish"}
            continue
        got = {k: f[k]["value"] for k in NEW if f.get(k) and f[k]["status"] == "OBSERVED"}
        row["got"] = got
        ok = all(got.get(k) == exp[k] for k in NEW)
        p1.append((arm, ok))
        if arm == "e40-m-multi":
            p2.append((arm, ok and all(exp[k] != FIRST_OFFER[k] for k in NEW)))
        # P40-3: initiator-only copy
        with tempfile.TemporaryDirectory() as d:
            cut = os.path.join(d, "cut.pcap")
            n = cut_before_responder(os.path.join(CAPS, arm + ".pcap"), cut)
            cf, _ = findings(cut)
        asserted = [k for k in NEW if cf and cf.get(k) and cf[k]["status"] != "UNKNOWN"]
        p3.append((arm, not asserted)); row["initiator_only_packets"] = n; row["initiator_only_asserted"] = asserted
        # P40-5
        vv = {x["rule"]: x["verdict"] for x in v}
        want193 = "PASS" if exp["ike_dh_group"] == "ECP-256" else "FAIL"
        rfc = [x for x in v if x["baseline"] == "RFC-8247" or x["rule"].startswith("RFC8247-")]
        p5.append((arm, vv.get("V-207193") == want193 and vv.get("V-207205") == "FAIL" and not rfc))
        row["V-207193"], row["V-207205"], row["rfc8247_verdicts"] = vv.get("V-207193"), vv.get("V-207205"), [x["rule"] for x in rfc]
        # P40-6: nothing else changed in (status, value)
        b = before[arm]["findings"] or {}
        diff = [k for k in set(b) | set(f) if k not in NEW + ("ike_integ", "capture_integrity")
                and (b.get(k, {}).get("status"), b.get(k, {}).get("value")) != (f.get(k, {}).get("status"), f.get(k, {}).get("value"))]
        p6.append((arm, not diff)); row["other_findings_changed"] = diff
        S["arms"][arm] = row
    for name, rows in (("P40-1", p1), ("P40-2", p2), ("P40-3", p3), ("P40-5", p5), ("P40-6", p6)):
        S[name] = {"arms_checked": len(rows), "arms_ok": sum(ok for _, ok in rows), "failed": [a_ for a_, ok in rows if not ok],
                   "pass": bool(rows) and all(ok for _, ok in rows)}
    json.dump(S, open(os.path.join(RES, "summary.json"), "w"), indent=1, default=str)
    print(json.dumps({k: S[k] for k in S if k.startswith("P40")}, indent=1))


if __name__ == "__main__":
    main()
