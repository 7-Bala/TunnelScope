"""EXP-26 scoring, exactly as PREREG.md defines it. Runs the shipped CLI (analyze + assess) on every arm's
capture and compares each scored finding with the arm's ground truth (config + RouterOS installed-SA state).

  .venv/bin/python experiments/exp26-mikrotik-routeros/analyze.py
"""
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAP = ROOT / "testbed" / "captures" / "exp26"
RESULTS = Path(__file__).resolve().parent / "results"
CLI = str(ROOT / ".venv" / "bin" / "tunnelscope")
ARMS = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]

# RouterOS config names -> TunnelScope's IANA-derived names (spelling only; same algorithm and key size)
IKE_ENC = {"aes-256": "AES-CBC-256", "aes-128": "AES-CBC-128", "3des": "3DES"}
INTEG = {"sha1": "HMAC-SHA1-96", "sha256": "HMAC-SHA2-256-128", "sha384": "HMAC-SHA2-384-192", "sha512": "HMAC-SHA2-512-256"}
PRF = {"sha1": "PRF-HMAC-SHA1", "sha256": "PRF-HMAC-SHA2-256", "sha384": "PRF-HMAC-SHA2-384", "sha512": "PRF-HMAC-SHA2-512"}
DH = {"modp1024": "MODP-1024", "modp2048": "MODP-2048", "ecp256": "ECP-256", "ecp384": "ECP-384", "x25519": "Curve25519"}
ESP = {("aes-256-gcm", None): "AES-GCM-16", ("aes-128-gcm", None): "AES-GCM-16",
       ("chacha20poly1305", None): "ChaCha20-Poly1305", ("3des", "sha1"): "3DES-CBC+HMAC-SHA1-96",
       ("aes-256-cbc", "sha256"): "AES-CBC+HMAC-SHA256-128"}
SCORED = ["ike_version", "ike_encr", "ike_integ", "ike_prf", "ike_dh_group", "ike_offered_dh", "pq_key_exchange",
          "ipsec_protocols", "esp_cipher_family", "pfs", "negotiation_outcome", "sequence_integrity", "early_childsa_cve"]
REPORTED = ["mode", "rekey_cadence", "traffic_type", "metadata_exposure", "peer_auth_method", "responder_cert_capability"]


def cli(cmd, pcap):
    out = subprocess.run([CLI, cmd, "--json", str(pcap)], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def truth(gt):
    c = gt["config"]
    return {"ike_version": "IKEv2", "ike_encr": IKE_ENC[c["ike_enc"]], "ike_integ": INTEG[c["ike_hash_prf"]],
            "ike_prf": PRF[c["ike_hash_prf"]], "ike_dh_group": DH[c["responder_groups"]],
            "ike_offered_dh": sorted(DH[g] for g in c["initiator_groups"].split(",")),
            "pq_key_exchange": "classical-only", "ipsec_protocols": ["ESP"],
            "esp_cipher_family": ESP[(c["esp_enc"], c["esp_auth"])], "pfs": c["pfs_group"] != "none",
            "negotiation_outcome": "success", "sequence_integrity": 0, "early_childsa_cve": "not-detected"}


def judge(attr, f, want):
    """-> 'correct' | 'unknown' | 'wrong' (+ the reason) per PREREG 'Scoring'."""
    st, val = f["status"], f["value"]
    if st in ("UNKNOWN", "NOT_OBSERVABLE"):
        return "unknown", st
    if attr == "esp_cipher_family":
        cands = val if isinstance(val, list) else [val]
        return ("correct" if want in cands else "wrong"), f"{st} {cands}"
    if attr == "ike_offered_dh":
        return ("correct" if sorted(val) == want else "wrong"), f"{st} {val}"
    if attr == "sequence_integrity":
        return ("correct" if val.get("replayed") == want else "wrong"), f"{st} replayed={val.get('replayed')}"
    if attr == "early_childsa_cve":
        # a non-detection under another name is still a non-detection; the literal is kept for H5
        return ("correct" if val in ("not-detected", "not-applicable") else "wrong"), f"{st} {val}"
    return ("correct" if val == want else "wrong"), f"{st} {val}"


def score_arm(arm):
    gt = json.loads((CAP / f"mt-{arm.lower()}.groundtruth.json").read_text())
    want = truth(gt)
    a = cli("analyze", CAP / f"mt-{arm.lower()}.pcap")
    verdicts = cli("assess", CAP / f"mt-{arm.lower()}.pcap")
    rows, reported = [], []
    for rec in a["records"]:
        F = rec["findings"]
        for attr in SCORED:
            if attr not in F:
                continue
            if attr == "pfs" and gt["config"]["child_lifetime"] != "30s" and F[attr]["status"] not in ("UNKNOWN", "NOT_OBSERVABLE"):
                pass   # a PFS claim without a rekey is still judged against the config
            verdict, why = judge(attr, F[attr], want[attr])
            rows.append({"sa": rec["sa_key"], "attribute": attr, "result": verdict, "tunnelscope": why,
                         "truth": want[attr]})
        reported.append({"sa": rec["sa_key"], **{k: {"status": F[k]["status"], "value": F[k]["value"]}
                                                 for k in REPORTED if k in F}})
    rules = {}
    for v in verdicts:
        rules.setdefault(v["rule_id"], set()).add(v["verdict"])
    return {"arm": arm, "summary": a["summary"], "rows": rows, "reported": reported,
            "rules": {k: sorted(s) for k, s in rules.items()},
            "installed_sa": [{k: s.get(k) for k in ("spi", "enc-algorithm", "auth-algorithm", "enc-key-size")}
                             for s in gt["installed_sa"]]}


def verify_hashes():
    """Captures must match testbed/captures/exp26/manifest.csv before anything is scored."""
    for row in csv.DictReader(open(CAP / "manifest.csv")):
        got = hashlib.sha256((CAP / row["file"]).read_bytes()).hexdigest()
        if got != row["sha256"]:
            sys.exit(f"hash mismatch for {row['file']}: {got} != {row['sha256']}")


def main():
    verify_hashes()
    RESULTS.mkdir(exist_ok=True)
    arms = [score_arm(a) for a in ARMS]
    allrows = [r for a in arms for r in a["rows"]]
    tally = {k: sum(r["result"] == k for r in allrows) for k in ("correct", "unknown", "wrong")}

    def best(arm, attr):   # any record observing it correctly counts; a wrong anywhere is reported by H1
        res = [r["result"] for r in next(x for x in arms if x["arm"] == arm)["rows"] if r["attribute"] == attr]
        return "wrong" if "wrong" in res else "correct" if "correct" in res else "unknown" if res else "absent"

    def fails(arm, rid):
        return "FAIL" in next(x for x in arms if x["arm"] == arm)["rules"].get(rid, [])

    def rekey_ok(arm):
        rc = [x["rekey_cadence"] for x in next(a for a in arms if a["arm"] == arm)["reported"] if "rekey_cadence" in x]
        vals = [x["value"] for x in rc if x["status"] == "MEASURED" and x["value"]]
        iv = [i for v in vals for i in v.get("intervals_s", [])]
        n = max([v.get("n_rekeys", 0) for v in vals] or [0])
        return {"n_rekeys": n, "intervals_s": iv, "pass": n >= 1 and all(i <= 35 for i in iv)}

    cve_literals = sorted({r["tunnelscope"] for r in allrows if r["attribute"] == "early_childsa_cve"})
    hyp = {
        "H1_zero_wrong": {"wrong": tally["wrong"], "pass": tally["wrong"] == 0},
        "H2_ike_suite_observed": {a: {k: best(a, k) for k in ("ike_encr", "ike_integ", "ike_prf", "ike_dh_group")} for a in ARMS},
        "H3_pfs": {"M6": best("M6", "pfs"), "M7": best("M7", "pfs")},
        "H4_rekey": {a: rekey_ok(a) for a in ("M6", "M7")},
        "H5_cve_specificity": {"literals": cve_literals, "wrong": sum(r["result"] == "wrong" for r in allrows if r["attribute"] == "early_childsa_cve")},
        "H6_compliance": {"M4 fails DH-MUST/ENCR/ESP-3DES": [fails("M4", r) for r in ("RFC8247-DH-MUST", "RFC8247-ENCR", "RFC8221-ESP-3DES")],
                          "M1 passes all three": [not fails("M1", r) for r in ("RFC8247-DH-MUST", "RFC8247-ENCR", "RFC8221-ESP-3DES")],
                          "M8 fails DH-OFFER, passes DH-MUST": [fails("M8", "RFC8247-DH-OFFER"), not fails("M8", "RFC8247-DH-MUST")]},
    }
    hyp["H2_ike_suite_observed"]["pass"] = all(v == "correct" for a in ARMS for v in hyp["H2_ike_suite_observed"][a].values())
    hyp["H3_pfs"]["pass"] = hyp["H3_pfs"] == {"M6": "correct", "M7": "correct"} or False
    hyp["H4_rekey"]["pass"] = all(hyp["H4_rekey"][a]["pass"] for a in ("M6", "M7"))
    hyp["H5_cve_specificity"]["pass_as_written"] = cve_literals and all(l.endswith("not-detected") for l in cve_literals)
    hyp["H6_compliance"]["pass"] = all(all(v) for v in hyp["H6_compliance"].values() if isinstance(v, list))
    out = {"tally": tally, "hypotheses": hyp, "arms": arms}
    (RESULTS / "score.json").write_text(json.dumps(out, indent=1, default=str) + "\n")
    print(json.dumps({"tally": tally, "hypotheses": hyp}, indent=1, default=str))
    for r in allrows:
        if r["result"] == "wrong":
            print("WRONG", r, file=sys.stderr)


if __name__ == "__main__":
    main()
