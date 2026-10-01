"""EXP-37 scorer (pre-registered in PREREG.md, commit df26be3). Writes results/raw.jsonl and results/summary.json.

    .venv/bin/python experiments/exp37-cross-lab-external/analyze.py --lab DIR/ipsec-pcap-lab --pq DIR/pq_thesis

Both directories live outside the repository (other teams' data, no licence): nothing is copied here.
Every capture goes through the shipped product path (`tunnelscope analyze --json`), no code in this file
reimplements an analysis. Anything that could be a spelling mismatch between our value and the other lab's
metadata is listed under `adjudicate` for a person to decide, never silently counted either way.
"""
import argparse
import csv
import glob
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CLI = os.path.join(REPO, ".venv", "bin", "tunnelscope")
RES = os.path.join(HERE, "results")
ASSERTED = ("OBSERVED", "INFERRED", "MEASURED")
MAP = {"bulk": "file_transfer", "file_transfer": "file_transfer"}


def run(path):
    p = subprocess.run([CLI, "analyze", "--json", path], capture_output=True, text=True, timeout=600)
    if p.returncode != 0:
        return {"pcap": path, "error": (p.stderr or p.stdout)[-300:]}
    d = json.loads(p.stdout)
    recs = d.get("records") or []

    def pk(r):
        v = (r["findings"].get("sequence_integrity") or {}).get("value")
        return (v or {}).get("packets", 0) if isinstance(v, dict) else 0
    best = max(recs, key=pk) if recs else None
    return {"pcap": path, "summary": d.get("summary"), "n_records": len(recs),
            "findings": (best or {}).get("findings")}


def f(row, name):
    return ((row.get("findings") or {}).get(name)) or {}


def asserted(fd):
    return fd.get("status") in ASSERTED and fd.get("value") not in (None, [], {}, "")


def label_of(fd):
    v = fd.get("value")
    if isinstance(v, dict):
        v = v.get("label") or v.get("class") or v.get("traffic_type")
    if isinstance(v, list) and v:
        v = v[0]
    return MAP.get(str(v).lower(), str(v).lower()) if v not in (None, "") else None


def family_set(fd):
    cands = fd.get("value") or []
    fam = set()
    for c in cands if isinstance(cands, list) else [str(cands)]:
        u = str(c).upper()
        for k in ("CBC", "GCM", "CTR", "CCM", "CHACHA", "NULL"):
            if k in u:
                fam.add(k)
    return fam


def norm(s):
    return re.sub(r"[^A-Z0-9]", "", str(s).upper())


def part_a(lab):
    meta = {r["pcap_path"]: r for r in csv.DictReader(open(os.path.join(lab, "metadata.csv")))}
    rows = {}
    todo = []
    for sub in ("known", "ood", "anomaly", "protocol_validation"):
        for p in sorted(glob.glob(os.path.join(lab, "pcaps", sub, "**", "*.pcap"), recursive=True)):
            todo.append((sub, p))
    with ThreadPoolExecutor(4) as ex:
        for (sub, p), r in zip(todo, ex.map(lambda x: run(x[1]), todo)):
            rel = os.path.relpath(p, lab)
            r["set"], r["rel"], r["meta"] = sub, rel, meta.get(rel)
            rows[rel] = r
    return list(rows.values())


def score_a(rows):
    S = {}
    known = [r for r in rows if r["set"] == "known" and "error" not in r and r["meta"]]
    S["n_known"] = len(known)
    S["errors"] = [r["rel"] for r in rows if "error" in r]
    # P37-1
    bad = [r["rel"] for r in known if asserted(f(r, "ike_dh_group")) or asserted(f(r, "pfs"))]
    S["P37-1"] = {"violations": len(bad), "examples": bad[:5], "pass": len(bad) == 0}
    # P37-2
    inferred = [r for r in known if f(r, "esp_cipher_family").get("status") == "INFERRED"]
    excl = []
    for r in inferred:
        truth = "CBC" if "CBC" in r["meta"]["cipher"].upper() else "GCM" if "GCM" in r["meta"]["cipher"].upper() else None
        if truth and truth not in family_set(f(r, "esp_cipher_family")):
            excl.append((r["rel"], r["meta"]["cipher"], sorted(family_set(f(r, "esp_cipher_family")))))
    S["P37-2"] = {"inferred": len(inferred), "unknown_or_other": len(known) - len(inferred), "exclusions": len(excl),
                  "examples": excl[:5], "pass": len(excl) == 0}
    # P37-3/4/5
    commits = [r for r in known if f(r, "traffic_type").get("status") != "UNKNOWN" and label_of(f(r, "traffic_type"))]
    right = [r for r in commits if label_of(f(r, "traffic_type")) == r["meta"]["canonical_label"]]
    conf_wrong = [r for r in commits if label_of(f(r, "traffic_type")) != r["meta"]["canonical_label"]
                  and (f(r, "traffic_type").get("confidence") or 0) >= 0.8]
    S["P37-3"] = {"commits": len(commits), "correct": len(right),
                  "accuracy": round(len(right) / len(commits), 4) if commits else None,
                  "pass": bool(commits) and len(right) / len(commits) >= 0.70}
    S["P37-4"] = {"coverage": round(len(commits) / len(known), 4) if known else None, "pass": bool(known) and len(commits) / len(known) >= 0.50}
    S["P37-5"] = {"confident_wrong": len(conf_wrong), "share_of_commits": round(len(conf_wrong) / len(commits), 4) if commits else None,
                  "pass": (len(conf_wrong) / len(commits) <= 0.10) if commits else None}
    conf = {}
    for r in commits:
        k = (r["meta"]["canonical_label"], label_of(f(r, "traffic_type")))
        conf[f"{k[0]}->{k[1]}"] = conf.get(f"{k[0]}->{k[1]}", 0) + 1
    S["confusion_committed"] = conf
    by_prof = {}
    for r in known:
        d = by_prof.setdefault(r["meta"]["profile_id"], {"n": 0, "commit": 0})
        d["n"] += 1
        d["commit"] += int(r in commits)
    S["commit_by_profile"] = by_prof
    # P37-6
    ood = [r for r in rows if r["set"] == "ood" and "error" not in r and r["meta"] and r["meta"]["dataset_role"] == "ood_eval"]
    ok = [r for r in ood if f(r, "traffic_type").get("status") == "UNKNOWN" or (f(r, "traffic_type").get("confidence") or 1) < 0.6]
    S["P37-6"] = {"ood_eval": len(ood), "abstained_or_low": len(ok), "share": round(len(ok) / len(ood), 4) if ood else None,
                  "pass": bool(ood) and len(ok) / len(ood) >= 0.60,
                  "labels_given": [label_of(f(r, "traffic_type")) for r in ood if r not in ok]}
    # P37-7
    mm = [r for r in known if f(r, "mode").get("status") != "UNKNOWN" and str(f(r, "mode").get("value")).lower() in ("tunnel", "transport")]
    mok = [r for r in mm if str(f(r, "mode").get("value")).lower() == r["meta"]["mode"].lower()]
    S["P37-7"] = {"committed": len(mm), "correct": len(mok), "accuracy": round(len(mok) / len(mm), 4) if mm else None,
                  "pass": (len(mok) / len(mm) >= 0.80) if mm else None, "note": "pass is None when the tool never commits"}
    # P37-8 (candidates for manual adjudication)
    adj = []
    for r in rows:
        if r["set"] != "protocol_validation" or "error" in r or not r["meta"]:
            continue
        m = r["meta"]
        for attr, truth in (("ike_version", m["ike_version"]), ("ike_dh_group", m["dh_group"]), ("mode", m["mode"])):
            fd = f(r, attr)
            if fd.get("status") == "OBSERVED":
                adj.append({"rel": r["rel"], "attr": attr, "ours": fd.get("value"), "metadata": truth})
    S["P37-8"] = {"observed_values_to_adjudicate": adj, "pass": "ADJUDICATE BY HAND (see RESULT.md)"}
    # exploratory
    S["exploratory_anomaly"] = [{"rel": r["rel"], "traffic_type": label_of(f(r, "traffic_type")), "status": f(r, "traffic_type").get("status"),
                                 "note": (f(r, "traffic_type").get("note") or "")[:120]} for r in rows if r["set"] == "anomaly" and "error" not in r]
    exact = []
    for r in inferred:
        c = r["meta"]
        want = ("GCM" if "GCM" in c["cipher"].upper() else "CBC")
        integ = re.sub(r"\D", "", c["integrity"]) if "HMAC" in c["integrity"].upper() else ""
        have = [str(x).upper() for x in (f(r, "esp_cipher_family").get("value") or [])]
        hit = any(want in h and (not integ or f"SHA{integ}" in h.replace("-", "")) for h in have)
        exact.append(hit)
    S["exploratory_exact_cipher_integrity_contained"] = {"checked": len(exact), "contained": sum(exact)}
    S["exploratory_candidate_set_size"] = sorted(len(f(r, "esp_cipher_family").get("value") or []) for r in inferred)[::max(1, len(inferred) // 10)]
    return S


def part_b(pq):
    caps = sorted(glob.glob(os.path.join(pq, "**", "*_ike_control_plane.pcap"), recursive=True))
    with ThreadPoolExecutor(4) as ex:
        res = list(ex.map(run, caps))
    for p, r in zip(caps, res):
        rel = os.path.relpath(p, pq)
        r["rel"], r["mode_truth"] = rel, ("hybrid" if rel.startswith("Hybrid") else "classical")
        sw = p.replace("_ike_control_plane.pcap", "_swanctl_after_traffic.txt")
        r["swanctl_line"] = next((l.strip() for l in open(sw) if "AES_GCM_16-256/" in l), None) if os.path.exists(sw) else None
    return res


def score_b(rows):
    S = {"n": len(rows), "errors": [r["rel"] for r in rows if "error" in r]}
    ok_rows = [r for r in rows if "error" not in r]
    inc = [r for r in ok_rows if (r.get("summary") or {}).get("has_ike_sa_init")]
    S["included"] = len(inc)
    S["excluded"] = [r["rel"] for r in ok_rows if r not in inc] + S["errors"]
    S["P37-12"] = {"share": round(len(inc) / len(rows), 4) if rows else None, "pass": bool(rows) and len(inc) / len(rows) >= 0.80}
    hyb = [r for r in inc if r["mode_truth"] == "hybrid"]
    cla = [r for r in inc if r["mode_truth"] == "classical"]
    pq = lambda r: f(r, "pq_key_exchange")
    miss = [r["rel"] for r in hyb if not (pq(r).get("status") == "OBSERVED" and "768" in norm(pq(r).get("value")))]
    S["P37-9"] = {"hybrid_included": len(hyb), "not_observed_as_mlkem768": len(miss), "examples": miss[:5], "pass": len(miss) == 0 and bool(hyb)}
    fp = [r["rel"] for r in cla if pq(r).get("status") in ASSERTED and re.search(r"KEM|KYBER|ADDKE", norm(pq(r).get("value")))]
    S["P37-10"] = {"classical_included": len(cla), "false_pq_claims": len(fp), "examples": fp[:5], "pass": len(fp) == 0 and bool(cla)}
    adj = []
    for r in inc:
        adj.append({"rel": r["rel"], "truth": r["swanctl_line"], "ike_encr": f(r, "ike_encr").get("value"), "ike_encr_status": f(r, "ike_encr").get("status"),
                    "ike_dh_group": f(r, "ike_dh_group").get("value"), "ike_dh_status": f(r, "ike_dh_group").get("status"),
                    "pq": pq(r).get("value"), "pq_status": pq(r).get("status")})
    bad = [a for a in adj if not (a["ike_encr_status"] == "OBSERVED" and "GCM" in norm(a["ike_encr"]) and "256" in norm(a["ike_encr"])
                                   and a["ike_dh_status"] == "OBSERVED" and re.search(r"CURVE25519|X25519|^31$|25519", norm(a["ike_dh_group"])))]
    S["P37-11"] = {"checked": len(adj), "auto_mismatch_candidates": len(bad), "examples": bad[:5], "pass": "ADJUDICATE BY HAND (see RESULT.md)" if bad else True}
    S["distinct_pq_values"] = sorted({str(pq(r).get("status")) + ":" + str(pq(r).get("value")) for r in inc})[:12]
    return S


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab")
    ap.add_argument("--pq")
    ap.add_argument("--only", help="dry run: analyse only this one capture and print the findings")
    a = ap.parse_args()
    if a.only:
        print(json.dumps(run(a.only)["findings"], indent=1)[:2000])
        return
    os.makedirs(RES, exist_ok=True)
    out = {}
    raw = open(os.path.join(RES, "raw.jsonl"), "w")
    if a.lab:
        A = part_a(a.lab)
        for r in A:
            raw.write(json.dumps({"part": "A", **r}) + "\n")
        out["A"] = score_a(A)
    if a.pq:
        B = part_b(a.pq)
        for r in B:
            raw.write(json.dumps({"part": "B", **r}) + "\n")
        out["B"] = score_b(B)
    raw.close()
    json.dump(out, open(os.path.join(RES, "summary.json"), "w"), indent=1, default=str)
    print(json.dumps(out, indent=1, default=str)[:6000])


if __name__ == "__main__":
    sys.exit(main())
