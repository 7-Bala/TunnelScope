#!/usr/bin/env python3
"""EXP-06 round 2 — can a passive (T0/T1, no keys) observer tell WHICH IKE
negotiation failure occurred?

Pre-registered design + predictions P-a..P-f:
  research/registers/EXPERIMENT-REGISTER.md  ("EXP-06 Round 2 — PRE-REGISTRATION")

Two classifiers on the SAME structural features, both evaluated
leave-one-repetition-out (session-level split, DEC-009):
  1. RULES — hand-written from protocol arithmetic, fixed before seeing data
     (thresholds derived below, not fitted).
  2. TREE  — sklearn DecisionTreeClassifier, fitted on the other repetitions.
If RULES matches TREE, failure diagnosis does not need ML (feeds CS-02 in the
AI Necessity Matrix).

Ground truth = the designed misconfiguration (configs/exp06/arms.json),
confirmed per run by charon's own log (T2) in each .groundtruth.json. Neither
is derived from the capture.

Threshold derivation (IKE SA = AES-CBC-256 + HMAC-SHA256-128, over UDP/4500):
  An encrypted IKE message carrying only one data-less NOTIFY is
    IP 20 + UDP 8 + non-ESP marker 4 + IKE hdr 28 + SK hdr 4 + IV 16
    + ciphertext 16 (8-byte notify padded to the 16-byte block) + ICV 16 = 112 bytes.
  A response that also carries IDr + AUTH (+ MOBIKE notifies) is far larger.
  So "response <= 144 bytes" (112 + two cipher blocks of slack) means the
  response carried nothing but an error notify.
"""
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.tree import DecisionTreeClassifier

NOTIFY_ONLY_MAX = 144          # derived above, not fitted
NO_PROPOSAL_CHOSEN = "14"
LABELS = ["F0-success", "F1-ike-proposal", "F2-child-proposal", "F3-ts-mismatch",
          "F4-auth-fail", "F5-pfs-mismatch", "F6-unreachable"]
FEATURES = ["n_init_req", "n_init_resp", "init_resp_noprop", "n_auth_req", "n_auth_resp",
            "auth_req_len", "auth_resp_len", "n_ccsa_req", "n_ccsa_resp", "ccsa_req_len",
            "ccsa_resp_len", "n_info", "n_esp", "init_retransmits"]


def extract(pcap: Path, initiator_prefix="10.10.1.") -> dict:
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-T", "fields", "-e", "ip.src", "-e", "ip.len", "-e", "ip.proto",
         "-e", "isakmp.exchangetype", "-e", "isakmp.flags", "-e", "isakmp.messageid",
         "-e", "isakmp.notify.msgtype"],
        capture_output=True, text=True, check=True).stdout
    f = dict.fromkeys(FEATURES, 0)
    seen_init_msgs = Counter()
    for line in out.splitlines():
        src, iplen, proto, exch, flags, msgid, notify = (line.split("\t") + [""] * 7)[:7]
        if proto == "50":
            f["n_esp"] += 1
            continue
        if not exch:
            continue
        is_init = src.startswith(initiator_prefix)
        is_resp = bool(int(flags or "0", 16) & 0x20)
        n = int(iplen)
        if exch == "34":
            if not is_resp:
                f["n_init_req"] += 1
                seen_init_msgs[msgid] += 1
            else:
                f["n_init_resp"] += 1
                if NO_PROPOSAL_CHOSEN in (notify or "").split(","):
                    f["init_resp_noprop"] = 1
        elif exch == "35":
            if not is_resp:
                f["n_auth_req"] += 1; f["auth_req_len"] = max(f["auth_req_len"], n)
            else:
                f["n_auth_resp"] += 1; f["auth_resp_len"] = max(f["auth_resp_len"], n)
        elif exch == "36":
            if is_init and not is_resp:
                f["n_ccsa_req"] += 1; f["ccsa_req_len"] = max(f["ccsa_req_len"], n)
            elif is_resp:
                f["n_ccsa_resp"] += 1
                f["ccsa_resp_len"] = n if f["ccsa_resp_len"] == 0 else min(f["ccsa_resp_len"], n)
        elif exch == "37":
            f["n_info"] += 1
    f["init_retransmits"] = sum(c - 1 for c in seen_init_msgs.values())
    return f


def rules(f: dict) -> str:
    """Fixed before seeing data; see the module docstring for thresholds."""
    if f["n_init_req"] > 0 and f["n_init_resp"] == 0:
        return "F6-unreachable"
    if f["init_resp_noprop"]:
        return "F1-ike-proposal"
    if f["n_auth_resp"] and f["auth_resp_len"] <= NOTIFY_ONLY_MAX:
        return "F4-auth-fail"
    if f["n_ccsa_req"] and f["n_ccsa_resp"] and f["ccsa_resp_len"] <= NOTIFY_ONLY_MAX:
        return "F5-pfs-mismatch"
    if f["n_esp"] > 0:
        return "F0-success"
    # IKE SA up, child failed, no ESP: F2 and F3 predicted indistinguishable (P-e).
    return "CHILD-FAIL(F2|F3)"


def main():
    cap = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures/exp06r2")
    res = Path(sys.argv[2] if len(sys.argv) > 2 else "results")
    res.mkdir(parents=True, exist_ok=True)

    rows = []
    for gt in sorted(cap.glob("*.groundtruth.json")):
        g = json.loads(gt.read_text())
        pcap = gt.with_name(gt.name.replace(".groundtruth.json", ".pcap"))
        if not pcap.exists() or pcap.stat().st_size == 0:
            continue
        rows.append({"arm": g["arm"], "rep": g["rep"], "label": g["designed_label"],
                     "t2_log": g["charon_log_T2"], **extract(pcap)})
    if not rows:
        sys.exit("no captures")

    y = np.array([r["label"] for r in rows])
    X = np.array([[r[k] for k in FEATURES] for r in rows], dtype=float)
    reps = np.array([r["rep"] for r in rows])

    # --- 1. RULES (no fitting) ---
    rule_pred = np.array([rules(r) for r in rows])
    rule_pred7 = np.where(rule_pred == "CHILD-FAIL(F2|F3)", "F2-child-proposal", rule_pred)
    merge = lambda a: np.where(np.isin(a, ["F2-child-proposal", "F3-ts-mismatch"]), "CHILD-FAIL(F2|F3)", a)

    # --- 2. TREE, leave-one-repetition-out ---
    tree_pred = np.empty_like(y)
    for rep in sorted(set(reps)):
        tr, te = reps != rep, reps == rep
        clf = DecisionTreeClassifier(random_state=0).fit(X[tr], y[tr])
        tree_pred[te] = clf.predict(X[te])

    def score(pred, truth, labels):
        return {"macro_f1": round(float(f1_score(truth, pred, labels=labels, average="macro", zero_division=0)), 4),
                "accuracy": round(float((pred == truth).mean()), 4),
                "confusion": {"labels": labels,
                              "matrix": confusion_matrix(truth, pred, labels=labels).tolist()}}

    labels6 = [l for l in LABELS if l not in ("F2-child-proposal", "F3-ts-mismatch")] + ["CHILD-FAIL(F2|F3)"]
    report = {
        "n_captures": len(rows), "reps": sorted(set(int(r) for r in reps)),
        "rules_7class": score(rule_pred7, y, LABELS),
        "rules_6class_F2F3_merged": score(merge(rule_pred), merge(y), labels6),
        "tree_7class_LORO": score(tree_pred, y, LABELS),
        "tree_6class_F2F3_merged_LORO": score(merge(tree_pred), merge(y), labels6),
    }

    # --- P-e: is there ANY feature that differs between F2 and F3? ---
    f2 = [tuple(r[k] for k in FEATURES) for r in rows if r["label"] == "F2-child-proposal"]
    f3 = [tuple(r[k] for k in FEATURES) for r in rows if r["label"] == "F3-ts-mismatch"]
    report["P-e_F2_vs_F3"] = {
        "F2_distinct_feature_vectors": sorted(set(f2)), "F3_distinct_feature_vectors": sorted(set(f3)),
        "overlap": bool(set(f2) & set(f3)),
        "features_that_ever_differ": [FEATURES[i] for i in range(len(FEATURES))
                                      if {v[i] for v in f2} != {v[i] for v in f3}],
    }
    report["per_arm_feature_summary"] = {
        lab: {k: sorted({r[k] for r in rows if r["label"] == lab}) for k in FEATURES} for lab in LABELS}
    report["t2_confirmation"] = {r["arm"] + f"-rep{r['rep']}": [l for l in r["t2_log"] if "notify" in l or "established" in l][:3] for r in rows}

    (res / "exp06r2_results.json").write_text(json.dumps(report, indent=2))
    print(f"captures: {len(rows)}  reps: {report['reps']}")
    for k in ("rules_7class", "rules_6class_F2F3_merged", "tree_7class_LORO", "tree_6class_F2F3_merged_LORO"):
        print(f"{k:32} macroF1={report[k]['macro_f1']:.3f} acc={report[k]['accuracy']:.3f}")
    print("P-e overlap F2/F3:", report["P-e_F2_vs_F3"]["overlap"],
          "| features that ever differ:", report["P-e_F2_vs_F3"]["features_that_ever_differ"])
    print("rules confusion (7-class):")
    for lab, row in zip(LABELS, report["rules_7class"]["confusion"]["matrix"]):
        print(f"  {lab:20} {row}")


if __name__ == "__main__":
    main()
