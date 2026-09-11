#!/usr/bin/env python3
"""EXP-07 — do EXP-01/02/03/04 hold on a second implementation (Libreswan 5.4)?

Pre-registration P7-1..P7-4d: research/registers/EXPERIMENT-REGISTER.md ("EXP-07").

Deliberately imports the SAME analysis functions used for the strongSwan runs,
so the only thing that changes is the implementation that produced the traffic.
Verdict per signal: HOLDS / HOLDS-IN-DIRECTION / IMPLEMENTATION-DEPENDENT / FAILS.
"""
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXP = HERE.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m


e01 = load("e01", EXP / "exp01-cipher-sieve/analyze.py")
e02 = load("e02", EXP / "exp02-negative-control/analyze.py")
e03 = load("e03", EXP / "exp03-pfs-signature/analyze.py")
e04 = load("e04", EXP / "exp04-pq-length-asymmetry/analyze.py")

LSW_FAMILY = {"e7-gcm128": "AES-GCM-16", "e7-gcm256": "AES-GCM-16", "e7-cbc128": "AES-CBC+HMAC-SHA256-128",
              "e7-cbc256": "AES-CBC+HMAC-SHA256-128", "e7-chacha": "ChaCha20-Poly1305",
              "e7-ctr128": "AES-CTR+HMAC-SHA256-128"}
# strongSwan reference results, from the committed EXP-01/03/04 result files
SS_SIEVE = json.loads((EXP / "exp01-cipher-sieve/results/exp01_results.json").read_text())["arms"]
SS_ARM = {"AES-GCM-16": "cs-aes256gcm16", "AES-CBC+HMAC-SHA256-128": "cs-aes256cbc-sha256",
          "ChaCha20-Poly1305": "cs-chacha20poly1305", "AES-CTR+HMAC-SHA256-128": "cs-aes128ctr-sha256"}


def main():
    cap = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures/exp07")
    res = Path(sys.argv[2] if len(sys.argv) > 2 else "results"); res.mkdir(parents=True, exist_ok=True)
    R = {"implementation": "libreswan-5.4-5.fc46 (NSS 3.127) <-> same", "verdicts": {}}

    # ---- P7-1: EXP-01 sieve ----
    sieve = {}
    for arm, fam in LSW_FAMILY.items():
        L = e01.extract_esp_content_lengths(cap / f"{arm}.pcap")
        s = e01.sieve(L)
        ss_set = SS_SIEVE[SS_ARM[fam]]["final_candidate_set"]
        sieve[arm] = {"n_esp": len(L), "final_candidates": s["final_candidates"],
                      "true_family_survived": fam in s["final_candidates"],
                      "same_set_as_strongswan": sorted(s["final_candidates"]) == sorted(ss_set)}
    ok = all(v["true_family_survived"] and v["same_set_as_strongswan"] and v["n_esp"] > 0 for v in sieve.values())
    R["exp01_sieve"] = sieve
    R["verdicts"]["P7-1 sieve"] = "HOLDS" if ok else "FAILS"

    # ---- P7-2: EXP-02 negative control ----
    nc = {}
    for lo, hi in (("e7-gcm128", "e7-gcm256"), ("e7-cbc128", "e7-cbc256")):
        ra, rb = e02.extract_fields(cap / f"{lo}.pcap"), e02.extract_fields(cap / f"{hi}.pcap")
        ex = e02.exact_set_comparison(ra, rb); clf = e02.classifier_test(ra, rb)
        nc[f"{lo} vs {hi}"] = {"identical_length_sets": ex["identical_sets"],
                               "symmetric_difference": ex["symmetric_difference"],
                               "classifier_mean_accuracy": round(clf["mean_accuracy"], 3)}
    R["exp02_negative_control"] = nc
    R["verdicts"]["P7-2 negative control"] = "HOLDS" if all(
        v["identical_length_sets"] and v["classifier_mean_accuracy"] <= 0.6 for v in nc.values()) else "FAILS"

    # ---- P7-3: EXP-03 PFS ----
    off = [r["ip_len"] for r in e03.extract_create_child_sa_sizes(cap / "e7-pfs-off.pcap")]
    on = [r["ip_len"] for r in e03.extract_create_child_sa_sizes(cap / "e7-pfs-on.pcap")]
    gap = (min(on) - max(off)) if on and off else None
    R["exp03_pfs"] = {"pfs_off_create_child_sa_sizes": sorted(off), "pfs_on_create_child_sa_sizes": sorted(on),
                      "min_gap_bytes": gap, "strongswan_gap_bytes": 256}
    R["verdicts"]["P7-3 PFS"] = ("HOLDS-IN-DIRECTION" if gap and gap > 0 and gap != 256 else
                                 "HOLDS" if gap == 256 else "FAILS (no rekey captured)" if gap is None else "FAILS")

    # ---- P7-4: EXP-04 PQ signals ----
    c = e04.analyze_capture(cap / "e7-classical.pcap", "e7-classical")
    p = e04.analyze_capture(cap / "e7-pq.pcap", "e7-pq")
    # Compare by ROLE, not by address. First run keyed this by ip.src and got an
    # empty delta (-> false "FAILS"): unlike EXP-04 on strongSwan, here the
    # classical and PQ arms use different alias pairs (.39 vs .40), so no
    # address is common to both. Initiators live on 10.10.1.x, responders on 10.10.2.x.
    role = lambda ip: "initiator" if ip.startswith("10.10.1.") else "responder"
    by_role = lambda d: {role(k): v for k, v in d.items()}
    cr, pr = by_role(c["signal2_ike_sa_init_sizes_by_src"]), by_role(p["signal2_ike_sa_init_sizes_by_src"])
    delta = {r: pr[r] - cr[r] for r in set(cr) & set(pr)}
    R_sizes = {"classical_ike_sa_init_by_role": cr, "pq_ike_sa_init_by_role": pr}
    R["exp04_pq"] = {"classical": c, "pq": p, "ike_sa_init_delta_bytes": delta, **R_sizes,
                     "strongswan_reference": {"delta_bytes": 16, "intermediate_msgs": "0 vs 3",
                                              "notify_16438": "PQ arm only", "fragmentation": "initiator 2, responder 1"}}
    R["verdicts"]["P7-4a IKE_INTERMEDIATE presence"] = (
        "HOLDS" if c["signal3_n_ike_intermediate_messages"] == 0 and p["signal3_n_ike_intermediate_messages"] > 0 else "FAILS")
    R["verdicts"]["P7-4b IKE_SA_INIT growth"] = (
        "HOLDS" if delta and all(v == 16 for v in delta.values()) else
        "HOLDS-IN-DIRECTION" if delta and all(v > 0 for v in delta.values()) else "FAILS")
    n_c, n_p = (c["signal1_intermediate_exchange_supported_notify_present"],
                p["signal1_intermediate_exchange_supported_notify_present"])
    R["verdicts"]["P7-4c notify 16438"] = ("TRACKS ADDKE (as in strongSwan)" if (not n_c and n_p) else
                                           f"IMPLEMENTATION-DEPENDENT (classical={n_c}, pq={n_p})")
    R["verdicts"]["P7-4d fragmentation pattern"] = (
        f"IMPLEMENTATION-DEPENDENT (libreswan IKE_INTERMEDIATE sizes by src: {p['signal4_ike_intermediate_sizes_by_src']})")

    (res / "exp07_results.json").write_text(json.dumps(R, indent=2))
    for k, v in R["verdicts"].items():
        print(f"{k:34} {v}")
    print("sieve sets:", {k: len(v["final_candidates"]) for k, v in sieve.items()})
    print("PFS sizes off/on:", R["exp03_pfs"]["pfs_off_create_child_sa_sizes"], R["exp03_pfs"]["pfs_on_create_child_sa_sizes"])
    print("IKE_SA_INIT delta:", delta, "| intermediate msgs:", c["signal3_n_ike_intermediate_messages"], "vs",
          p["signal3_n_ike_intermediate_messages"])


if __name__ == "__main__":
    main()
