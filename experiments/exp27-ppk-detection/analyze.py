"""EXP-27 scoring as PREREG.md defines it: TunnelScope's pq_ppk (and the IKE suite, H3) against strongSwan's
own logs (T2). Writes results/score.json.

  .venv/bin/python experiments/exp27-ppk-detection/analyze.py
"""
import json
from pathlib import Path

from tunnelscope.evidence.extract import build_records

ROOT = Path(__file__).resolve().parents[2]
CAP = ROOT / "testbed" / "captures" / "exp27"
RESULTS = Path(__file__).resolve().parent / "results"
ARMS = ["k0", "k1", "k2", "k3", "k4", "k5"]
SUITE = {"ike_encr": "AES-CBC-256", "ike_integ": "HMAC-SHA2-256-128", "ike_prf": "PRF-HMAC-SHA2-256",
         "ike_dh_group": "MODP-2048"}


def truth(arm):
    g = json.loads((CAP / f"ppk-{arm}.groundtruth.json").read_text())
    log = g["alice_log"] + "\n" + g["bob_log"]
    sa_init = [ln for ln in log.splitlines() if "IKE_SA_INIT" in ln and ("generating" in ln or "parsed" in ln)]
    req = any("request" in ln and "USE_PPK" in ln for ln in sa_init)
    resp = any("response" in ln and "USE_PPK" in ln for ln in sa_init)
    return {"established": "established" in g["initiate_output"], "ppk_used": "using PPK for PPK_ID" in log,
            "use_ppk_request": req, "use_ppk_response": resp,
            "expected_pq_ppk": "negotiated" if req and resp else "offered-not-negotiated" if req else "not-offered",
            "log_evidence": [ln.strip() for ln in log.splitlines()
                             if any(k in ln for k in ("using PPK for", "NO_PPK_AUTH notify", "didn't use PPK",
                                                      "but require", "AUTH_FAILED"))][:6]}


def main():
    RESULTS.mkdir(exist_ok=True)
    arms = []
    for arm in ARMS:
        (r,) = [r for r in build_records(str(CAP / f"ppk-{arm}.pcap")) if getattr(r, "_ike", [])]
        t, f = truth(arm), r.findings["pq_ppk"]
        claims_use = "used" in str(f.value) or ("not visible" not in (f.note or "") and f.value == "negotiated")
        suite = {k: r.findings[k].value for k in SUITE if k in r.findings}
        arms.append({"arm": arm.upper(), "truth": t,
                     "tunnelscope": {"pq_ppk": {"status": f.status.value, "value": f.value, "note": f.note},
                                     "pq_key_exchange": r.findings["pq_key_exchange"].value,
                                     "negotiation_outcome": r.findings["negotiation_outcome"].value, "suite": suite},
                     "pq_ppk_correct": f.value == t["expected_pq_ppk"], "claims_ppk_use": claims_use,
                     "suite_wrong": [k for k, v in SUITE.items() if suite.get(k) not in (v, None)]})
    by = {a["arm"]: a for a in arms}
    hyp = {"H1": {a: by[a]["pq_ppk_correct"] for a in ("K0", "K1", "K2", "K3")},
           "H2": {"K5_value": by["K5"]["tunnelscope"]["pq_ppk"]["value"], "K5_ppk_used_truth": by["K5"]["truth"]["ppk_used"],
                  "any_arm_claims_use": any(a["claims_ppk_use"] for a in arms)},
           "H3": {a["arm"]: a["suite_wrong"] for a in arms}}
    hyp["H1"]["pass"] = all(v for k, v in hyp["H1"].items() if k != "pass")
    hyp["H2"]["pass"] = (by["K5"]["pq_ppk_correct"] and not by["K5"]["truth"]["ppk_used"]
                         and not hyp["H2"]["any_arm_claims_use"])
    hyp["H3"]["pass"] = not any(a["suite_wrong"] for a in arms)
    (RESULTS / "score.json").write_text(json.dumps({"hypotheses": hyp, "arms": arms}, indent=1, default=str) + "\n")
    print(json.dumps(hyp, indent=1))
    for a in arms:
        print(a["arm"], "truth:", {k: a["truth"][k] for k in ("established", "ppk_used", "expected_pq_ppk")},
              "| TS:", a["tunnelscope"]["pq_ppk"]["value"], a["tunnelscope"]["negotiation_outcome"])


if __name__ == "__main__":
    main()
