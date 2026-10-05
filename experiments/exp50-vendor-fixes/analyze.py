"""EXP-50 Libreswan scorer (bars H2 of PREREG.md). Reads the captures and ground truth the harness wrote, runs TunnelScope on each capture,
writes results/summary-libreswan.json.   python3 experiments/exp50-vendor-fixes/analyze.py [label]
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, REPO)
from tunnelscope.assess.engine import assess_record, load_baselines  # noqa: E402
from tunnelscope.evidence.extract import build_records  # noqa: E402

CAP = os.path.join(REPO, "testbed", "captures", "exp50")
GT = os.path.join(HERE, "results", "ground-truth")
# rule -> (algorithm the weak state must show on Libreswan's own report, the one the fixed state must show)
DEVICE_STATE = {"RFC8221-AH-INTEG": ("HMAC_MD5_96", "HMAC_SHA2_256_128"), "RFC8221-ESP-3DES": ("3DES_CBC", "AES_GCM_16_256")}
ARMS = json.load(open(os.path.join(REPO, "testbed", "configs", "exp50", "arms.json")))


def verdicts(name):
    path = os.path.join(CAP, name + ".pcap")
    if not os.path.exists(path):
        return None
    recs = [r for r in build_records(path) if getattr(r, "_ike", []) or getattr(r, "_esp", []) or getattr(r, "_ah", [])]
    base = load_baselines()
    out = {}
    for r in recs:
        for v in assess_record(r, base):
            out.setdefault(v.rule_id, v.verdict)
    return {"n_records": len(recs), "verdicts": out}


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "libreswan"
    rules = {}
    for n, arm in ARMS.items():
        rules.setdefault(arm["rule"], {})[arm["state"]] = n
    out = {"rules": {}}
    for rule, pair in rules.items():
        row = {"arms": pair}
        for state in ("before", "after"):
            n = pair[state]
            g = json.load(open(os.path.join(GT, n + ".json"))) if os.path.exists(os.path.join(GT, n + ".json")) else {}
            v = verdicts(n)
            row[state] = {"up": g.get("up_rc") == 0, "ping_ok": all(g.get("ping_ok", {}).values()) and bool(g.get("ping_ok")),
                          "n_records": v and v["n_records"], "rule_verdict": v and v["verdicts"].get(rule),
                          "add_a": (g.get("add_a") or "")[-200:], "verdicts": v and v["verdicts"]}
        b, a = row["before"], row["after"]
        regress = sorted(k for k, x in (b["verdicts"] or {}).items() if x == "PASS" and (a["verdicts"] or {}).get(k) == "FAIL")   # PASS -> FAIL only
        row["reproduced"] = b["rule_verdict"] == "FAIL"
        row["fixed"] = a["rule_verdict"] == "PASS" and a["up"] and a["ping_ok"]
        row["regressions"] = regress
        row["pass"] = row["reproduced"] and row["fixed"] and not regress
        # rules the wire cannot decide (UNKNOWN before): the device's own algorithm report is the evidence (PREREG addendum A)
        dev = DEVICE_STATE.get(rule)
        if dev:
            gb = json.load(open(os.path.join(GT, pair["before"] + ".json")))
            ga = json.load(open(os.path.join(GT, pair["after"] + ".json")))
            row["device_state"] = {"before_has": dev[0] in gb["up_log"] + gb["status_a"], "after_has": dev[1] in ga["up_log"] + ga["status_a"],
                                   "before_lacks_after_alg": dev[1] not in gb["up_log"] + gb["status_a"], "expected": list(dev)}
            row["pass_device_state"] = bool(row["device_state"]["before_has"] and row["device_state"]["after_has"] and row["device_state"]["before_lacks_after_alg"]
                                            and not regress and row["after"]["up"] and row["after"]["ping_ok"])
        out["rules"][rule] = row
        print(f"{rule:26} before={b['rule_verdict']!s:15} up={b['up']!s:5} after={a['rule_verdict']!s:15} up={a['up']!s:5} ping={a['ping_ok']!s:5} regress={regress} PASS={row['pass']}")
    json.dump(out, open(os.path.join(HERE, "results", f"summary-{label}.json"), "w"), indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
