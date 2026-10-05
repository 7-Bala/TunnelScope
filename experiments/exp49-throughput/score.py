"""EXP-49 scorer: reads results/summary.json (written by bench.py), prints the tables and the verdict on each bar and prediction, writes results/scored.json.

    python3 experiments/exp49-throughput/score.py
"""
import json
import os
import statistics as st

HERE = os.path.dirname(os.path.abspath(__file__))
S = json.load(open(os.path.join(HERE, "results", "summary.json")))
runs = [r for r in S["runs"] if r["scenario"] in "ABCD" and len(r["scenario"]) == 1]
out = {"hardware": S["hardware"], "table": [], "bars": {}, "predictions": {}}


def med(rows, k):
    return st.median(r["result"][k] if k in r["result"] else r[k] for r in rows)


groups = {}
for r in runs:
    groups.setdefault((r["scenario"], r["n"]), []).append(r)
for (scn, n), rows in sorted(groups.items()):
    ok = [r for r in rows if "error" not in r["result"]]
    if not ok:
        out["table"].append({"scenario": scn, "n": n, "reps": len(rows), "error": rows[0]["result"]["error"]})
        continue
    wall = [r["result"]["wall_s"] for r in ok]
    row = {"scenario": scn, "n": n, "reps": len(ok), "wall_s_median": st.median(wall), "wall_s_min": min(wall), "wall_s_max": max(wall),
           "pps_median": st.median(r["pps"] for r in ok), "file_mb_s_median": st.median(r["file_mb_s"] for r in ok),
           "represented_gbps_median": st.median(r["represented_gbps"] for r in ok), "tshark_share": st.median(r["result"]["tshark_s"] / r["result"]["wall_s"] for r in ok),
           "tshark_passes": ok[0]["result"]["tshark_passes"], "rss_python_mb": max(r["result"]["rss_python_mb"] for r in ok),
           "rss_largest_tshark_mb": max(r["result"]["rss_largest_tshark_mb"] for r in ok), "load_avg_1m_before": [round(r["load_avg_1m"], 2) for r in ok],
           "exact": all(r["exact"] for r in ok), "file_mb": ok[0]["truth"]["file_bytes"] / 1e6}
    out["table"].append(row)
H1 = [(r["scenario"], r["n"], r["rep"]) for r in runs if "error" in r["result"] or not r.get("exact")]
out["bars"]["H1"] = {"pass": not H1 and bool(runs), "runs": len(runs), "failures": H1}
h2 = [r for r in S["runs"] if r["scenario"] == "H2"]
if h2:
    r = h2[0]
    out["bars"]["H2"] = {"pass": r["returncode"] != 0 and r["stdout_bytes"] == 0 and "timed out" in r["stderr"], "returncode": r["returncode"],
                         "stdout_bytes": r["stdout_bytes"], "stderr": r["stderr"]}
h3 = [r for r in S["runs"] if r["scenario"] == "H3"]
if h3:
    out["bars"]["H3"] = {"pass": all(("error" in r["result"] and "truncat" in str(r["result"]["error"]).lower()) or
                                     (r["result"].get("truncated") and r["result"].get("n_esp_summary") == r["whole_packets_before_cut"]) for r in h3),
                         "cases": [{"cut": r["cut"], "whole_packets_before_cut": r["whole_packets_before_cut"],
                                    "n_esp_summary": r["result"].get("n_esp_summary"), "esp_in_records": r["result"].get("esp_in_records"),
                                    "truncated": r["result"].get("truncated"), "error": r["result"].get("error")} for r in h3]}
A = {r["n"]: r for r in out["table"] if r["scenario"] == "A" and "error" not in r}
if 100_000 in A and 1_000_000 in A:
    per_pkt = lambda r: r["wall_s_median"] / r["n"]
    ratio = per_pkt(A[1_000_000]) / per_pkt(A[100_000])
    out["predictions"]["P1"] = {"held": 0.75 <= ratio <= 1.25, "per_packet_time_ratio_1e6_over_1e5": ratio}
pps_all = [r["pps_median"] for r in out["table"] if r["scenario"] == "A" and r["n"] >= 100_000 and "error" not in r]
if pps_all:
    out["predictions"]["P2"] = {"held": all(30_000 <= p <= 150_000 for p in pps_all), "pps": pps_all,
                                "represented_gbps": [r["represented_gbps_median"] for r in out["table"] if r["scenario"] == "A" and r["n"] >= 100_000 and "error" not in r]}
big = A.get(3_000_000) or A.get(1_000_000)
if big:
    kb = big["rss_python_mb"] * 1e3 / big["n"]
    out["predictions"]["P3"] = {"held": kb > 0.5 and (big["n"] != 3_000_000 or big["rss_python_mb"] > 1500), "kb_per_packet_at_largest": kb, "n": big["n"], "rss_python_mb": big["rss_python_mb"]}
C = next((r for r in out["table"] if r["scenario"] == "D" and "error" not in r), None)
if C and 100_000 in A:
    rel = C["wall_s_median"] / A[100_000]["wall_s_median"]
    out["predictions"]["P4"] = {"held": abs(rel - 1) <= 0.30, "full_over_headers_only_time_at_1e5": rel}
shares = [r["tshark_share"] for r in out["table"] if "error" not in r and r["n"] >= 100_000]
if shares:
    out["predictions"]["P5"] = {"held": all(s > 0.5 for s in shares), "tshark_share": shares}
# H5 (derived): the highest packet rate whose 30-second window is analysed in < 30 s, from the largest completed size that fits a straight line
if 1_000_000 in A:
    fit_pps = A[1_000_000]["pps_median"]
    out["bars"]["H5_derived"] = {"window_s": 30, "sustainable_pps_at_1e6_rate": fit_pps, "packets_per_30s_window": fit_pps * 30,
                                 "represented_gbps_at_1400B": fit_pps * 1400 * 8 / 1e9,
                                 "assumption": "windows analysed one after another in one process; per-packet cost as measured at 10^6 packets; memory for that window "
                                               f"(rss {A[1_000_000]['rss_python_mb']:.0f} MB) fits; not measured on a live interface"}
json.dump(out, open(os.path.join(HERE, "results", "scored.json"), "w"), indent=1, sort_keys=True)
print(json.dumps(out, indent=1, sort_keys=True))
