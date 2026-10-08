"""EXP-49 addendum A: A and D at 10^5 packets, interleaved, so the same load hits both. Writes results/confound.json."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bench  # noqa: E402
import gen  # noqa: E402

work = os.path.abspath(sys.argv[1])
os.makedirs(work, exist_ok=True)
rows = []
for rep in range(3):
    for scn, caplen in (("A", 80), ("D", 1400)):
        p = os.path.join(work, f"c-{scn}.pcap")
        truth = gen.gen(p, 100_000, caplen=caplen)
        res = bench.run_child(p)
        rows.append({"scenario": scn, "rep": rep + 1, "load_avg_1m": os.getloadavg()[0], "wall_s": res["wall_s"], "exact": res["esp_in_records"] == truth["esp_packets"]})
        print(rows[-1], flush=True)
        os.remove(p)
med = lambda s: sorted(r["wall_s"] for r in rows if r["scenario"] == s)[1]
out = {"rows": rows, "median_wall_s": {"A": med("A"), "D": med("D")}, "D_over_A": med("D") / med("A")}
json.dump(out, open(os.path.join(HERE, "results", "confound.json"), "w"), indent=1)
print(out["median_wall_s"], out["D_over_A"])
