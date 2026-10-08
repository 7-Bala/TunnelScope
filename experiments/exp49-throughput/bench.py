"""EXP-49 harness (bars and scenarios fixed in PREREG.md). Every measurement is a fresh Python process.

    python3 experiments/exp49-throughput/bench.py WORKDIR [--only A,B,C,D,H2,H3] [--quick]

Writes results/raw.jsonl (one line per run) and results/summary.json. The generated captures stay in WORKDIR (outside the repository) and are deleted after each run.
"""
import json
import os
import platform
import resource
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import gen  # noqa: E402

HANDSHAKE = os.path.join(REPO, "testbed", "captures", "exp15", "s-ecp256.pcap")


def child(pcap):
    """The measured run: report.analyze(pcap), the function the live window uses."""
    from tunnelscope.ingest import tshark
    from tunnelscope.report.report import analyze
    calls = []
    orig = tshark._run_fields

    def timed(*a, **k):
        t = time.perf_counter()
        try:
            return orig(*a, **k)
        finally:
            calls.append(time.perf_counter() - t)
    tshark._run_fields = timed
    t0 = time.perf_counter()
    a = analyze(pcap)
    wall = time.perf_counter() - t0
    summ = tshark.capture_summary(pcap)
    esp_records = [s["record"] for s in a["sas"] if getattr(s["record"], "_esp", [])]
    frames = set()
    n_in_records = ip_len = 0
    for r in esp_records:
        for p in r._esp:
            n_in_records += 1
            ip_len += p["ip_len"]
            frames.add(p["frame"])
    out = {"wall_s": wall, "tshark_s": sum(calls), "tshark_passes": len(calls), "n_sa_records": len(a["sas"]), "n_esp_records": len(esp_records),
           "esp_in_records": n_in_records, "esp_unique_frames": len(frames), "esp_ip_len_sum": ip_len, "n_esp_summary": summ["n_esp"],
           "truncated": bool(summ.get("capture_truncated")),
           "rss_python_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e6,          # bytes on macOS
           "rss_largest_tshark_mb": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1e6}
    print(json.dumps(out))


def run_child(pcap):
    r = subprocess.run([sys.executable, __file__, "--child", pcap], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": REPO}, cwd=REPO)
    if r.returncode != 0:
        return {"error": (r.stderr or "").strip().splitlines()[-1:] or ["exit %d" % r.returncode]}
    return json.loads(r.stdout.strip().splitlines()[-1])


def main():
    work = os.path.abspath(sys.argv[1])
    only = set((sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else "A,B,C,D,H2,H3").split(","))
    quick = "--quick" in sys.argv
    os.makedirs(work, exist_ok=True)
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    raw = open(os.path.join(HERE, "results", "raw.jsonl"), "a")
    summary = {"hardware": {"machine": platform.machine(), "mac": platform.mac_ver()[0], "python": platform.python_version(),
                            "cpu": subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip(),
                            "cores": os.cpu_count(), "ram_bytes": int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout),
                            "tshark": subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
                            "commit": subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()},
               "runs": []}

    def record(scn, n, rep, truth, res, extra=None):
        row = {"scenario": scn, "n": n, "rep": rep, "load_avg_1m": os.getloadavg()[0], "truth": truth, "result": res, **(extra or {})}
        if "error" not in res:
            row["pps"] = truth["esp_packets"] / res["wall_s"]
            row["file_mb_s"] = truth["file_bytes"] / 1e6 / res["wall_s"]
            row["represented_gbps"] = truth["sum_origlen"] * 8 / 1e9 / res["wall_s"]
            row["exact"] = (res["esp_in_records"] == truth["esp_packets"] and res["esp_unique_frames"] == truth["esp_packets"]
                            and res["esp_ip_len_sum"] == truth["sum_ip_len"] and res["n_esp_summary"] == truth["esp_packets"])
        raw.write(json.dumps(row) + "\n")
        raw.flush()
        summary["runs"].append(row)
        print(scn, n, rep, {k: row.get(k) for k in ("pps", "represented_gbps", "exact")}, res.get("wall_s"), res.get("rss_python_mb"), flush=True)

    plan = []
    for n, reps in ((10_000, 3), (100_000, 3), (1_000_000, 1), (3_000_000, 1)):
        plan.append(("A", n, reps, dict(pairs=1)))
    plan.append(("B", 1_000_000, 1, dict(pairs=1000)))
    plan.append(("C", 100_000, 3, dict(pairs=1, handshake=True)))
    plan.append(("D", 100_000, 3, dict(pairs=1, caplen=1400)))
    for scn, n, reps, kw in plan:
        if scn not in only or (quick and n > 100_000):
            continue
        for rep in range(1, reps + 1):
            p = os.path.join(work, f"{scn}-{n}.pcap")
            kw2 = {k: v for k, v in kw.items() if k != "handshake"}
            truth = gen.gen(p if not kw.get("handshake") else p + ".gen", n, **kw2)
            if kw.get("handshake"):
                subprocess.run(["mergecap", "-F", "pcap", "-w", p, HANDSHAKE, p + ".gen"], check=True)
                os.remove(p + ".gen")
                t = gen.classic_esp_truth(p)                      # independent of tshark: includes the 54 real ESP packets
                truth = {**truth, "esp_packets": t["esp_packets"], "sum_ip_len": t["sum_ip_len"], "file_bytes": os.path.getsize(p),
                         "sum_origlen": t["sum_origlen_all"]}
            res = run_child(p)
            record(scn, n, rep, truth, res)
            os.remove(p)

    if "H2" in only:
        p = os.path.join(work, "H2.pcap")
        truth = gen.gen(p, 1_000_000)
        r = subprocess.run([sys.executable, "-m", "tunnelscope.cli", "analyze", p], capture_output=True, text=True, cwd=REPO,
                           env={**os.environ, "PYTHONPATH": REPO, "TUNNELSCOPE_TSHARK_TIMEOUT": "2"})
        row = {"scenario": "H2", "n": 1_000_000, "returncode": r.returncode, "stdout_bytes": len(r.stdout), "stderr": r.stderr.strip()[-300:]}
        raw.write(json.dumps(row) + "\n")
        summary["runs"].append(row)
        print("H2", row, flush=True)
        os.remove(p)
    if "H3" in only:
        p = os.path.join(work, "H3.pcap")
        truth = gen.gen(p, 100_000)
        size = os.path.getsize(p)
        for name, cut in (("inside last packet", size - 7), ("inside last record header", size - 80 - 16 + 5)):
            q = os.path.join(work, "H3-cut.pcap")
            with open(p, "rb") as src, open(q, "wb") as dst:
                dst.write(src.read(cut))
            res = run_child(q)
            row = {"scenario": "H3", "cut": name, "whole_packets_before_cut": truth["esp_packets"] - 1, "result": res}
            raw.write(json.dumps(row) + "\n")
            summary["runs"].append(row)
            print("H3", name, res, flush=True)
            os.remove(q)
        os.remove(p)
    json.dump(summary, open(os.path.join(HERE, "results", "summary.json"), "w"), indent=1, sort_keys=True)


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--child":
        child(sys.argv[2])
    else:
        main()
