"""EXP-50 Libreswan harness (arms and bars fixed in PREREG.md). Needs the lab up:

    cd testbed && python3 scripts/gen_exp50_conf.py && docker compose -f docker-compose.yml -f docker-compose.exp50.yml up -d --force-recreate router lsw-a lsw-b
    python3 experiments/exp50-vendor-fixes/run_libreswan.py [--only x50-v207193-before,...]

Per arm: add the connection on both ends, capture on the keyless router, bring the tunnel up from A, send pings through it, read Libreswan's own
state as ground truth, write <arm>.pcap (local) and <arm>.json (committed) into testbed/captures/exp50/ and results/ground-truth/.
"""
import argparse
import json
import os
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CONF = os.path.join(REPO, "testbed", "configs", "exp50", "arms.json")
CAP = os.path.join(REPO, "testbed", "captures", "exp50")
GT = os.path.join(HERE, "results", "ground-truth")
A, B, R = "sih26-lsw-a", "sih26-lsw-b", "sih26-router"


def dx(c, cmd, timeout=60):
    r = subprocess.run(["docker", "exec", c, "bash", "-c", cmd], capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    args = ap.parse_args()
    arms = json.load(open(CONF))
    names = args.only.split(",") if args.only else sorted(arms, key=lambda n: arms[n]["k"])
    os.makedirs(CAP, exist_ok=True)
    os.makedirs(GT, exist_ok=True)
    for n in arms:                                  # every arm's alias pair first, then ONE listen, so pluto sees them all (as run_exp07.sh does)
        dx(A, f"ip addr add {arms[n]['a']}/32 dev eth0 2>/dev/null; true")
        dx(B, f"ip addr add {arms[n]['b']}/32 dev eth0 2>/dev/null; true")
    for c in (A, B):
        dx(c, "ipsec whack --listen >/dev/null 2>&1; true")
    for n in names:
        arm = arms[n]
        a, b = arm["a"], arm["b"]
        print(f"=== {n} ({a} <-> {b}) rule {arm['rule']} {arm['state']}", flush=True)
        added = {c: dx(c, f"ipsec add {n}")[1] for c in (A, B)}
        for attempt in range(3):                       # a capture that is empty although the tunnel came up is a harness fault: redo the arm
            dx(R, "pkill tcpdump >/dev/null 2>&1; true")
            dx(A, f"ipsec down {n} >/dev/null 2>&1; true")
            time.sleep(1)
            subprocess.run(["docker", "exec", "-d", R, "bash", "-c",
                            f"rm -f /captures/exp50/{n}.pcap; tcpdump -U -i eth0 -w /captures/exp50/{n}.pcap 'host {a} and host {b} and (ip proto 50 or ip proto 51 or udp port 500 or udp port 4500)' >/dev/null 2>&1"],
                           check=True)
            for _ in range(10):
                if dx(R, "pgrep tcpdump")[0] == 0:
                    break
                time.sleep(0.5)
            time.sleep(1.5)
            t0 = time.time()
            rc_up, up = dx(A, f"timeout 40 ipsec up {n}", timeout=60)
            ping = {}
            if "established" in up.lower():
                for size in (56, 200, 1000):
                    rc, out = dx(A, f"ping -c 5 -i 0.1 -W 1 -s {size} -I {a} {b}")
                    ping[str(size)] = "0% packet loss" in out
                time.sleep(1)
            for _ in range(5):
                dx(R, "pkill -INT tcpdump >/dev/null 2>&1; true")
                time.sleep(1)
                if dx(R, "pgrep tcpdump")[0] != 0:
                    break
            npk = dx(R, f"tcpdump -nr /captures/exp50/{n}.pcap 2>/dev/null | wc -l")[1].strip()
            if npk.isdigit() and int(npk) > 0 or rc_up != 0:
                break
        replace_rc, replace_out = (None, "")
        if rc_up == 0:                                    # the template's reload line, on the running device
            replace_rc, replace_out = dx(A, f"ipsec replace {n}")
        rec = {"arm": n, "rule": arm["rule"], "state": arm["state"], "up_rc": rc_up, "up_log": up[-1500:], "ping_ok": ping,
               "add_a": added[A][-600:], "add_b": added[B][-600:], "seconds": round(time.time() - t0), "capture_attempts": attempt + 1,
               "capture_packets": npk, "replace_rc": replace_rc, "replace_out": replace_out[-200:],
               "status_a": dx(A, f"ipsec status | grep -E '{n}' | head -12")[1][-1500:],
               "trafficstatus_a": dx(A, "ipsec trafficstatus")[1][-800:]}
        json.dump(rec, open(os.path.join(GT, f"{n}.json"), "w"), indent=1, sort_keys=True)
        print(f"    up_rc={rc_up} ping={ping}", flush=True)
        dx(A, f"ipsec down {n} >/dev/null 2>&1; true")


if __name__ == "__main__":
    main()
