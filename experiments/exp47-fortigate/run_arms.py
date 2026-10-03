"""EXP-47 capture harness (arms fixed in PREREG.md, 28d7ed0). Needs the lab of testbed/fortigate/lab.sh running
(FortiGate on serial tcp:4555, peer on tcp:4556, wire capture through the QEMU monitor).

    python3 experiments/exp47-fortigate/run_arms.py [--only S03,P01] [--out testbed/captures/exp47]

For each arm: configure both ends, record the wire, bring the tunnel up, send 40 pings through it, read the ground truth from
the FortiGate and from the peer, and write <arm>.pcap (local, not committed) and <arm>.json (committed) into --out.
The pre-shared key and the lab password are read from files outside the repository and are never written to any output.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO, "testbed", "fortigate"))
from fgt_console import Console  # noqa: E402

LAB = os.environ.get("FGT_LAB", os.path.expanduser("~/Documents/SIH-2026-fortilab"))
PSK = open(os.path.join(LAB, "lab-psk.txt")).read().strip()
DH_NAME = {2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 19: "ecp256", 20: "ecp384",
           21: "ecp521", 31: "curve25519", 28: "ecp256bp"}
# id: (ike, hash, dh, extra)  -- the arm table of PREREG.md
ARMS = {}
for i, (h, g) in enumerate([("md5", 2), ("sha1", 5), ("sha256", 14), ("sha384", 15), ("sha512", 16)], 1):
    ARMS[f"S{i:02d}"] = dict(ike=2, hash=h, dh=g)
for i, g in enumerate([19, 20, 21, 31, 28], 6):
    ARMS[f"S{i:02d}"] = dict(ike=2, hash="sha256", dh=g)
ARMS["V01"] = dict(ike=1, hash="sha256", dh=14, mode="main")
ARMS["V02"] = dict(ike=1, hash="sha256", dh=14, mode="aggressive")
ARMS["R01"] = dict(ike=2, hash="sha256", dh=14, role="responder")
ARMS["P01"] = dict(ike=2, hash="sha256", dh=14, keylife=120, record=330)
ARMS["P02"] = dict(ike=2, hash="sha256", dh=14, keylife=120, record=330, pfs=False)
ARMS["P03"] = dict(ike=2, hash="sha256", dh=19, keylife=120, record=330)
ARMS["X01"] = dict(ike=2, hash="sha256", dh=32, fail="no-proposal")
ARMS["X02"] = dict(ike=2, hash="sha256", dh=14, fail="bad-psk")


class Lab:
    def __init__(self):
        self.fg = Console()
        self.peer = Console(port=4556, prompt=rb"# $", autologin=False)
        self.peer.send("")
        self.peer.expect(rb"# $", limit=10)

    # ---- FortiGate CLI: every line must be accepted
    def fgt(self, cmds, quiet=False):
        for x in cmds:
            out = self.fg.run(x, limit=40)
            if re.search(r"(command parse error|Unknown action|invalid|not found|fail|error)", out, re.I) and "psksecret" not in x:
                raise RuntimeError(f"FortiGate rejected {x!r}: {out[:200]}")
        return None

    def fgt_out(self, cmd, limit=40):
        return self.fg.run(cmd, limit=limit)

    def sh(self, cmd, limit=40):
        return self.peer.run(cmd, limit=limit)

    # ---- one-time lab setup
    def base(self):
        self.fgt(["config system interface", 'edit "lo1"', "set vdom root", "set type loopback", "set ip 10.61.0.1 255.255.255.0",
                  "set allowaccess ping", "next", "end"])
        self.fgt(["config router static", "edit 1", "set dst 10.62.0.0 255.255.255.0", 'set device "tsc-p1"', "next", "end"])
        self.sh("ip addr show dev lo | grep -q 10.62.0.1 || ip addr add 10.62.0.1/24 dev lo")

    # ---- per-arm configuration
    def configure(self, a, arm):
        dh, hsh = a["dh"], a["hash"]
        pfs = a.get("pfs", True)
        p1 = ['config vpn ipsec phase1-interface', 'edit "tsc-p1"', 'set interface "port2"', f"set ike-version {a['ike']}",
              "set peertype any", "set net-device disable", f"set proposal des-{hsh}", f"set dhgrp {dh}",
              "set remote-gw 10.50.0.2", f"set psksecret {PSK}", "set keylife 86400", "unset localid"]
        if a["ike"] == 1:
            p1 += [f"set mode {a.get('mode', 'main')}"]
            if a.get("mode") == "aggressive":
                p1 += ['set localid "fgt"']
        p1 += ["next", "end"]
        self.fgt(p1)
        p2 = ["config vpn ipsec phase2-interface", 'edit "tsc-p2"', 'set phase1name "tsc-p1"', f"set proposal des-{hsh}",
              "set auto-negotiate disable", "set src-addr-type subnet", "set src-subnet 10.61.0.0 255.255.255.0",
              "set dst-addr-type subnet", "set dst-subnet 10.62.0.0 255.255.255.0",
              f"set keylifeseconds {a.get('keylife', 43200)}"]
        p2 += ["set pfs enable", f"set dhgrp {dh}"] if pfs else ["set pfs disable"]
        p2 += ["next", "end"]
        self.fgt(p2)
        psk = PSK + ("-WRONG" if a.get("fail") == "bad-psk" else "")
        ike_dh = DH_NAME.get(dh, "modp2048")                    # X01: group 32 has no strongSwan name; the peer offers modp2048
        esp = f"des-{hsh}-{ike_dh}" if pfs else f"des-{hsh}"
        conf = f"""connections {{
  fgt {{
    version = {a['ike']}
    local_addrs = 10.50.0.2
    remote_addrs = 10.50.0.1
    proposals = des-{hsh}-{ike_dh}
    {'aggressive = yes' if a.get('mode') == 'aggressive' else ''}
    local {{ auth = psk
      id = 10.50.0.2 }}
    remote {{ auth = psk
      id = {'fgt' if a.get('mode') == 'aggressive' else '10.50.0.1'} }}
    children {{ net {{ local_ts = 10.62.0.0/24
      remote_ts = 10.61.0.0/24
      esp_proposals = {esp}
      rekey_time = 3000
      mode = tunnel }} }}
  }}
}}
secrets {{ ike-fgt {{ secret = {psk} }} }}
"""
        self.sh("cat > /etc/swanctl/swanctl.conf <<'EOF'\n" + conf + "EOF")
        out = self.sh("swanctl --load-all 2>&1 | tail -3", limit=30)
        if "successfully loaded" not in out:
            raise RuntimeError(f"peer config not loaded: {out[:300]}")

    def clear(self):
        self.sh("swanctl --terminate --ike fgt --force 2>&1 | tail -1", limit=30)
        self.fg.run("diagnose vpn ike gateway clear name tsc-p1", limit=15)
        time.sleep(3)

    def established(self):
        out = self.sh("swanctl --list-sas 2>&1", limit=20)
        return "ESTABLISHED" in out and "INSTALLED" in out, out

    def pings(self):
        self.fgt(["execute ping-options reset", "execute ping-options source 10.61.0.1", "execute ping-options data-size 56",
                  "execute ping-options repeat-count 28"])
        a = self.fgt_out("execute ping 10.62.0.1", limit=60)
        self.fgt(["execute ping-options data-size 1000", "execute ping-options repeat-count 12"])
        b = self.fgt_out("execute ping 10.62.0.1", limit=60)
        self.fgt_out("execute ping-options reset")
        return {"small": re.findall(r"(\d+) packets received", a), "large": re.findall(r"(\d+) packets received", b)}


def run_arm(lab, arm, out_dir):
    a = ARMS[arm]
    print(f"--- {arm} {a}", flush=True)
    lab.clear()
    lab.configure(a, arm)
    cap = f"exp47-{arm}"
    subprocess.run([os.path.join(REPO, "testbed", "fortigate", "lab.sh"), "cap-start", cap], check=True, capture_output=True)
    t0 = time.time()
    try:
        if a.get("role") == "responder":
            lab.sh("swanctl --initiate --child net 2>&1 | tail -2", limit=40)
        else:
            lab.fgt_out("diagnose vpn tunnel up tsc-p2", limit=15)
        ok, sas = False, ""
        for _ in range(25):
            time.sleep(2)
            ok, sas = lab.established()
            if ok:
                break
        ping = lab.pings() if ok else None
        if ok and a.get("record"):
            end = t0 + a["record"]
            while time.time() < end:                           # keep the tunnel busy so a rekey is not skipped as idle
                time.sleep(20)
                lab.fgt(["execute ping-options source 10.61.0.1", "execute ping-options repeat-count 3"])
                lab.fgt_out("execute ping 10.62.0.1", limit=20)
                lab.fgt_out("execute ping-options reset")
        gt = {
            "fortigate_ike_gateway": lab.fgt_out("diagnose vpn ike gateway list name tsc-p1", limit=30),
            "fortigate_tunnel": lab.fgt_out("diagnose vpn tunnel list name tsc-p1", limit=30),
            "peer_sas": lab.sh("swanctl --list-sas 2>&1", limit=20),
            "peer_log": lab.sh("grep -iE 'no proposal|AUTHENTICATION_FAILED|NO_PROPOSAL|retransmit|timed out|giving up' /var/log/messages 2>/dev/null | tail -5", limit=15),
        }
    finally:
        time.sleep(2)
        subprocess.run([os.path.join(REPO, "testbed", "fortigate", "lab.sh"), "cap-stop", cap], check=True, capture_output=True)
    os.makedirs(out_dir, exist_ok=True)
    src = os.path.join(LAB, "cap", cap + ".pcap")
    dst = os.path.join(out_dir, f"{arm}.pcap")
    subprocess.run(["cp", src, dst], check=True)
    rec = {"arm": arm, "params": a, "established": ok, "pings": ping, "seconds": round(time.time() - t0), "ground_truth": gt}
    json.dump(rec, open(os.path.join(out_dir, f"{arm}.json"), "w"), indent=1, sort_keys=True)
    print(f"    established={ok} pcap={os.path.getsize(dst)} bytes pings={ping}", flush=True)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only")
    ap.add_argument("--out", default=os.path.join(REPO, "testbed", "captures", "exp47"))
    args = ap.parse_args()
    lab = Lab()
    lab.base()
    for arm in (args.only.split(",") if args.only else ARMS):
        run_arm(lab, arm, args.out)


if __name__ == "__main__":
    main()
