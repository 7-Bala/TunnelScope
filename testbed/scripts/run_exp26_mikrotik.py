"""EXP-26: run the pre-registered MikroTik RouterOS arms and capture the cable (keyless T0 vantage).

Needs the two VMs from testbed/mikrotik/boot.sh. Per arm: wipe IPsec config on both routers, apply the
arm, start QEMU filter-dump on VM A's cable NIC, push ICMP through the tunnel, read RouterOS's own
installed-SA / active-peer state as ground truth, stop the capture.

  .venv/bin/python testbed/scripts/run_exp26_mikrotik.py [ARM ...]      (default: all arms)
"""
import base64
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "captures" / "exp26"
REST = {"a": 8081, "b": 8082}
MONITOR_A = 4461
PSK = "IhtestlabSIH26160presharedkeydonotusehere"   # lab-only throwaway, never used outside testbed/
AUTH = "Basic " + base64.b64encode(b"admin:").decode()
WIRE = {"a": "10.99.0.1", "b": "10.99.0.2"}
LAN = {"a": "10.1.1.1/24", "b": "10.2.2.1/24"}
SIZES = (56, 200, 500, 1000, 1400)

# arm: (ike enc, hash=prf, initiator groups, responder groups, esp enc, esp auth, pfs, child lifetime, seconds of traffic)
ARMS = {
    "M1": ("aes-256", "sha256", "modp2048", "modp2048", "aes-256-gcm", "", "none", "30m", 20),
    "M2": ("aes-256", "sha512", "x25519", "x25519", "chacha20poly1305", "", "none", "30m", 20),
    "M3": ("aes-128", "sha256", "ecp256", "ecp256", "aes-128-gcm", "", "none", "30m", 20),
    "M4": ("3des", "sha1", "modp1024", "modp1024", "3des", "sha1", "none", "30m", 20),
    "M5": ("aes-256", "sha384", "ecp384", "ecp384", "aes-256-cbc", "sha256", "none", "30m", 20),
    "M6": ("aes-256", "sha256", "modp2048", "modp2048", "aes-256-cbc", "sha256", "ecp256", "30s", 100),
    "M7": ("aes-256", "sha256", "modp2048", "modp2048", "aes-256-cbc", "sha256", "none", "30s", 100),
    "M8": ("aes-256", "sha256", "modp1024,modp2048", "modp2048", "aes-256-gcm", "", "none", "30m", 20),
    "E1": ("aes-256", "sha256", "modp2048", "modp2048", "aes-256-gcm", "", "none", "30m", 20),
}


def ros(vm, method, path, body=None, timeout=120):
    req = urllib.request.Request(f"http://127.0.0.1:{REST[vm]}/rest/{path}", method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{vm} {method} {path} {body}: {e.code} {e.read().decode(errors='replace')}") from None


def monitor(cmd):
    with socket.create_connection(("127.0.0.1", MONITOR_A), timeout=10) as s:
        s.recv(4096)
        s.sendall((cmd + "\n").encode())
        time.sleep(0.5)
        return s.recv(4096).decode(errors="replace")


def wipe(vm):
    for path in ("ip/ipsec/policy", "ip/ipsec/identity", "ip/ipsec/peer", "ip/ipsec/profile", "ip/ipsec/proposal"):
        for item in ros(vm, "GET", path):
            if item.get("default") == "true" or item.get("dynamic") == "true":
                continue
            ros(vm, "DELETE", f"{path}/{item['.id']}")


def base_network():
    for vm in "ab":
        addrs = {a["address"] for a in ros(vm, "GET", "ip/address")}
        if not any(b["name"] == "lan" for b in ros(vm, "GET", "interface/bridge")):
            ros(vm, "PUT", "interface/bridge", {"name": "lan"})
        if f"{WIRE[vm]}/30" not in addrs:
            ros(vm, "PUT", "ip/address", {"address": f"{WIRE[vm]}/30", "interface": "ether2"})
        if LAN[vm] not in addrs:
            ros(vm, "PUT", "ip/address", {"address": LAN[vm], "interface": "lan"})


def configure(arm):
    enc, hsh, groups_a, groups_b, esp, auth, pfs, life, _ = ARMS[arm]
    for vm, peer_ip, groups, src, dst in (("a", WIRE["b"], groups_a, "10.1.1.0/24", "10.2.2.0/24"),
                                          ("b", WIRE["a"], groups_b, "10.2.2.0/24", "10.1.1.0/24")):
        wipe(vm)
        prof = {"name": "p26", "enc-algorithm": enc, "hash-algorithm": hsh, "prf-algorithm": hsh, "dh-group": groups}
        if arm == "E1":
            prof["ppk"] = "yes"
        ros(vm, "PUT", "ip/ipsec/profile", prof)
        ros(vm, "PUT", "ip/ipsec/proposal", {"name": "pr26", "enc-algorithms": esp, "auth-algorithms": auth,
                                              "pfs-group": pfs, "lifetime": life})
        peer = {"name": "peer26", "address": f"{peer_ip}/32", "profile": "p26", "exchange-mode": "ike2"}
        if vm == "b":
            peer["passive"] = "yes"
        ros(vm, "PUT", "ip/ipsec/peer", peer)
        ident = {"peer": "peer26", "auth-method": "pre-shared-key", "secret": PSK}
        if arm == "E1":
            ident["ppk-secret"] = PSK + "ppk"
        ros(vm, "PUT", "ip/ipsec/identity", ident)
        ros(vm, "PUT", "ip/ipsec/policy", {"src-address": src, "dst-address": dst, "tunnel": "yes",
                                           "peer": "peer26", "proposal": "pr26"})


def traffic(seconds):
    t_end, sent = time.time() + seconds, 0
    while time.time() < t_end:
        for size in SIZES:
            ros("a", "POST", "ping", {"address": "10.2.2.1", "src-address": "10.1.1.1", "size": str(size),
                                      "count": "2", "interval": "0.5"})
            sent += 2
    return sent


def run(arm):
    print(f"== {arm}", flush=True)
    pcap = OUT / f"mt-{arm.lower()}.pcap"
    OUT.mkdir(parents=True, exist_ok=True)
    pcap.unlink(missing_ok=True)
    configure(arm)
    monitor(f"object_add filter-dump,id=cap,netdev=link,file={pcap}")
    started = time.time()
    try:
        sent = traffic(ARMS[arm][-1])
        gt = {"installed_sa": ros("a", "GET", "ip/ipsec/installed-sa"),
              "active_peers": ros("a", "GET", "ip/ipsec/active-peers"),
              "responder_active_peers": ros("b", "GET", "ip/ipsec/active-peers")}
    finally:
        monitor("object_del cap")
    enc, hsh, groups_a, groups_b, esp, auth, pfs, life, secs = ARMS[arm]
    doc = {"capture": pcap.name, "experiment": "EXP-26", "arm": arm, "implementation": "MikroTik RouterOS 7.24.4 (CHR arm64)",
           "vantage": "T0: QEMU filter-dump on VM A's cable NIC (no keys)",
           "config": {"ike_enc": enc, "ike_hash_prf": hsh, "initiator_groups": groups_a, "responder_groups": groups_b,
                      "esp_enc": esp, "esp_auth": auth or None, "pfs_group": pfs, "child_lifetime": life, "ppk": arm == "E1"},
           "icmp_packets_sent": sent, "traffic_seconds": round(time.time() - started, 1),
           "ground_truth_source": "arm config (single offer) + RouterOS REST /ip/ipsec/installed-sa and active-peers (T2)",
           **gt}
    (OUT / f"mt-{arm.lower()}.groundtruth.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(f"   {pcap.name}: {pcap.stat().st_size} bytes, {len(gt['installed_sa'])} installed SAs", flush=True)


if __name__ == "__main__":
    base_network()
    for a in (sys.argv[1:] or list(ARMS)):
        try:
            run(a)
        except RuntimeError as e:
            print(f"   DROPPED {a}: {e}", flush=True)
            (OUT / f"mt-{a.lower()}.dropped.txt").write_text(str(e) + "\n")
