#!/bin/bash
# Run one experiment arm (one swanctl connection/child name), capture traffic
# at the genuine third-party vantage point (`router`, no keys, no endpoint
# config), send a controlled sequence of varied-size ICMP probes through the
# tunnel, and record ground truth (swanctl SA state + XFRM state on both
# endpoints) alongside the capture.
#
# Usage: run_arm.sh <arm-name> [pcap-suffix]
#
# Output: testbed/captures/<arm-name>[-<suffix>].pcap
#         testbed/captures/<arm-name>[-<suffix>].groundtruth.json
set -euo pipefail

ARM="${1:?usage: run_arm.sh <arm-name> [suffix]}"
SUFFIX="${2:-}"
TAG="${ARM}${SUFFIX:+-$SUFFIX}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURES_DIR="$HERE/../captures"
mkdir -p "$CAPTURES_DIR"

PCAP="/captures/${TAG}.pcap"
HOST_PCAP="$CAPTURES_DIR/${TAG}.pcap"
GT_JSON="$CAPTURES_DIR/${TAG}.groundtruth.json"

echo "=== [$TAG] terminating any prior SA for this arm ==="
docker exec sih26-alice swanctl --terminate --ike "$ARM" >/dev/null 2>&1 || true
sleep 1

echo "=== [$TAG] starting capture on router (eth0 only — see NOTE below) ==="
# NOTE: capture on eth0 ONLY, not `-i any`. router forwards between eth0
# (net-a, alice side) and eth1 (net-b, bob side); a packet in either
# direction crosses eth0 exactly once (as ingress-from-alice or as
# egress-to-alice), so this yields each wire packet exactly once. Verified
# empirically: `-i any` double-counted every packet (saw 264 ESP frames
# where swanctl reported 66+66=132 packets sent) because Linux's `any`
# pseudo-interface reports a forwarded packet on both the ingress and
# egress real interface.
docker exec -d sih26-router bash -c "rm -f $PCAP; tcpdump -i eth0 -w $PCAP 'ip proto 50 or udp port 500 or udp port 4500' >/tmp/tcpdump-${TAG}.log 2>&1"
sleep 1

echo "=== [$TAG] initiating IKE/CHILD SA ==="
docker exec sih26-alice swanctl --initiate --child "$ARM" 2>&1 | tail -5

echo "=== [$TAG] sending varied-size ICMP probes through the tunnel ==="
# Sizes chosen to straddle AES block-size (16B) and AEAD 4-byte alignment
# boundaries: 0,1,...,16 covers every residue class for a 16-byte-aligned
# cipher; 32..1400 in steps of 32 gives broad coverage for larger payloads.
SIZES="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 20 24 28 32 48 64 96 128 192 256 384 512 768 1024 1200 1400"
for s in $SIZES; do
    docker exec sih26-alice ping -c 2 -i 0.05 -s "$s" -W1 10.10.2.10 >/dev/null 2>&1 || true
done

sleep 1
echo "=== [$TAG] capturing ground truth (T2/T3: swanctl + xfrm state) ==="
ALICE_SAS=$(docker exec sih26-alice swanctl --list-sas --raw 2>/dev/null || true)
BOB_SAS=$(docker exec sih26-bob swanctl --list-sas --raw 2>/dev/null || true)
ALICE_XFRM=$(docker exec sih26-alice ip -j xfrm state 2>/dev/null || docker exec sih26-alice ip xfrm state 2>/dev/null || true)
ALICE_XFRM_POLICY=$(docker exec sih26-alice ip xfrm policy 2>/dev/null || true)

echo "=== [$TAG] stopping capture ==="
docker exec sih26-router pkill -INT tcpdump >/dev/null 2>&1 || true
sleep 1
docker cp sih26-router:"$PCAP" "$HOST_PCAP" 2>&1 || echo "WARNING: pcap copy failed"

python3 - "$GT_JSON" "$ARM" "$TAG" <<'PYEOF'
import json, sys, subprocess, datetime
out_path, arm, tag = sys.argv[1], sys.argv[2], sys.argv[3]

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

record = {
    "arm": arm,
    "tag": tag,
    "captured_at_utc": datetime.datetime.utcnow().isoformat() + "Z",
    "alice_list_sas": run("docker exec sih26-alice swanctl --list-sas 2>&1"),
    "bob_list_sas": run("docker exec sih26-bob swanctl --list-sas 2>&1"),
    "alice_xfrm_state": run("docker exec sih26-alice ip xfrm state 2>&1"),
    "alice_xfrm_policy": run("docker exec sih26-alice ip xfrm policy 2>&1"),
    "note": "Ground truth is authoritative (T2/T3): read directly from strongSwan's "
            "vici/swanctl interface and the kernel XFRM state on the endpoint. It is "
            "NEVER derived from the analyzer's own inference — see DEC (no circular "
            "validation), 00-RESEARCH-PLAN/registers.",
}
with open(out_path, "w") as f:
    json.dump(record, f, indent=2)
print(f"Wrote ground truth to {out_path}")
PYEOF

echo "=== [$TAG] done. pcap=$HOST_PCAP groundtruth=$GT_JSON ==="
