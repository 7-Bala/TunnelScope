#!/bin/bash
# PQ-arm variant of run_arm.sh: drives alice-pq/bob-pq instead of alice/bob.
# Usage: run_pq_arm.sh <arm-name> [suffix]
set -euo pipefail
ARM="${1:?usage: run_pq_arm.sh <arm-name> [suffix]}"
SUFFIX="${2:-}"
TAG="${ARM}${SUFFIX:+-$SUFFIX}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURES_DIR="$HERE/../captures"
mkdir -p "$CAPTURES_DIR"

PCAP="/captures/${TAG}.pcap"
HOST_PCAP="$CAPTURES_DIR/${TAG}.pcap"
GT_JSON="$CAPTURES_DIR/${TAG}.groundtruth.json"

echo "=== [$TAG] terminating any prior SA ==="
docker exec sih26-alice-pq swanctl --terminate --ike "$ARM" >/dev/null 2>&1 || true
sleep 1

echo "=== [$TAG] starting capture on router (eth0) ==="
docker exec -d sih26-router bash -c "rm -f $PCAP; tcpdump -i eth0 -w $PCAP 'ip proto 50 or udp port 500 or udp port 4500' >/tmp/tcpdump-${TAG}.log 2>&1"
sleep 1

echo "=== [$TAG] initiating IKE/CHILD SA ==="
docker exec sih26-alice-pq swanctl --initiate --child "$ARM" 2>&1 | tail -10

echo "=== [$TAG] sending varied-size ICMP probes through the tunnel ==="
SIZES="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 20 24 28 32 48 64 96 128 192 256 384 512 768 1024 1200 1400"
for s in $SIZES; do
    docker exec sih26-alice-pq ping -c 2 -i 0.05 -s "$s" -W1 10.10.2.20 >/dev/null 2>&1 || true
done

sleep 1
docker exec sih26-router pkill -INT tcpdump >/dev/null 2>&1 || true
sleep 1
docker cp sih26-router:"$PCAP" "$HOST_PCAP" 2>&1 || echo "WARNING: pcap copy failed"

python3 - "$GT_JSON" "$ARM" "$TAG" <<'PYEOF'
import json, sys, subprocess, datetime
out_path, arm, tag = sys.argv[1], sys.argv[2], sys.argv[3]
def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
record = {
    "arm": arm, "tag": tag,
    "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "alice_list_sas": run("docker exec sih26-alice-pq swanctl --list-sas 2>&1"),
    "bob_list_sas": run("docker exec sih26-bob-pq swanctl --list-sas 2>&1"),
    "alice_xfrm_state": run("docker exec sih26-alice-pq ip xfrm state 2>&1"),
    "note": "T2/T3 ground truth from strongSwan vici/swanctl and kernel XFRM state on the endpoint — never from analyzer inference.",
}
with open(out_path, "w") as f:
    json.dump(record, f, indent=2)
print(f"Wrote ground truth to {out_path}")
PYEOF
echo "=== [$TAG] done. pcap=$HOST_PCAP ==="
