#!/bin/bash
# T-057: run one arm of the encapsulation lab (docker-compose.encap.yml) -
# same procedure as run_arm.sh (keyless router capture on the alice side,
# varied-size ICMP through the tunnel, T2 ground truth from swanctl + XFRM),
# with the lab's own container names and an IPv4 or IPv6 target.
#
# Usage: run_encap.sh <arm-name> <peer-address> [initiator]
#   initiator  alice (default) or bob, e.g. EXP-13's cloud-initiated arm
#   CAP_SUBDIR captures sub-directory (default encap; EXP-13 uses cloud)
# Output: testbed/captures/$CAP_SUBDIR/<arm>.pcap + <arm>.groundtruth.json
set -euo pipefail

ARM="${1:?usage: run_encap.sh <arm> <peer-address>}"
PEER="${2:?usage: run_encap.sh <arm> <peer-address>}"
INIT="${3:-alice}"
SUB="${CAP_SUBDIR:-encap}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/$SUB"
mkdir -p "$OUT"
PCAP="/captures/$SUB/${ARM}.pcap"
PING="ping"; [[ "$PEER" == *:* ]] && PING="ping -6"

docker exec sih26e-alice swanctl --terminate --ike "$ARM" >/dev/null 2>&1 || true
docker exec sih26e-bob swanctl --terminate --ike "$ARM" >/dev/null 2>&1 || true
sleep 1
# eth0 only: each forwarded packet crosses it exactly once (see run_arm.sh).
docker exec -d sih26e-router bash -c "rm -f $PCAP; tcpdump -i eth0 -w $PCAP '(ip proto 50) or (ip6 proto 50) or udp port 500 or udp port 4500' >/tmp/tcpdump-${ARM}.log 2>&1"
sleep 1
docker exec "sih26e-$INIT" swanctl --initiate --child "$ARM" 2>&1 | tail -2

SIZES="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 20 24 28 32 48 64 96 128 192 256 384 512 768 1024 1200 1400"
for s in $SIZES; do
    docker exec sih26e-alice $PING -c 2 -i 0.05 -s "$s" -W1 "$PEER" >/dev/null 2>&1 || true
done
sleep 1

python3 - "$OUT/${ARM}.groundtruth.json" "$ARM" <<'PYEOF'
import json, sys, subprocess, datetime
out_path, arm = sys.argv[1], sys.argv[2]
run = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
json.dump({
    "arm": arm,
    "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "alice_list_sas": run("docker exec sih26e-alice swanctl --list-sas 2>&1"),
    "bob_list_sas": run("docker exec sih26e-bob swanctl --list-sas 2>&1"),
    "alice_xfrm_state": run("docker exec sih26e-alice ip xfrm state 2>&1"),
    "note": "T2/T3 ground truth from swanctl and kernel XFRM on the endpoint, never from the analyzer.",
}, open(out_path, "w"), indent=2)
PYEOF

for _ in 1 2 3 4 5; do
    docker exec sih26e-router pkill -INT tcpdump >/dev/null 2>&1 || true
    sleep 1
    docker exec sih26e-router pgrep tcpdump >/dev/null 2>&1 || break
done
sleep 1
echo "=== [$ARM] done: $OUT/${ARM}.pcap ==="
