#!/bin/bash
# Capture a CHILD_SA rekey (CREATE_CHILD_SA exchange) for one already-established
# arm, to compare message sizes between PFS-on and PFS-off (EXP-03).
set -euo pipefail
ARM="${1:?usage: capture_rekey.sh <arm-name>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURES_DIR="$HERE/../captures"
mkdir -p "$CAPTURES_DIR"
PCAP="/captures/rekey-${ARM}.pcap"
HOST_PCAP="$CAPTURES_DIR/rekey-${ARM}.pcap"

echo "=== [$ARM] starting rekey capture ==="
docker exec -d sih26-router bash -c "rm -f $PCAP; tcpdump -i eth0 -w $PCAP 'ip proto 50 or udp port 500 or udp port 4500' >/tmp/tcpdump-rekey-${ARM}.log 2>&1"
sleep 1
echo "=== [$ARM] triggering CHILD_SA rekey ==="
docker exec sih26-alice swanctl --rekey --child "$ARM" 2>&1 | tail -15
sleep 1
docker exec sih26-router pkill -INT tcpdump >/dev/null 2>&1 || true
sleep 1
docker cp sih26-router:"$PCAP" "$HOST_PCAP"
echo "=== [$ARM] rekey capture saved to $HOST_PCAP ==="
