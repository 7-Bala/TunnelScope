#!/bin/bash
# T-083 live end-to-end: the router (keyless sensor) writes a new capture file
# every WIN seconds into testbed/captures/live/; `tunnelscope serve
# --live-follow testbed/captures/live` (or `tunnelscope live --follow ...`)
# analyses each closed window. Phase 1: a strong tunnel (MODP-3072, AES-GCM)
# carries messaging + web traffic for STRONG_S seconds. Phase 2: the SAME
# tunnel (same name, same addresses) is re-negotiated with MODP-1024 /
# AES-128 / SHA-1 and carries traffic for WEAK_S seconds: a downgrade the live
# view must flag.
#
# Usage: run_live_demo.sh [WIN=15] [STRONG_S=75] [WEAK_S=45]
set -uo pipefail
WIN="${1:-15}"; STRONG_S="${2:-75}"; WEAK_S="${3:-45}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A=sih26-alice-pq; B=sih26-bob-pq; R=sih26-router
a=10.10.1.240; b=10.10.2.240
mkdir -p "$HERE/../captures/live"
docker exec $A ip addr add $a/32 dev eth0 2>/dev/null; docker exec $B ip addr add $b/32 dev eth0 2>/dev/null
docker cp "$HERE/tgen.py" $A:/tmp/tgen.py >/dev/null; docker cp "$HERE/tgen.py" $B:/tmp/tgen.py >/dev/null
docker exec $B pkill -f "tgen.py server $b" >/dev/null 2>&1; docker exec -d $B python3 /tmp/tgen.py server $b

load() {   # $1 = strong | weak
    for s in alice bob; do
        c=$([ $s = alice ] && echo $A || echo $B)
        docker cp "$HERE/../configs/live/$s-$1.conf" $c:/tmp/live.conf >/dev/null
        docker exec $c swanctl --load-all --file /tmp/live.conf >/dev/null 2>&1
    done
}
traffic() {   # $1 = seconds
    docker exec $A sh -c "timeout $(( $1 + 5 )) python3 /tmp/tgen.py client messaging $b $1 7 $a & timeout $(( $1 + 5 )) python3 /tmp/tgen.py client web $b $1 8 $a; wait" >/dev/null 2>&1
}

docker exec $R pkill -f "live/w-" >/dev/null 2>&1
docker exec -d $R bash -c "tcpdump -i eth0 -G $WIN -w '/captures/live/w-%s.pcap' 'host $a and host $b' >/dev/null 2>&1"
echo "sensor: rotating ${WIN}s capture files into testbed/captures/live/"

docker exec $A swanctl --terminate --ike live >/dev/null 2>&1; sleep 1
load strong; docker exec $A swanctl --initiate --child live --timeout 10000 2>&1 | tail -1
echo "phase 1: strong tunnel (MODP-3072, AES-GCM-256), traffic for ${STRONG_S}s"; traffic "$STRONG_S"

docker exec $A swanctl --terminate --ike live >/dev/null 2>&1; sleep 1
load weak; docker exec $A swanctl --initiate --child live --timeout 10000 2>&1 | tail -1
echo "phase 2: same tunnel re-negotiated WEAK (MODP-1024, AES-128, SHA-1), traffic for ${WEAK_S}s"; traffic "$WEAK_S"

sleep $(( WIN + 2 ))
docker exec $R pkill -f "live/w-" >/dev/null 2>&1
docker exec $A swanctl --terminate --ike live >/dev/null 2>&1
echo "done: $(ls "$HERE/../captures/live" | wc -l | tr -d ' ') window file(s) written"
