#!/bin/bash
# EXP-40 capture harness: Libreswan 5.4 <-> Libreswan 5.4, IKEv1 (Main and Aggressive Mode), through the keyless
# router. Pre-registration: experiments/exp40-ikev1-transforms/PREREG.md.
# Per arm: tear down, capture (filtered to the arm's address pair), bring the tunnel up, a few pings, stop.
# Ground truth = the arm as configured + pluto's own "ISAKMP SA established {...}" line.
# Usage: docker compose -f docker-compose.yml -f docker-compose.exp40.yml up -d router lsw-a lsw-b && run_exp40.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp40"; mkdir -p "$OUT"
A=sih26-lsw-a; B=sih26-lsw-b
ARMS=$(python3 -c "import json;print(' '.join(json.load(open('$HERE/../configs/exp40/arms.json'))))")
k_of() { python3 -c "import json;print(json.load(open('$HERE/../configs/exp40/arms.json'))['$1']['k'])"; }

for k in $(seq 1 8); do
    docker exec $A ip addr add "10.10.1.$((40+k))/32" dev eth0 2>/dev/null || true
    docker exec $B ip addr add "10.10.2.$((40+k))/32" dev eth0 2>/dev/null || true
done
for c in $A $B; do
    docker exec $c ipsec whack --listen >/dev/null 2>&1
    for n in $ARMS; do docker exec $c ipsec add "$n" >/dev/null 2>&1; done
done

stop_capture() {
    for _ in 1 2 3 4 5; do
        docker exec sih26-router pkill -INT tcpdump >/dev/null 2>&1 || true; sleep 1
        docker exec sih26-router pgrep tcpdump >/dev/null 2>&1 || return 0
    done
}

for n in $ARMS; do
    k=$(k_of "$n"); a="10.10.1.$((40+k))"; b="10.10.2.$((40+k))"
    echo "=== $n ($a <-> $b) ==="
    for m in $ARMS; do docker exec $A ipsec down "$m" >/dev/null 2>&1; done
    sleep 1
    docker exec sih26-router pkill tcpdump >/dev/null 2>&1 || true
    docker exec -d sih26-router bash -c "rm -f /captures/exp40/$n.pcap; tcpdump -i eth0 -w /captures/exp40/$n.pcap 'host $a and host $b and (ip proto 50 or udp port 500 or udp port 4500)'"
    sleep 1
    docker exec $A timeout 30 ipsec up "$n" > "$OUT/$n.up.log" 2>&1
    for _ in 1 2 3; do docker exec $A ping -c 2 -i 0.2 -W1 -I "$a" "$b" >/dev/null 2>&1 || true; done
    sleep 1; stop_capture
    docker exec $B bash -c "ipsec status 2>/dev/null; ipsec trafficstatus 2>/dev/null" > "$OUT/$n.status.txt" 2>&1 || true
    python3 - "$OUT/$n.groundtruth.json" "$n" "$OUT/$n.up.log" "$OUT/$n.status.txt" "$HERE/../configs/exp40/arms.json" <<'PY'
import json, sys
out, n, uplog, status, arms = sys.argv[1:6]
lines = open(uplog).read().splitlines() + open(status).read().splitlines()
json.dump({"arm": n, "implementation": "libreswan-5.4-5.fc46 (NSS 3.127)", "configured": json.load(open(arms))[n],
           "pluto_log_T2": [l for l in lines if "ISAKMP SA established" in l or "STATE_" in l or "NO_PROPOSAL" in l
                            or "established" in l or "no acceptable" in l.lower() or "ERROR" in l or "failed" in l.lower()],
           "note": "T2 ground truth = configured arm + pluto's own log of what it negotiated."}, open(out, "w"), indent=2)
PY
done
for m in $ARMS; do docker exec $A ipsec down "$m" >/dev/null 2>&1; done
echo "done: $(ls "$OUT"/*.pcap | wc -l) captures"
