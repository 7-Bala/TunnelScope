#!/bin/bash
# EXP-07 capture harness: Libreswan 5.4 <-> Libreswan 5.4 through the keyless
# router. Pre-registration: research/registers/EXPERIMENT-REGISTER.md ("EXP-07").
#
# Per arm: tear down, capture (filtered to the arm's aliases), bring the tunnel
# up, send the same ICMP size sweep as run_arm.sh, and for the PFS arms force
# two Child-SA rekeys. Output layout mirrors the strongSwan captures so the
# EXP-01..04 analysis code can be pointed at it.
# Usage: run_exp07.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp07"; mkdir -p "$OUT"
A=sih26-lsw-a; B=sih26-lsw-b
SIZES="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 20 24 28 32 48 64 96 128 192 256 384 512 768 1024 1200 1400"
ARMS="e7-gcm128 e7-gcm256 e7-cbc128 e7-cbc256 e7-chacha e7-ctr128 e7-pfs-off e7-pfs-on e7-classical e7-pq"

k_of() { python3 -c "import json;print(json.load(open('$HERE/../configs/exp07/arms.json'))['$1']['k'])"; }

for k in $(seq 1 10); do
    docker exec $A ip addr add "10.10.1.$((30+k))/32" dev eth0 2>/dev/null || true
    docker exec $B ip addr add "10.10.2.$((30+k))/32" dev eth0 2>/dev/null || true
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
    k=$(k_of "$n"); a="10.10.1.$((30+k))"; b="10.10.2.$((30+k))"
    echo "=== $n ($a <-> $b) ==="
    for m in $ARMS; do docker exec $A ipsec down "$m" >/dev/null 2>&1; done
    sleep 1
    docker exec sih26-router pkill tcpdump >/dev/null 2>&1 || true
    docker exec -d sih26-router bash -c "rm -f /captures/exp07/$n.pcap; tcpdump -i eth0 -w /captures/exp07/$n.pcap 'host $a and host $b and (ip proto 50 or udp port 500 or udp port 4500)' >/dev/null 2>&1"
    sleep 1
    docker exec $A timeout 30 ipsec up "$n" > "$OUT/$n.up.log" 2>&1
    for s in $SIZES; do docker exec $A ping -c 2 -i 0.05 -W1 -s "$s" -I "$a" "$b" >/dev/null 2>&1 || true; done
    case "$n" in e7-pfs-*)
        for _ in 1 2; do docker exec $A ipsec whack --name "$n" --rekey-child >> "$OUT/$n.up.log" 2>&1; sleep 2; done ;;
    esac
    sleep 1; stop_capture
    docker exec $A ipsec trafficstatus > "$OUT/$n.trafficstatus.txt" 2>&1 || true
    python3 - "$OUT/$n.groundtruth.json" "$n" "$OUT/$n.up.log" "$HERE/../configs/exp07/arms.json" <<'PY'
import json, sys
out, n, uplog, arms = sys.argv[1:5]
json.dump({"arm": n, "implementation": "libreswan-5.4-5.fc46 (NSS 3.127)",
           "configured": json.load(open(arms))[n],
           "pluto_log_T2": [l for l in open(uplog).read().splitlines() if "established" in l or "rekeyed" in l or "INTERMEDIATE" in l],
           "note": "T2 ground truth = configured arm + pluto's own log of what it negotiated."},
          open(out, "w"), indent=2)
PY
done
for m in $ARMS; do docker exec $A ipsec down "$m" >/dev/null 2>&1; done
echo "done: $(ls "$OUT"/*.pcap | wc -l) captures"
