#!/bin/bash
# EXP-17 capture harness (network conditions). Pre-registration:
# experiments/exp17-network-conditions/PREREG.md  (committed BEFORE this is run).
#
#   Part A  synthetic 8 classes through strongSwan t-tun, profiles wan + lossy
#   Part C  IKE bring-ups under loss (captured whole), checked against swanctl
#   Part B  real applications through the e16 tunnel, profiles wan + lossy
# tc netem is applied on the router's egress on eth0 AND eth1 (both directions) and is ALWAYS removed on exit.
#
# Prerequisites:  cd testbed && docker compose up -d router alice-pq bob-pq apps-a apps-b
# Usage:          testbed/scripts/run_exp17.sh [reps=3] [duration_s=20]     (about 50 minutes)
# Output:         testbed/captures/exp17/  (*.pcap ignored by git; *.pkts.csv.gz + manifest.csv + ike/ tracked)
set -uo pipefail
REPS="${1:-3}"; DUR="${2:-20}"; PARTS="${PARTS:-ACB}"   # PARTS=B runs only part B, etc.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp17"; mkdir -p "$OUT/ike"
R=sih26-router; A=sih26-alice-pq; B=sih26-bob-pq
CLASSES="voip web bulk interactive video email messaging icmp"
REAL_CLASSES="web video bulk interactive email messaging voip icmp"
declare_profile() { case "$1" in wan) echo "delay 40ms 10ms loss 0.5%";; lossy) echo "delay 80ms 20ms loss 2%";; esac; }

impair() { for i in eth0 eth1; do docker exec $R tc qdisc replace dev $i root netem $(declare_profile "$1") || { echo "FATAL: tc failed"; exit 2; }; done
           echo ">>> profile $1 applied: $(docker exec $R tc qdisc show dev eth0 | head -1)"; }
clear_netem() { for i in eth0 eth1; do docker exec $R tc qdisc del dev $i root 2>/dev/null; done; }
trap 'clear_netem; docker exec $R pkill tcpdump >/dev/null 2>&1' EXIT
stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }
reduce() {   # tag out-address arm class rep seed
    tshark -r "$OUT/$1.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null \
      | awk -v a="$2" 'BEGIN{OFS=","; print "t","dir","len"} {print $1, ($2==a?"out":"in"), $3}' | gzip -9 > "$OUT/$1.pkts.csv.gz"
    local npk sha; npk=$(($(gzip -dc "$OUT/$1.pkts.csv.gz" | wc -l) - 1)); sha=$(shasum -a 256 "$OUT/$1.pcap" | cut -d' ' -f1)
    echo "$1,$3,$4,$5,$6,$npk,$sha" >> "$OUT/manifest.csv"; echo "=== $1 packets=$npk"
    # a real session that moved almost nothing means the app or its server did not work: say so loudly
    [ "$npk" -lt 30 ] && [ "$4" != icmp ] && echo "WARNING: $1 has only $npk packets, the application probably did not run"
}
apps_ready() {   # setup the real servers on apps-b and REFUSE to continue unless all four listen
    bash "$HERE/apps_server_setup.sh" > "$OUT/apps_setup.log" 2>&1
    for p in 443 22 25 5222; do
        docker exec sih26-apps-b sh -c "ss -lnt 2>/dev/null | grep -q ':$p '" \
          || { echo "FATAL: apps-b is not listening on port $p; see $OUT/apps_setup.log"; exit 4; }
    done
}
clear_netem

# ---------------------------------------------------------------- setup: exp15 config (Part A and C)
setup_exp15() {
    python3 "$HERE/gen_exp15_conf.py" >/dev/null
    for j in 0 1 2 3 4; do docker exec $A ip addr add "10.10.1.$((210+j))/32" dev eth0 2>/dev/null; docker exec $B ip addr add "10.10.2.$((210+j))/32" dev eth0 2>/dev/null; done
    docker cp "$HERE/../configs/exp15/alice.conf" $A:/tmp/exp15-alice.conf >/dev/null; docker cp "$HERE/../configs/exp15/bob.conf" $B:/tmp/exp15-bob.conf >/dev/null
    docker exec $A swanctl --load-all --file /tmp/exp15-alice.conf >/dev/null 2>&1; docker exec $B swanctl --load-all --file /tmp/exp15-bob.conf >/dev/null 2>&1
    docker cp "$HERE/tgen.py" $A:/tmp/tgen.py >/dev/null; docker cp "$HERE/tgen.py" $B:/tmp/tgen.py >/dev/null
    docker exec $B pkill -f "tgen.py server" >/dev/null 2>&1; docker exec -d $B python3 /tmp/tgen.py server 10.10.2.210
    docker exec $A swanctl --terminate --ike t-tun >/dev/null 2>&1; sleep 1
    docker exec $A swanctl --initiate --child t-tun --timeout 15000 >/dev/null 2>&1
    docker exec $A ping -c 2 -W 2 -I 10.10.1.210 10.10.2.210 >/dev/null 2>&1 || { echo "FATAL: t-tun does not carry traffic"; exit 3; }
}

partA() {
# ---------------------------------------------------------------- Part A
setup_exp15
for prof in wan lossy; do
    impair "$prof"
    for rep in $(seq 1 "$REPS"); do for cls in $CLASSES; do
        tag="exp17-$prof-syn-$cls-rep$rep"; [ -s "$OUT/$tag.pkts.csv.gz" ] && continue
        seed=$((17100 + rep * 100 + ${#cls}))
        docker exec $R pkill tcpdump >/dev/null 2>&1
        docker exec -d $R bash -c "rm -f /captures/exp17/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp17/$tag.pcap 'ip proto 50 and host 10.10.1.210 and host 10.10.2.210' >/dev/null 2>&1"; sleep 1
        docker exec $A timeout $((DUR + 15)) python3 /tmp/tgen.py client "$cls" 10.10.2.210 "$DUR" "$seed" 10.10.1.210 >/dev/null 2>&1
        sleep 1; stop_capture; reduce "$tag" 10.10.1.210 "$prof-syn" "$cls" "$rep" "$seed"
    done; done
    clear_netem
done

}
partC() {
# ---------------------------------------------------------------- Part C: IKE robustness under loss
for prof in wan lossy; do
    impair "$prof"
    for i in 1 2 3 4 5; do
        n="ike-$prof-$i"
        docker exec $A swanctl --terminate --ike t-tun >/dev/null 2>&1; sleep 2
        docker exec $R pkill tcpdump >/dev/null 2>&1
        docker exec -d $R bash -c "rm -f /captures/exp17/ike/$n.pcap; tcpdump -i eth0 -w /captures/exp17/ike/$n.pcap 'host 10.10.1.210 and host 10.10.2.210' >/dev/null 2>&1"; sleep 1
        r=$(docker exec $A swanctl --initiate --child t-tun --timeout 40000 2>&1 | tail -1)
        docker exec $A ping -c 4 -W 3 -I 10.10.1.210 10.10.2.210 >/dev/null 2>&1; sleep 2; stop_capture
        python3 - "$OUT/ike/$n.groundtruth.json" "$n" "$prof" "$r" <<'PY'
import json, subprocess, sys
out, name, prof, initiate = sys.argv[1:5]
run = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
json.dump({"arm": name, "profile": prof, "initiate_result": initiate,
           "alice_list_sas": run("docker exec sih26-alice-pq swanctl --list-sas --ike t-tun 2>&1"),
           "note": "T2 ground truth from swanctl on the endpoint, never from the analyzer."}, open(out, "w"), indent=2)
PY
        echo "=== $n: $r"
    done
    clear_netem
done

}
partB() {
# ---------------------------------------------------------------- Part B: real applications through e16
for s in alice bob; do docker cp "$HERE/../configs/exp16/$s.conf" "sih26-$s-pq:/tmp/e16.conf" >/dev/null; docker exec "sih26-$s-pq" swanctl --load-all --file /tmp/e16.conf >/dev/null 2>&1; done
apps_ready; docker cp "$HERE/apps_client.py" sih26-apps-a:/tmp/apps_client.py >/dev/null
docker exec $A swanctl --terminate --ike e16 >/dev/null 2>&1; sleep 1; docker exec $A swanctl --initiate --child e16 --timeout 15000 >/dev/null 2>&1
docker exec sih26-apps-a ping -c 2 -W 2 10.10.2.50 >/dev/null 2>&1 || { echo "FATAL: e16 does not carry traffic"; exit 3; }
for prof in wan lossy; do
    impair "$prof"
    for rep in $(seq 1 "$REPS"); do for cls in $REAL_CLASSES; do
        tag="exp17-$prof-real-$cls-rep$rep"; [ -s "$OUT/$tag.pkts.csv.gz" ] && continue
        seed=$((17200 + rep * 100 + ${#cls}))
        docker exec $R pkill tcpdump >/dev/null 2>&1
        docker exec -d $R bash -c "rm -f /captures/exp17/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp17/$tag.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"; sleep 1
        docker exec sih26-apps-a python3 /tmp/apps_client.py "$cls" 10.10.2.50 "$DUR" "$seed" >/dev/null 2>&1
        sleep 1; stop_capture; reduce "$tag" 10.10.1.20 "$prof-real" "$cls" "$rep" "$seed"
    done; done
    clear_netem
done
}
[[ "$PARTS" == *A* ]] && partA
[[ "$PARTS" == *C* ]] && { [[ "$PARTS" == *A* ]] || setup_exp15; partC; }
[[ "$PARTS" == *B* ]] && partB
echo "done: $(ls "$OUT"/*.pkts.csv.gz 2>/dev/null | wc -l | tr -d ' ') sessions, $(ls "$OUT"/ike/*.pcap 2>/dev/null | wc -l | tr -d ' ') IKE bring-ups"
