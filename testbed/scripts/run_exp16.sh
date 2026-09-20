#!/bin/bash
# EXP-16 capture harness. Pre-registration: experiments/exp16-real-apps-cross-impl/PREREG.md
#
#   part A  REAL applications (Chromium, OpenSSH/SFTP, swaks+Postfix, XMPP,
#           ffmpeg RTP, ping) between apps-a and apps-b, which sit BEHIND the
#           strongSwan gateways, so their traffic crosses the tunnel.
#   part B  the synthetic generator's 8 classes through LIBRESWAN 5.4
#           (cross-implementation transfer test; never used for training).
# Capture stays at the keyless router, headers only (-s 96); each session is
# reduced to the committed per-packet table (t, dir, len).
#
# Usage: run_exp16.sh [A|B|AB] [reps=4] [duration_s=20]
set -uo pipefail
PART="${1:-AB}"; REPS="${2:-4}"; DUR="${3:-20}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp16"; mkdir -p "$OUT"
R=sih26-router
CLASSES="web video bulk interactive email messaging voip icmp"

stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }

reduce() {   # $1 tag, $2 "out" source address
    tshark -r "$OUT/$1.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null \
      | awk -v a="$2" 'BEGIN{OFS=","; print "t","dir","len"} {print $1, ($2==a?"out":"in"), $3}' \
      | gzip -9 > "$OUT/$1.pkts.csv.gz"
    local npk sha
    npk=$(($(gzip -dc "$OUT/$1.pkts.csv.gz" | wc -l) - 1))
    sha=$(shasum -a 256 "$OUT/$1.pcap" | cut -d' ' -f1)
    echo "$1,$3,$4,$5,$6,$npk,$sha" >> "$OUT/manifest.csv"
    echo "=== $1 packets=$npk"
}

if [[ "$PART" == *A* ]]; then
    bash "$HERE/apps_server_setup.sh" >/dev/null 2>&1
    docker cp "$HERE/apps_client.py" sih26-apps-a:/tmp/apps_client.py >/dev/null
    for s in alice bob; do
        docker cp "$HERE/../configs/exp16/$s.conf" "sih26-$s-pq:/tmp/e16.conf" >/dev/null
        docker exec "sih26-$s-pq" swanctl --load-all --file /tmp/e16.conf >/dev/null 2>&1
    done
    docker exec sih26-alice-pq swanctl --list-sas --ike e16 2>/dev/null | grep -q INSTALLED \
      || docker exec sih26-alice-pq swanctl --initiate --child e16 --timeout 10000 >/dev/null 2>&1
    for rep in $(seq 1 "$REPS"); do
        for cls in $CLASSES; do
            tag="exp16-real-$cls-rep$rep"
            [ -s "$OUT/$tag.pkts.csv.gz" ] && continue
            seed=$((16000 + rep * 100 + ${#cls}))
            docker exec $R pkill tcpdump >/dev/null 2>&1
            docker exec -d $R bash -c "rm -f /captures/exp16/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp16/$tag.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"
            sleep 1
            docker exec sih26-apps-a python3 /tmp/apps_client.py "$cls" 10.10.2.50 "$DUR" "$seed" >/dev/null 2>&1
            sleep 1; stop_capture
            reduce "$tag" 10.10.1.20 real "$cls" "$rep" "$seed"
        done
    done
fi

if [[ "$PART" == *B* ]]; then
    A=sih26-lsw-a; B=sih26-lsw-b
    for k in $(seq 1 10); do
        docker exec $A ip addr add "10.10.1.$((30+k))/32" dev eth0 2>/dev/null
        docker exec $B ip addr add "10.10.2.$((30+k))/32" dev eth0 2>/dev/null
    done
    for c in $A $B; do docker exec $c ipsec whack --listen >/dev/null 2>&1; docker exec $c ipsec add e7-gcm256 >/dev/null 2>&1; done
    docker cp "$HERE/tgen.py" $A:/tmp/tgen.py >/dev/null; docker cp "$HERE/tgen.py" $B:/tmp/tgen.py >/dev/null
    docker exec $B pkill -f "tgen.py server" >/dev/null 2>&1
    docker exec -d $B python3 /tmp/tgen.py server 10.10.2.32
    docker exec $A ipsec down e7-gcm256 >/dev/null 2>&1; sleep 1
    docker exec $A ipsec up e7-gcm256 >/dev/null 2>&1; sleep 1
    for rep in $(seq 1 "$REPS"); do
        for cls in $CLASSES; do
            tag="exp16-lsw-$cls-rep$rep"
            [ -s "$OUT/$tag.pkts.csv.gz" ] && continue
            seed=$((17000 + rep * 100 + ${#cls}))
            docker exec $R pkill tcpdump >/dev/null 2>&1
            docker exec -d $R bash -c "rm -f /captures/exp16/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp16/$tag.pcap 'ip proto 50 and host 10.10.1.32 and host 10.10.2.32' >/dev/null 2>&1"
            sleep 1
            docker exec $A timeout $((DUR + 10)) python3 /tmp/tgen.py client "$cls" 10.10.2.32 "$DUR" "$seed" 10.10.1.32 >/dev/null 2>&1
            sleep 1; stop_capture
            reduce "$tag" 10.10.1.32 lsw "$cls" "$rep" "$seed"
        done
    done
fi
echo "done: $(ls "$OUT"/*.pkts.csv.gz 2>/dev/null | wc -l | tr -d ' ') sessions"
