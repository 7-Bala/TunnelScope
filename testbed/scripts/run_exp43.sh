#!/bin/bash
# EXP-43 capture harness (lab D). Pre-registration: experiments/exp43-lab-d/PREREG.md
# Per tunnel configuration (gcm, cbc) and repetition, each of the 8 classes runs for DUR seconds behind the gateways; the keyless
# router captures ESP headers (-s 96); the pcap is reduced to a committed per-packet table (t, dir, len) and hashed in manifest.csv.
# Usage: run_exp43.sh [reps=2] [duration_s=60]
set -uo pipefail
REPS="${1:-2}"; DUR="${2:-60}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp43"; mkdir -p "$OUT"
R=sih26-router
CLASSES=(bulk web messaging interactive video voip email icmp)

stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }

reduce() {   # $1 tag, $2 config, $3 class, $4 rep
    tshark -r "$OUT/$1.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null \
      | awk -v a="10.10.1.20" 'BEGIN{OFS=","; print "t","dir","len"} {print $1, ($2==a?"out":"in"), $3}' | gzip -9 > "$OUT/$1.pkts.csv.gz"
    local npk sha
    npk=$(($(gzip -dc "$OUT/$1.pkts.csv.gz" | wc -l) - 1)); sha=$(shasum -a 256 "$OUT/$1.pcap" | cut -d' ' -f1)
    [ -s "$OUT/manifest.csv" ] || echo "tag,config,class,rep,packets,pcap_sha256" > "$OUT/manifest.csv"
    echo "$1,$2,$3,$4,$npk,$sha" >> "$OUT/manifest.csv"
    echo "=== $1 packets=$npk"
}

bash "$HERE/labd_gen.sh" setup >/dev/null 2>&1
# a delayed, slightly lossy path, both directions (pre-registered for lab D)
for dev in eth0 eth1; do docker exec $R tc qdisc replace dev $dev root netem delay 15ms 5ms loss 0.2% >/dev/null 2>&1; done
docker exec $R tc qdisc show dev eth0 > "$OUT/netem.txt" 2>&1
for cfg in chacha sha384; do
    id=e43p; [ "$cfg" = sha384 ] && id=e43s
    for s in alice bob; do
        docker exec sih26-$s-pq swanctl --terminate --ike e43p >/dev/null 2>&1; docker exec sih26-$s-pq swanctl --terminate --ike e43s >/dev/null 2>&1
        docker cp "$HERE/../configs/exp43/$s-$cfg.conf" "sih26-$s-pq:/tmp/e41.conf" >/dev/null
        docker exec "sih26-$s-pq" swanctl --load-all --file /tmp/e41.conf >/dev/null 2>&1
    done
    docker exec sih26-alice-pq swanctl --initiate --child $id --timeout 15000 >/dev/null 2>&1
    docker exec sih26-alice-pq swanctl --list-sas > "$OUT/$cfg.swanctl.txt" 2>&1
    grep -q INSTALLED "$OUT/$cfg.swanctl.txt" || { echo "FATAL: $cfg tunnel not installed"; exit 4; }
    for rep in $(seq 1 "$REPS"); do
        # fixed per-(config, rep) shuffle so no class always follows the same neighbour
        order=$(python3 -c "import random,sys; c='${CLASSES[*]}'.split(); random.Random('$cfg$rep').shuffle(c); print(' '.join(c))")
        for cls in $order; do
            tag="exp43-$cfg-$cls-rep$rep"
            [ -s "$OUT/$tag.pkts.csv.gz" ] && continue
            docker exec $R pkill tcpdump >/dev/null 2>&1
            docker exec -d $R bash -c "rm -f /captures/exp43/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp43/$tag.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"
            sleep 1
            bash "$HERE/labd_gen.sh" run "$cls" "$DUR" >/dev/null 2>&1
            sleep 2; stop_capture
            reduce "$tag" "$cfg" "$cls" "$rep"
            sleep 3
        done
    done
done
echo "done: $(ls "$OUT"/*.pkts.csv.gz | wc -l) tables"
