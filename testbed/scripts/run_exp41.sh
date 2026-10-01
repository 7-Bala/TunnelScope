#!/bin/bash
# EXP-41 capture harness (lab C). Pre-registration: experiments/exp41-lab-c/PREREG.md
# Per tunnel configuration (gcm, cbc) and repetition, each of the 8 classes runs for DUR seconds behind the gateways; the keyless
# router captures ESP headers (-s 96); the pcap is reduced to a committed per-packet table (t, dir, len) and hashed in manifest.csv.
# Usage: run_exp41.sh [reps=2] [duration_s=60]
set -uo pipefail
REPS="${1:-2}"; DUR="${2:-60}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp41"; mkdir -p "$OUT"
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

bash "$HERE/labc_gen.sh" setup >/dev/null 2>&1
for cfg in gcm cbc; do
    id=e41g; [ "$cfg" = cbc ] && id=e41c
    for s in alice bob; do
        docker exec sih26-$s-pq swanctl --terminate --ike e41g >/dev/null 2>&1; docker exec sih26-$s-pq swanctl --terminate --ike e41c >/dev/null 2>&1
        docker cp "$HERE/../configs/exp41/$s-$cfg.conf" "sih26-$s-pq:/tmp/e41.conf" >/dev/null
        docker exec "sih26-$s-pq" swanctl --load-all --file /tmp/e41.conf >/dev/null 2>&1
    done
    docker exec sih26-alice-pq swanctl --initiate --child $id --timeout 15000 >/dev/null 2>&1
    docker exec sih26-alice-pq swanctl --list-sas > "$OUT/$cfg.swanctl.txt" 2>&1
    grep -q INSTALLED "$OUT/$cfg.swanctl.txt" || { echo "FATAL: $cfg tunnel not installed"; exit 4; }
    for rep in $(seq 1 "$REPS"); do
        # fixed per-(config, rep) shuffle so no class always follows the same neighbour
        order=$(python3 -c "import random,sys; c='${CLASSES[*]}'.split(); random.Random('$cfg$rep').shuffle(c); print(' '.join(c))")
        for cls in $order; do
            tag="exp41-$cfg-$cls-rep$rep"
            [ -s "$OUT/$tag.pkts.csv.gz" ] && continue
            docker exec $R pkill tcpdump >/dev/null 2>&1
            docker exec -d $R bash -c "rm -f /captures/exp41/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp41/$tag.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"
            sleep 1
            bash "$HERE/labc_gen.sh" run "$cls" "$DUR" >/dev/null 2>&1
            sleep 2; stop_capture
            reduce "$tag" "$cfg" "$cls" "$rep"
            sleep 3
        done
    done
done
echo "done: $(ls "$OUT"/*.pkts.csv.gz | wc -l) tables"
