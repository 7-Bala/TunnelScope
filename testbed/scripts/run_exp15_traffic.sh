#!/bin/bash
# EXP-15 part A: traffic-class sessions for the 8-class classifier (and EXP-14's
# transport-mode floor). Same harness as run_exp05.sh: long-lived SAs, fixed-
# seed shuffled schedule, keyless-router capture per session, reduced to a
# per-packet table (t, dir, len) that is committed; pcaps hashed, not committed.
# Pre-registration: experiments/exp15-traffic-classes-suites-ah/PREREG.md.
#
# Usage: run_exp15_traffic.sh [reps=4] [duration_s=20]
set -uo pipefail
REPS="${1:-4}"; DUR="${2:-20}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp15/traffic"; mkdir -p "$OUT"
A=sih26-alice-pq; B=sih26-bob-pq; R=sih26-router
CLASSES="voip web bulk interactive video email messaging icmp"
arm_j() { case "$1" in tun) echo 0;; tfc) echo 1;; tra) echo 2;; mux) echo 3;; cbc) echo 4;; esac; }

docker cp "$HERE/tgen.py" $A:/tmp/tgen.py >/dev/null; docker cp "$HERE/tgen.py" $B:/tmp/tgen.py >/dev/null
docker exec $B pkill -f "tgen.py server" >/dev/null 2>&1 || true
for j in 0 1 2 3 4; do docker exec -d $B python3 /tmp/tgen.py server "10.10.2.$((210+j))"; done
sleep 1
for arm in tun tfc tra mux cbc; do
    docker exec $A swanctl --list-sas --ike "t-$arm" 2>/dev/null | grep -q INSTALLED \
      || docker exec $A swanctl --initiate --child "t-$arm" --timeout 10000 >/dev/null 2>&1
done

[ -s "$OUT/schedule.txt" ] || python3 - "$REPS" "$CLASSES" > "$OUT/schedule.txt" <<'PY'
import random, sys
reps, classes = int(sys.argv[1]), sys.argv[2].split()
rows = []
for r in range(1, reps + 1):
    for arm in ("tun", "tfc", "tra"):
        for c in classes:
            rows.append((arm, c, r))
    for pair in ("voip+web", "video+interactive", "email+messaging", "bulk+icmp"):
        rows.append(("mux", pair, r))
for r in (1, 2):
    for c in classes:
        rows.append(("cbc", c, r))
random.Random(20260920).shuffle(rows)
for i, (arm, c, r) in enumerate(rows):
    print(arm, c, r, 15000 + i)
PY

stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }

while read -r arm cls rep seed <&3; do
    tag="exp15-$arm-${cls/+/_}-rep$rep"
    if [ -s "$OUT/$tag.pkts.csv.gz" ]; then continue; fi
    j=$(arm_j "$arm"); a="10.10.1.$((210+j))"; b="10.10.2.$((210+j))"
    docker exec $R pkill tcpdump >/dev/null 2>&1 || true
    docker exec -d $R bash -c "rm -f /captures/exp15/traffic/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp15/traffic/$tag.pcap 'ip proto 50 and host $a and host $b' >/dev/null 2>&1"
    sleep 1
    if [ "$arm" = mux ]; then
        c1=${cls%+*}; c2=${cls#*+}
        docker exec $A sh -c "timeout $((DUR+10)) python3 /tmp/tgen.py client $c1 $b $DUR $seed $a & timeout $((DUR+10)) python3 /tmp/tgen.py client $c2 $b $DUR $((seed+100000)) $a; wait" >/dev/null 2>&1
    else
        docker exec $A timeout $((DUR+10)) python3 /tmp/tgen.py client "$cls" "$b" "$DUR" "$seed" "$a" >/dev/null 2>&1
    fi
    sleep 1; stop_capture
    tshark -r "$OUT/$tag.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null \
      | awk -v a="$a" 'BEGIN{OFS=","; print "t","dir","len"} {print $1, ($2==a?"out":"in"), $3}' \
      | gzip -9 > "$OUT/$tag.pkts.csv.gz"
    sha=$(shasum -a 256 "$OUT/$tag.pcap" | cut -d' ' -f1)
    npk=$(($(gzip -dc "$OUT/$tag.pkts.csv.gz" | wc -l) - 1))
    echo "$tag,$arm,$cls,$rep,$seed,$npk,$sha" >> "$OUT/manifest.csv"
    echo "=== $tag packets=$npk"
done 3< "$OUT/schedule.txt"
echo "done: $(ls "$OUT"/*.pkts.csv.gz | wc -l) sessions"
