#!/bin/bash
# EXP-05 capture harness (metadata leakage). Pre-registration:
# research/registers/EXPERIMENT-REGISTER.md ("EXP-05 — PRE-REGISTRATION").
#
# - Tunnels e5-base / e5-tfc / e5-mux stay up for the whole run (long-lived
#   SAs, as in production). IP-TFS arm dropped: kernel lacks it (NOTES.md #13).
# - Session order is shuffled with a fixed seed, so slow drift over the run
#   can't line up with any class.
# - Capture at the keyless router, headers only (-s 96), filtered to the arm's
#   alias pair. Each pcap is reduced to a per-packet table (time, direction,
#   ip.len) which is what gets committed; pcaps are SHA-256'd into a manifest.
#
# Usage: run_exp05.sh [reps=4] [duration_s=20]
set -uo pipefail
REPS="${1:-4}"; DUR="${2:-20}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp05"; mkdir -p "$OUT"
A=sih26-alice-pq; B=sih26-bob-pq
arm_idx() { case "$1" in base) echo 0;; tfc) echo 1;; mux) echo 3;; esac; }   # bash 3.2 (macOS): no assoc arrays

# --- idempotent setup ---
for j in 0 1 3; do
    docker exec $A ip addr add "10.10.1.$((200+j))/32" dev eth0 2>/dev/null || true
    docker exec $B ip addr add "10.10.2.$((200+j))/32" dev eth0 2>/dev/null || true
done
docker exec $A swanctl --load-all --file /etc/swanctl/exp05/alice.conf >/dev/null 2>&1
docker exec $B swanctl --load-all --file /etc/swanctl/exp05/bob.conf   >/dev/null 2>&1
docker cp "$HERE/tgen.py" $A:/tmp/tgen.py >/dev/null; docker cp "$HERE/tgen.py" $B:/tmp/tgen.py >/dev/null
docker exec $B pkill -f "tgen.py server" >/dev/null 2>&1 || true
for j in 0 1 3; do docker exec -d $B python3 /tmp/tgen.py server "10.10.2.$((200+j))"; done
sleep 1
for arm in base tfc mux; do
    docker exec $A swanctl --list-sas --ike "e5-$arm" 2>/dev/null | grep -q INSTALLED \
      || docker exec $A swanctl --initiate --child "e5-$arm" --timeout 10000 >/dev/null 2>&1
done

# --- schedule (fixed-seed shuffle), written out for reproducibility ---
python3 - "$REPS" > "$OUT/schedule.txt" <<'PY'
import random, sys
reps = int(sys.argv[1]); rows = []
for r in range(1, reps + 1):
    for arm in ("base", "tfc"):
        for cls in ("voip", "web", "bulk", "interactive", "video"):
            rows.append((arm, cls, r))
    for pair in ("voip+web", "video+interactive", "bulk+voip"):
        rows.append(("mux", pair, r))
random.Random(20260912).shuffle(rows)
for i, (arm, cls, r) in enumerate(rows):
    print(arm, cls, r, 5000 + i)   # last column = generator seed
PY

stop_capture() {
    for _ in 1 2 3 4 5; do
        docker exec sih26-router pkill -INT tcpdump >/dev/null 2>&1 || true; sleep 1
        docker exec sih26-router pgrep tcpdump >/dev/null 2>&1 || return 0
    done
}

while read -r arm cls rep seed <&3; do   # fd 3: nothing inside the loop can eat the schedule
    tag="exp05-$arm-${cls/+/_}-rep$rep"
    if [ -s "$OUT/$tag.pkts.csv.gz" ]; then echo "=== $tag (done) ==="; continue; fi
    echo "=== $tag (seed $seed) ==="
    j=$(arm_idx "$arm"); a="10.10.1.$((200+j))"; b="10.10.2.$((200+j))"
    docker exec sih26-router pkill tcpdump >/dev/null 2>&1 || true
    docker exec -d sih26-router bash -c "rm -f /captures/exp05/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/exp05/$tag.pcap 'ip proto 50 and host $a and host $b' >/dev/null 2>&1"
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
    echo "    packets=$npk"
done 3< "$OUT/schedule.txt"
echo "done: $(ls "$OUT"/*.pkts.csv.gz | wc -l) sessions"
