#!/bin/bash
# EXP-06 round 2 capture harness. See research/registers/EXPERIMENT-REGISTER.md
# ("EXP-06 Round 2 — PRE-REGISTRATION") for the design and the predictions.
#
# For each repetition r and arm k (f00..f06):
#   1. terminate EVERY IKE SA on alice and bob (round-1 flaw #3)
#   2. capture on router eth0, filtered to arm k's alias hosts only
#   3. initiate f0k; ping via the arm's aliases; for f05 trigger a CHILD_SA rekey
#   4. stop the capture; record T2 ground truth (the designed label + charon's
#      own log lines for this run)
#
# Usage: run_exp06.sh [reps=5]
set -uo pipefail
REPS="${1:-5}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp06r2"
mkdir -p "$OUT"

terminate_all() {
    for c in sih26-alice sih26-bob; do
        for ike in $(docker exec $c swanctl --list-sas 2>/dev/null | grep -oE '^[a-z0-9-]+: #[0-9]+' | cut -d: -f1 | sort -u); do
            docker exec $c swanctl --terminate --ike "$ike" --timeout 3 >/dev/null 2>&1 || true
        done
    done
}

stop_capture() {
    for _ in 1 2 3 4 5; do
        docker exec sih26-router pkill -INT tcpdump >/dev/null 2>&1 || true
        sleep 1
        docker exec sih26-router pgrep tcpdump >/dev/null 2>&1 || return 0
    done
}

# Idempotent setup, so the harness survives container restarts (which drop
# alias IPs and loaded configs): add per-arm aliases, load ONLY the exp06 conns.
for k in 0 1 2 3 4 5 6; do
    docker exec sih26-alice ip addr add "10.10.1.$((100+k))/32" dev eth0 2>/dev/null || true
    docker exec sih26-bob   ip addr add "10.10.2.$((100+k))/32" dev eth0 2>/dev/null || true
done
docker exec sih26-alice swanctl --load-all --file /etc/swanctl/exp06/alice.conf >/dev/null 2>&1
docker exec sih26-bob   swanctl --load-all --file /etc/swanctl/exp06/bob.conf   >/dev/null 2>&1

for r in $(seq 1 "$REPS"); do
  for k in 0 1 2 3 4 5 6; do
    arm="f0$k"; a="10.10.1.$((100+k))"; b="10.10.2.$((100+k))"; [ "$k" = 6 ] && b="10.10.2.199"
    tag="exp06r2-$arm-rep$r"
    # Resume support: skip runs that completed (non-empty pcap + ground truth).
    if [ -s "$OUT/$tag.pcap" ] && [ -s "$OUT/$tag.groundtruth.json" ]; then
        echo "=== $tag (done, skipping) ==="; continue
    fi
    echo "=== $tag ==="
    terminate_all; sleep 1
    docker exec sih26-router pkill tcpdump >/dev/null 2>&1 || true
    since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    docker exec -d sih26-router bash -c "rm -f /captures/exp06r2/$tag.pcap; tcpdump -i eth0 -w /captures/exp06r2/$tag.pcap 'host $a and host $b and (ip proto 50 or udp port 500 or udp port 4500)' >/dev/null 2>&1"
    sleep 1
    to=8; [ "$k" = 6 ] && to=10
    docker exec sih26-alice swanctl --initiate --child "$arm" --timeout $((to*1000)) >/dev/null 2>&1
    docker exec sih26-alice ping -c 5 -i 0.2 -W1 -I "$a" "$b" >/dev/null 2>&1 || true
    if [ "$k" = 5 ]; then
        docker exec sih26-alice swanctl --rekey --child "$arm" >/dev/null 2>&1 || true
        sleep 2
    fi
    sleep 1
    stop_capture
    logs="$(docker logs --since "$since" sih26-alice 2>&1 | grep -E 'parsed (IKE_SA_INIT|IKE_AUTH|CREATE_CHILD_SA) response|received .* notify|established|retransmit' | sed 's/^[0-9]*\[[A-Z]*\] //')"
    python3 - "$OUT/$tag.groundtruth.json" "$arm" "$r" "$since" "$logs" <<'PY'
import json, sys, pathlib
out, arm, rep, since, logs = sys.argv[1:6]
arms = json.loads((pathlib.Path(out).parent.parent.parent / "configs/exp06/arms.json").read_text())
json.dump({"arm": arm, "rep": int(rep), "designed_label": arms[arm]["label"],
           "captured_since_utc": since, "charon_log_T2": logs.splitlines(),
           "note": "designed_label is the ground truth (the misconfiguration we built); "
                   "charon_log_T2 is the endpoint's own confirmation. Neither is derived from the capture."},
          open(out, "w"), indent=2)
PY
  done
done
terminate_all
echo "done: $(ls "$OUT"/*.pcap | wc -l) captures in $OUT"
