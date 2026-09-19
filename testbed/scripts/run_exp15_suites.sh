#!/bin/bash
# EXP-15 parts B (IKE/DH suites) and C (AH): one capture per arm, taken at the
# keyless router from BEFORE the IKE_SA_INIT, then a size-sweep of pings, one
# CREATE_CHILD_SA rekey (so PFS is visible), more pings. T2 ground truth from
# swanctl + XFRM afterwards. Pre-registration: experiments/exp15-*/PREREG.md.
#
# Usage: run_exp15_suites.sh [arm ...]      (default: every s-* and a-* arm)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/../captures/exp15"; mkdir -p "$OUT"
A=sih26-alice-pq; B=sih26-bob-pq; R=sih26-router
ARMS=("$@"); [ ${#ARMS[@]} -eq 0 ] && ARMS=(s-modp1024 s-modp1536 s-modp3072 s-modp4096 s-ecp256 s-ecp384 s-x25519 s-3des s-mlkem a-tun-sha256 a-tra-sha256 a-tra-sha1 a-tun-sha384 a-tra-sha512)
j_of() { python3 -c "import json,sys;print(json.load(open('$HERE/../configs/exp15/arms.json'))[sys.argv[1]]['j'])" "$1"; }

stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }

for arm in "${ARMS[@]}"; do
    j=$(j_of "$arm"); a="10.10.1.$((210+j))"; b="10.10.2.$((210+j))"
    docker exec $A swanctl --terminate --ike "$arm" >/dev/null 2>&1; sleep 1
    docker exec -d $R bash -c "rm -f /captures/exp15/$arm.pcap; tcpdump -i eth0 -w /captures/exp15/$arm.pcap 'host $a and host $b' >/dev/null 2>&1"
    sleep 1
    docker exec $A swanctl --initiate --child "$arm" --timeout 10000 2>&1 | tail -1
    for s in 0 8 16 32 56 64 100 128 256 512 1024 1400; do
        docker exec $A ping -c 2 -i 0.1 -s "$s" -W1 -I "$a" "$b" >/dev/null 2>&1
    done
    docker exec $A swanctl --rekey --child "$arm" >/dev/null 2>&1; sleep 2
    docker exec $A ping -c 6 -i 0.2 -I "$a" "$b" >/dev/null 2>&1
    python3 - "$OUT/$arm.groundtruth.json" "$arm" <<'PY'
import json, sys, subprocess, datetime
out, arm = sys.argv[1], sys.argv[2]
run = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
json.dump({"arm": arm, "experiment": "EXP-15",
           "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "alice_list_sas": run(f"docker exec sih26-alice-pq swanctl --list-sas --ike {arm} 2>&1"),
           "bob_list_sas": run(f"docker exec sih26-bob-pq swanctl --list-sas --ike {arm} 2>&1"),
           "note": "T2 ground truth from swanctl on the endpoints, never from the analyzer."},
          open(out, "w"), indent=2)
PY
    stop_capture; sleep 1
    echo "=== $arm: $(ls -l "$OUT/$arm.pcap" | awk '{print $5}') bytes"
done
