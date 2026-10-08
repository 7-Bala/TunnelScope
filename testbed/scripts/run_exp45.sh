#!/bin/bash
# EXP-45 capture harness (labs E and F). Pre-registration: experiments/exp45-more-diversity/PREREG.md
# Per lab and ESP suite, every single-class variant and every mixed pairing runs for DUR seconds behind the gateways; the keyless
# router captures ESP headers (-s 96); each pcap is reduced to a committed per-packet table (t, dir, len) and hashed in manifest.csv.
#
#   Lab E (training):  netem delay 8ms 3ms loss 0.1%;  suites gcm128 (rep 1) and cbc128 (rep 2)
#                      singles: every VARIANTS_E variant x 2 repetitions (one per suite)
#                      mixed:   8 class pairs x 2 variant pairings x 2 repetitions x 2 suites = 64
#   Lab F (test only): netem delay 25ms 10ms loss 0.5%; suites chacha (rep 1) and gcm256 (rep 2)
#                      singles: every VARIANTS_F variant x 2 repetitions (one per suite)
#                      mixed:   4 class pairs x 2 variant pairings x 2 repetitions (one per suite) = 16
# The variants of a mixed pairing come from a shuffle seeded here (lab + pair name), before any capture; pairing 1 and 2 differ.
# A session with fewer than MIN_PKTS packets is a tool that did not run: it is retried once, and the manifest keeps the attempt count.
# That rule looks at the packet count only, never at a label or a score.
# Usage: run_exp45.sh <E|F> [duration_s=45]      (resumable: a session whose table exists is skipped)
set -uo pipefail
LAB="${1:?usage: run_exp45.sh <E|F> [duration_s]}"; DUR="${2:-45}"; MIN_PKTS=30
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# EXP45_SUBDIR is for a throwaway rehearsal of this harness only (short sessions, deleted afterwards); scored runs use exp45.
SUB="${EXP45_SUBDIR:-exp45}"; OUT="$HERE/../captures/$SUB"; mkdir -p "$OUT"
R=sih26-router; GEN="$HERE/labef_gen.sh"

# iLBC is dropped from lab F before any scored capture: the image's GStreamer has no ilbcenc (PREREG: a tool that cannot be
# made to run is dropped and listed in the RESULT).
DROPPED_F="voip.ilbc"
eval "$(grep -E '^VARIANTS_(E|F)=' "$GEN")"
if [ "$LAB" = E ]; then
    VARIANTS="$VARIANTS_E"; NETEM="delay 8ms 3ms loss 0.1%"; SUITES=(gcm128 cbc128); MIXREPS="1 2"
    PAIRS="video+interactive web+voip bulk+interactive bulk+voip web+video messaging+email voip+interactive bulk+web"
elif [ "$LAB" = F ]; then
    VARIANTS=""; for v in $VARIANTS_F; do case " $DROPPED_F " in *" $v "*) ;; *) VARIANTS="$VARIANTS $v" ;; esac; done
    NETEM="delay 25ms 10ms loss 0.5%"; SUITES=(chacha gcm256); MIXREPS=""
    PAIRS="video+interactive web+voip bulk+interactive messaging+email"
else echo "lab must be E or F" >&2; exit 2; fi
child_of() { case "$1" in gcm128) echo e45a ;; cbc128) echo e45b ;; chacha) echo e45c ;; gcm256) echo e45d ;; esac; }

stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }
cleanup_gens() {
    docker exec sih26-labe-a pkill -f "expect|gst-launch|ffmpeg|siege|curl|nping|hping3|rsync|lftp|lynx|nghttp|h2load|swaks|mosquitto|python3 -c|traceroute|ping|nc |pv" >/dev/null 2>&1
    docker exec sih26-labe-b pkill -f "gst-launch|ffmpeg|nc -l|python3 -c|mosquitto_sub|mosquitto_pub" >/dev/null 2>&1
}

capture_one() {   # $1 tag, $2 suite, $3 class, $4 variant(s), $5 rep, then the generator arguments
    local tag="$1" suite="$2" cls="$3" var="$4" rep="$5"; shift 5
    [ -s "$OUT/$tag.pkts.csv.gz" ] && return 0
    local attempt npk sha
    for attempt in 1 2; do
        docker exec $R pkill tcpdump >/dev/null 2>&1
        docker exec -d $R bash -c "rm -f /captures/$SUB/$tag.pcap; tcpdump -i eth0 -s 96 -w /captures/$SUB/$tag.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"
        sleep 1
        bash "$GEN" "$@" "$DUR" >/dev/null 2>&1
        sleep 2; stop_capture; cleanup_gens
        npk=$(tshark -r "$OUT/$tag.pcap" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' ')
        [ "$npk" -ge "$MIN_PKTS" ] && break
        echo "    retry $tag (only $npk packets on attempt $attempt)"; sleep 3
    done
    tshark -r "$OUT/$tag.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null \
      | awk -v a="10.10.1.20" 'BEGIN{OFS=","; print "t","dir","len"} {print $1, ($2==a?"out":"in"), $3}' | gzip -9 > "$OUT/$tag.pkts.csv.gz"
    npk=$(($(gzip -dc "$OUT/$tag.pkts.csv.gz" | wc -l) - 1)); sha=$(shasum -a 256 "$OUT/$tag.pcap" | cut -d' ' -f1)
    [ -s "$OUT/manifest.csv" ] || echo "tag,lab,suite,class,variant,rep,packets,attempts,pcap_sha256" > "$OUT/manifest.csv"
    echo "$tag,$LAB,$suite,$cls,$var,$rep,$npk,$attempt,$sha" >> "$OUT/manifest.csv"
    echo "=== $tag packets=$npk attempts=$attempt"
    sleep 3
}

bash "$GEN" setup >/dev/null 2>&1
for dev in eth0 eth1; do docker exec $R tc qdisc replace dev $dev root netem $NETEM >/dev/null 2>&1; done
docker exec $R tc qdisc show dev eth0 > "$OUT/netem-$LAB.txt" 2>&1

si=0
for suite in "${SUITES[@]}"; do
    si=$((si + 1)); child=$(child_of "$suite")
    for s in alice bob; do
        for c in e45a e45b e45c e45d; do docker exec sih26-$s-pq swanctl --terminate --ike $c >/dev/null 2>&1; done
        docker cp "$HERE/../configs/exp45/$s-$suite.conf" "sih26-$s-pq:/tmp/e45.conf" >/dev/null
        docker exec "sih26-$s-pq" swanctl --load-all --file /tmp/e45.conf >/dev/null 2>&1
    done
    docker exec sih26-alice-pq swanctl --initiate --child "$child" --timeout 15000 >/dev/null 2>&1
    docker exec sih26-alice-pq swanctl --list-sas > "$OUT/$LAB-$suite.swanctl.txt" 2>&1
    grep -q INSTALLED "$OUT/$LAB-$suite.swanctl.txt" || { echo "FATAL: $suite tunnel not installed"; exit 4; }
    docker exec sih26-labe-a ping -c 2 -W 3 10.10.2.53 >/dev/null 2>&1 || { echo "FATAL: no path through the $suite tunnel"; exit 4; }

    # singles: repetition number = suite number; a fixed per-suite shuffle so no class always follows the same neighbour
    order=$(python3 -c "import random; v='$VARIANTS'.split(); random.Random('$LAB$suite').shuffle(v); print(' '.join(v))")
    for v in $order; do
        capture_one "exp45-$LAB-$suite-$v-rep$si" "$suite" "${v%%.*}" "$v" "$si" run "$v"
    done

    # mixed: two classes at once, one variant of each
    for pair in $PAIRS; do
        for k in 1 2; do
            vv=$(python3 -c "
import random
V='$VARIANTS'.split(); a,b='$pair'.split('+')
A=[v for v in V if v.startswith(a+'.')]; B=[v for v in V if v.startswith(b+'.')]
random.Random('$LAB$pair'+'a').shuffle(A); random.Random('$LAB$pair'+'b').shuffle(B)
print(A[$k-1], B[$k-1])")      # pairings 1 and 2 never repeat a variant
            va=${vv% *}; vb=${vv#* }
            for rep in ${MIXREPS:-$si}; do
                capture_one "exp45-$LAB-$suite-mix-$va+$vb-p$k-rep$rep" "$suite" mixed "$va+$vb" "$rep" mix "$va" "$vb"
            done
        done
    done
done
for dev in eth0 eth1; do docker exec $R tc qdisc del dev $dev root >/dev/null 2>&1; done
# Leave the gateways as found: the lab remediation engine loads the FIRST /tmp/*.conf it finds, and a leftover e45.conf
# sorts before the lab's own file (it made tests/test_remediate.py::test_lab_remediation_e2e fail during the rehearsal).
for s in alice bob; do
    for c in e45a e45b e45c e45d; do docker exec sih26-$s-pq swanctl --terminate --ike $c >/dev/null 2>&1; done
    docker exec sih26-$s-pq rm -f /tmp/e45.conf >/dev/null 2>&1
done
echo "done lab $LAB: $(ls "$OUT"/exp45-$LAB-*.pkts.csv.gz | wc -l) tables"
