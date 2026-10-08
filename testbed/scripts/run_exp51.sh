#!/bin/bash
# EXP-51 capture harness (labs H and G). Pre-registration: experiments/exp51-rate-invariance/PREREG.md
# Per lab, ESP suite and link profile, every single-class variant (and, for lab G, every mixed pairing) runs for DUR seconds behind
# the gateways; the keyless router captures ESP headers (-s 96); each pcap is reduced to a committed per-packet table (t, dir, len)
# and hashed in manifest.csv.
#
#   Lab H (training):  suites gcm256 (rep 1) and ctr128 (rep 2); link profiles r2 (2 Mbit/s), r20 (20 Mbit/s), r100 (100 Mbit/s)
#                      singles: every VARIANTS_H variant x 3 profiles x 2 repetitions (one per suite)
#   Lab G (test only): suites gcm192 (rep 1) and cbc256s512 (rep 2); link profiles g5 (5 Mbit/s, 40 ms delay), g50 (50 Mbit/s)
#                      singles: every VARIANTS_G variant x 2 profiles x 2 suites  (8 sessions per class)
#                      mixed:   4 class pairs x 2 profiles x 2 suites = 16
# The PREREG's third lab-H profile was "unshaped"; the smoke test (packet counts only) showed an unshaped download is about 55,000
# packets/s, i.e. 2.4 million packets and a table far over the repository's 5 MB limit per session, so it is 100 Mbit/s instead.
# Shaped profiles use `netem ... limit 120` (a 120-packet queue; netem's default of 1000 would hold seconds of traffic at 2 Mbit/s).
# The variants of a mixed pairing come from a shuffle seeded here (lab + pair name), before any capture.
# A session with fewer than MIN_PKTS packets is a tool that did not run: it is retried once, and the manifest keeps the attempt count.
# That rule looks at the packet count only, never at a label or a score.
# Usage: run_exp51.sh <H|G> [duration_s=45]      (resumable: a session whose table exists is skipped)
set -uo pipefail
LAB="${1:?usage: run_exp51.sh <H|G> [duration_s]}"; DUR="${2:-45}"; MIN_PKTS=30
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# EXP51_SUBDIR is for a throwaway rehearsal of this harness only (short sessions, deleted afterwards); scored runs use exp51.
SUB="${EXP51_SUBDIR:-exp51}"; OUT="$HERE/../captures/$SUB"; mkdir -p "$OUT"
R=sih26-router; GEN="$HERE/labgh_gen.sh"

# Dropped before any scored capture (PREREG: a tool that cannot be made to run is dropped and listed in the RESULT):
# voip.amrnb, the image's ffmpeg has no AMR encoder.
DROPPED="voip.amrnb"
eval "$(grep -E '^VARIANTS_(H|G)=' "$GEN")"
if [ "$LAB" = H ]; then
    ALL="$VARIANTS_H"; SUITES=(gcm256 ctr128); PROFILES="r2 r20 r100"; PAIRS=""
elif [ "$LAB" = G ]; then
    ALL="$VARIANTS_G"; SUITES=(gcm192 cbc256s512); PROFILES="g5 g50"; PAIRS="video+interactive web+voip bulk+interactive messaging+email"
else echo "lab must be H or G" >&2; exit 2; fi
VARIANTS=""; for v in $ALL; do case " $DROPPED " in *" $v "*) ;; *) VARIANTS="$VARIANTS $v" ;; esac; done
child_of() { case "$1" in gcm256) echo e51a ;; ctr128) echo e51b ;; gcm192) echo e51c ;; cbc256s512) echo e51d ;; esac; }
netem_of() { case "$1" in r2) echo "rate 2mbit limit 120" ;; r20) echo "rate 20mbit limit 120" ;; g5) echo "delay 40ms rate 5mbit limit 120" ;; g50) echo "rate 50mbit limit 120" ;; r100) echo "rate 100mbit limit 120" ;; esac; }

stop_capture() { for _ in 1 2 3 4 5; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; docker exec $R pgrep tcpdump >/dev/null 2>&1 || return 0; done; }
cleanup_gens() {
    docker exec sih26-labg-a pkill -f "expect|gst-launch|ffmpeg|curl|axel|scp|sftp|wget|chromium|firefox|w3m|socat|labgh_tool.py [a-z]+ 10|mtr|ping|mail " >/dev/null 2>&1
    docker exec sih26-labg-b pkill -f "gst-launch|ffmpeg|socat" >/dev/null 2>&1
}

capture_one() {   # $1 tag, $2 suite, $3 profile, $4 class, $5 variant(s), $6 rep, then the generator arguments
    local tag="$1" suite="$2" prof="$3" cls="$4" var="$5" rep="$6"; shift 6
    # Done means BOTH the table and its manifest row exist. The table is written to a temporary name and renamed, so an
    # interrupted run leaves no half-written table, and a table without a manifest row is captured again.
    [ -s "$OUT/$tag.pkts.csv.gz" ] && grep -q "^$tag," "$OUT/manifest.csv" 2>/dev/null && return 0
    rm -f "$OUT/$tag.pkts.csv.gz" "$OUT/$tag.pkts.csv.gz.tmp"
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
      | awk -v a="10.10.1.20" 'BEGIN{OFS=","; print "t","dir","len"} {print $1, ($2==a?"out":"in"), $3}' | gzip -9 > "$OUT/$tag.pkts.csv.gz.tmp"
    mv "$OUT/$tag.pkts.csv.gz.tmp" "$OUT/$tag.pkts.csv.gz"
    npk=$(($(gzip -dc "$OUT/$tag.pkts.csv.gz" | wc -l) - 1)); sha=$(shasum -a 256 "$OUT/$tag.pcap" | cut -d' ' -f1)
    [ -s "$OUT/manifest.csv" ] || echo "tag,lab,suite,profile,class,variant,rep,packets,attempts,pcap_sha256" > "$OUT/manifest.csv"
    echo "$tag,$LAB,$suite,$prof,$cls,$var,$rep,$npk,$attempt,$sha" >> "$OUT/manifest.csv"
    echo "=== $tag packets=$npk attempts=$attempt"
    sleep 3
}

bash "$GEN" setup >/dev/null 2>&1
si=0
for suite in "${SUITES[@]}"; do
    si=$((si + 1)); child=$(child_of "$suite")
    for s in alice bob; do
        for c in e51a e51b e51c e51d; do docker exec sih26-$s-pq swanctl --terminate --ike $c >/dev/null 2>&1; done
        docker cp "$HERE/../configs/exp51/$s-$suite.conf" "sih26-$s-pq:/tmp/e51.conf" >/dev/null
        docker exec "sih26-$s-pq" swanctl --load-all --file /tmp/e51.conf >/dev/null 2>&1
    done
    docker exec sih26-alice-pq swanctl --initiate --child "$child" --timeout 15000 >/dev/null 2>&1
    docker exec sih26-alice-pq swanctl --list-sas > "$OUT/$LAB-$suite.swanctl.txt" 2>&1
    grep -q INSTALLED "$OUT/$LAB-$suite.swanctl.txt" || { echo "FATAL: $suite tunnel not installed"; exit 4; }
    docker exec sih26-labg-a ping -c 2 -W 3 10.10.2.54 >/dev/null 2>&1 || { echo "FATAL: no path through the $suite tunnel"; exit 4; }

    for prof in $PROFILES; do
        ne=$(netem_of "$prof")
        for dev in eth0 eth1; do
            docker exec $R tc qdisc del dev $dev root >/dev/null 2>&1
            [ -n "$ne" ] && docker exec $R tc qdisc replace dev $dev root netem $ne >/dev/null 2>&1
        done
        docker exec $R tc qdisc show dev eth0 > "$OUT/netem-$LAB-$prof.txt" 2>&1

        # singles: repetition number = suite number; a fixed shuffle per suite and profile so no class always follows the same neighbour
        order=$(python3 -c "import random; v='$VARIANTS'.split(); random.Random('$LAB$suite$prof').shuffle(v); print(' '.join(v))")
        for v in $order; do
            capture_one "exp51-$LAB-$suite-$prof-$v-rep$si" "$suite" "$prof" "${v%%.*}" "$v" "$si" run "$v"
        done
        # mixed (lab G only): two classes at once, one variant of each
        for pair in $PAIRS; do
            vv=$(python3 -c "
import random
V='$VARIANTS'.split(); a,b='$pair'.split('+')
A=[v for v in V if v.startswith(a+'.')]; B=[v for v in V if v.startswith(b+'.')]
random.Random('$LAB$pair$suite$prof'+'a').shuffle(A); random.Random('$LAB$pair$suite$prof'+'b').shuffle(B)
print(A[0], B[0])")
            va=${vv% *}; vb=${vv#* }
            capture_one "exp51-$LAB-$suite-$prof-mix-$va+$vb-rep$si" "$suite" "$prof" mixed "$va+$vb" "$si" mix "$va" "$vb"
        done
    done
done
for dev in eth0 eth1; do docker exec $R tc qdisc del dev $dev root >/dev/null 2>&1; done
# Leave the gateways as found: the lab remediation engine loads the FIRST /tmp/*.conf it finds.
for s in alice bob; do
    for c in e51a e51b e51c e51d; do docker exec sih26-$s-pq swanctl --terminate --ike $c >/dev/null 2>&1; done
    docker exec sih26-$s-pq rm -f /tmp/e51.conf >/dev/null 2>&1
done
echo "done lab $LAB: $(ls "$OUT"/exp51-$LAB-*.pkts.csv.gz | wc -l) tables"
