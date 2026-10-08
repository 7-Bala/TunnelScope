#!/bin/bash
# Smoke test: run each variant for $2 seconds and report what the router saw (packets, direction split, median/max size, span).
# It prints packet counts only; nothing it captures is kept. usage: labgh_smoke.sh "<variants>" [seconds]
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; R=sih26-router; DUR="${2:-12}"; mkdir -p "$HERE/../captures/exp51-smoke"
for v in $1; do
  docker exec $R pkill tcpdump >/dev/null 2>&1; docker exec -d $R bash -c "rm -f /captures/exp51-smoke/smoke.pcap; tcpdump -i eth0 -s 96 -w /captures/exp51-smoke/smoke.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"; sleep 1
  bash "$HERE/labgh_gen.sh" run "$v" "$DUR" >/dev/null 2>&1; sleep 2
  for _ in 1 2 3; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; done
  tshark -r "$HERE/../captures/exp51-smoke/smoke.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null | python3 -c "
import sys
rows=[l.split() for l in sys.stdin if len(l.split())==3]
n=len(rows); a=sum(1 for r in rows if r[1]=='10.10.1.20'); sz=sorted(int(r[2]) for r in rows)
span=float(rows[-1][0])-float(rows[0][0]) if rows else 0
print('$v'.ljust(22),'pkts',str(n).rjust(7),'a>b',str(a).rjust(6),'b>a',str(n-a).rjust(6),'med',str(sz[len(sz)//2] if sz else '-').rjust(5),'max',str(sz[-1] if sz else '-').rjust(5),'span %5.1fs'%span)"
  docker exec sih26-labg-a pkill -f "expect|gst-launch|ffmpeg|curl|axel|scp|sftp|wget|chromium|firefox|w3m|socat|labgh_tool.py [a-z]+ 10|mtr|ping|mail " >/dev/null 2>&1; docker exec sih26-labg-b pkill -f "gst-launch|ffmpeg|socat" >/dev/null 2>&1
done; rm -rf "$HERE/../captures/exp51-smoke"
