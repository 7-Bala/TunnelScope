#!/bin/bash
# Smoke test: run each variant for $2 seconds and report what the router saw (packets, direction split, median/max size, span).
# usage: labef_smoke.sh "<variants>" [seconds]
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; R=sih26-router; DUR="${2:-12}"
for v in $1; do
  docker exec $R pkill tcpdump >/dev/null 2>&1; docker exec -d $R bash -c "rm -f /captures/exp45/smoke.pcap; tcpdump -i eth0 -s 96 -w /captures/exp45/smoke.pcap 'ip proto 50 and host 10.10.1.20 and host 10.10.2.20' >/dev/null 2>&1"; sleep 1
  bash "$HERE/labef_gen.sh" run "$v" "$DUR" >/dev/null 2>&1; sleep 2
  for _ in 1 2 3; do docker exec $R pkill -INT tcpdump >/dev/null 2>&1; sleep 1; done
  tshark -r "$HERE/../captures/exp45/smoke.pcap" -T fields -e frame.time_relative -e ip.src -e ip.len 2>/dev/null | python3 -c "
import sys
rows=[l.split() for l in sys.stdin if len(l.split())==3]
n=len(rows); a=sum(1 for r in rows if r[1]=='10.10.1.20'); sz=sorted(int(r[2]) for r in rows)
span=float(rows[-1][0])-float(rows[0][0]) if rows else 0
print('$v'.ljust(22),'pkts',str(n).rjust(6),'a>b',str(a).rjust(5),'b>a',str(n-a).rjust(5),'med',str(sz[len(sz)//2] if sz else '-').rjust(5),'max',str(sz[-1] if sz else '-').rjust(5),'span %5.1fs'%span)"
  docker exec sih26-labe-a pkill -f "expect|gst-launch|ffmpeg|siege|curl|nping|hping3|rsync|lftp" >/dev/null 2>&1; docker exec sih26-labe-b pkill -f "gst-launch|ffmpeg|mosh-server|nc -l" >/dev/null 2>&1
done; rm -f "$HERE/../captures/exp45/smoke.pcap"
