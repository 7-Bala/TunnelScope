#!/bin/bash
# Lab C (EXP-41) traffic generators. Real tools chosen to differ from our shipped generators and from the two public labs.
#   labc_gen.sh setup            start the servers on labc-b (idempotent)
#   labc_gen.sh run <class> <s>  drive one sustained session of <class> for <s> seconds from labc-a
# Classes: bulk web messaging interactive video voip email icmp
set -uo pipefail
A=sih26-labc-a; B=sih26-labc-b; BIP=10.10.2.51; AIP=10.10.1.51

setup() {
  docker exec -i $B bash -s <<'IN'
set -e
mkdir -p /srv/www /tmp/mq
python3 - <<'PY'
import os, random
random.seed(41)
os.makedirs("/srv/www/img", exist_ok=True)
for i in range(70):
    n = random.choice([4_000, 12_000, 40_000, 90_000, 150_000])
    open(f"/srv/www/img/p{i}.bin", "wb").write(os.urandom(n))
for i in range(45):
    links = " ".join(f'<a href="page{random.randrange(45)}.html">p</a>' for _ in range(6))
    imgs = " ".join(f'<img src="img/p{random.randrange(70)}.bin">' for _ in range(3))
    open(f"/srv/www/page{i}.html", "w").write(f"<html><body>{'lorem ipsum '*random.randint(20,400)}{links}{imgs}</body></html>")
open("/srv/www/index.html","w").write('<a href="page0.html">start</a>')
PY
printf 'listener 1883\nallow_anonymous true\n' > /tmp/mq/m.conf
pgrep -f "iperf3 -s" >/dev/null || (iperf3 -s -D)
pgrep -f "busybox httpd" >/dev/null || busybox httpd -p 8081 -h /srv/www
pgrep -f "mosquitto -c" >/dev/null || (mosquitto -c /tmp/mq/m.conf -d)
pgrep -f "socat TCP-LISTEN:2323" >/dev/null || (nohup socat TCP-LISTEN:2323,fork,reuseaddr EXEC:"/bin/sh -i",pty,stderr,setsid,sigint,sane >/tmp/socat.log 2>&1 &)
pgrep -f "smtpd" >/dev/null || (nohup python3 -m smtpd -n -c DebuggingServer 10.10.2.51:2525 >/tmp/smtpd.log 2>&1 &)
IN
}

run() {
  local cls="$1" dur="$2"
  case "$cls" in
  bulk)        docker exec $A iperf3 -c $BIP -t "$dur" -b 5M >/dev/null 2>&1 ;;
  web)         docker exec $A bash -c "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do rm -rf /tmp/w; timeout \$((end-SECONDS)) wget -q -r -l3 -np -nd -P /tmp/w --wait=0.6 --random-wait http://$BIP:8081/index.html; done" >/dev/null 2>&1 ;;
  messaging)   docker exec -d $A bash -c "timeout $dur mosquitto_sub -h $BIP -t 'chat/#' >/dev/null"
               docker exec -d $B bash -c "timeout $dur mosquitto_sub -h $BIP -t 'in/#' >/dev/null"
               docker exec -d $B bash -c "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do mosquitto_pub -h $BIP -t chat/b -m \"\$(head -c \$((20+RANDOM%160)) /dev/urandom | base64 -w0)\"; sleep \$(awk 'BEGIN{srand(); print 0.6+rand()*4}'); done"
               docker exec $A bash -c "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do mosquitto_pub -h $BIP -t in/a -m \"\$(head -c \$((20+RANDOM%160)) /dev/urandom | base64 -w0)\"; sleep \$(awk 'BEGIN{srand(); print 0.6+rand()*4}'); done" ;;
  interactive) docker exec $A bash -c "timeout $dur expect -c '
      set timeout 5
      spawn telnet $BIP 2323
      expect -re {#|\\\$|~}
      set cmds {{ls -la /etc} {cat /etc/os-release} {ps} {uname -a} {df -h} {ip addr} {echo hello} {date}}
      while {1} {
        set c [lindex \$cmds [expr {int(rand()*[llength \$cmds])}]]
        foreach ch [split \$c {}] { send -- \$ch; after [expr {80+int(rand()*260)}] }
        send -- \"\\r\"
        after [expr {1200+int(rand()*3500)}]
      }' " >/dev/null 2>&1 ;;
  video)       docker exec -d $A bash -c "timeout $((dur+2)) ffmpeg -loglevel quiet -i 'udp://$AIP:5000?fifo_size=5000000&overrun_nonfatal=1' -f null -"
               sleep 1
               docker exec $B bash -c "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=640x360:rate=25 -c:v libx264 -preset ultrafast -b:v 900k -g 50 -f mpegts 'udp://$AIP:5000?pkt_size=1316'" >/dev/null 2>&1 ;;
  voip)        docker exec $A bash -c "cat > /tmp/a.sdp <<S
v=0
o=- 0 0 IN IP4 $AIP
s=call
c=IN IP4 $AIP
t=0 0
m=audio 5004 RTP/AVP 97
a=rtpmap:97 opus/48000/2
S"
               docker exec $B bash -c "cat > /tmp/b.sdp <<S
v=0
o=- 0 0 IN IP4 $BIP
s=call
c=IN IP4 $BIP
t=0 0
m=audio 5006 RTP/AVP 97
a=rtpmap:97 opus/48000/2
S"
               docker exec -d $A bash -c "timeout $((dur+2)) ffmpeg -loglevel quiet -protocol_whitelist file,udp,rtp -i /tmp/a.sdp -f null -"
               docker exec -d $B bash -c "timeout $((dur+2)) ffmpeg -loglevel quiet -protocol_whitelist file,udp,rtp -i /tmp/b.sdp -f null -"
               sleep 1
               docker exec -d $B bash -c "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=300' -c:a libopus -b:a 24k -frame_duration 20 -payload_type 97 -f rtp rtp://$AIP:5004"
               docker exec $A bash -c "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=500' -c:a libopus -b:a 24k -frame_duration 20 -payload_type 97 -f rtp rtp://$BIP:5006" >/dev/null 2>&1 ;;
  email)       docker exec $A bash -c "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do
                 n=\$((1+RANDOM%6)); { printf 'From: a@lab\r\nTo: b@lab\r\nSubject: s\r\n\r\n'; head -c \$((300+RANDOM*(\$n))) /dev/urandom | base64; } > /tmp/m.txt
                 curl -s --url smtp://$BIP:2525 --mail-from a@lab --mail-rcpt b@lab -T /tmp/m.txt >/dev/null; sleep \$(awk 'BEGIN{srand(); print 1.5+rand()*5}'); done" >/dev/null 2>&1 ;;
  icmp)        docker exec $A ping -i 0.7 -s 200 -w "$dur" $BIP >/dev/null 2>&1 ;;
  *) echo "unknown class $cls" >&2; return 2 ;;
  esac
}

case "${1:-}" in setup) setup ;; run) run "$2" "$3" ;; *) echo "usage: $0 setup | run <class> <seconds>" >&2; exit 2 ;; esac
