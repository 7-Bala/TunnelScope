#!/bin/bash
# Lab D (EXP-43) traffic generators: every tool differs from our shipped generators, labs A and B, and lab C.
#   labd_gen.sh setup            start the servers on labd-b and the keys/configs on labd-a (idempotent)
#   labd_gen.sh run <class> <s>  drive one sustained session of <class> for <s> seconds
# Classes: bulk web messaging interactive video voip email icmp
set -uo pipefail
A=sih26-labd-a; B=sih26-labd-b; BIP=10.10.2.52; AIP=10.10.1.52

setup() {
  docker exec -i $B bash -s <<'IN'
mkdir -p /srv/www/img /run/sshd /root/.ssh
if [ ! -f /srv/www/big.bin ]; then
python3 - <<'PY'
import os, random
random.seed(43)
for i in range(60):
    open(f"/srv/www/img/i{i}.dat", "wb").write(os.urandom(random.choice([6_000, 20_000, 60_000, 110_000, 180_000])))
for i in range(40):
    links = " ".join(f'<a href="p{random.randrange(40)}.html">x</a>' for _ in range(5))
    imgs = " ".join(f'<img src="img/i{random.randrange(60)}.dat">' for _ in range(4))
    open(f"/srv/www/p{i}.html", "w").write(f"<html><body>{'text '*random.randint(50,900)}{links}{imgs}</body></html>")
open("/srv/www/index.html", "w").write('<a href="p0.html">p0</a><a href="p1.html">p1</a>')
with open("/srv/www/big.bin", "wb") as f:
    for _ in range(200): f.write(os.urandom(1 << 20))
PY
fi
cat > /tmp/lighttpd.conf <<'C'
server.document-root = "/srv/www"
server.port = 8082
index-file.names = ("index.html")
mimetype.assign = (".html" => "text/html", "" => "application/octet-stream")
C
ss -lnt | grep -q ":8082 " || lighttpd -f /tmp/lighttpd.conf
ss -lnt | grep -q ":6667 " || ngircd
printf 'listen on 0.0.0.0\naction "local" mbox\nmatch from any for any action "local"\n' > /etc/smtpd.conf
ss -lnt | grep -q ":25 " || smtpd
ss -lnt | grep -q ":22 " || /usr/sbin/sshd
IN
  docker exec $A bash -c "[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519"
  docker exec $A cat /root/.ssh/id_ed25519.pub | docker exec -i $B bash -c "cat > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys"
  docker exec $A bash -c "printf 'account default\nhost $BIP\nport 25\nfrom a@labd\nauth off\ntls off\n' > /root/.msmtprc; chmod 600 /root/.msmtprc"
}

rand() { echo "\$(awk 'BEGIN{srand(); print $1+rand()*$2}')"; }

run() {
  local cls="$1" dur="$2"
  case "$cls" in
  bulk)        docker exec $A bash -c "rm -f /tmp/big.bin*; timeout $dur aria2c -q -x 8 -s 8 --max-overall-download-limit=1M -d /tmp http://$BIP:8082/big.bin" >/dev/null 2>&1 ;;
  web)         docker exec $A bash -c "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do rm -rf /tmp/h; timeout \$((end-SECONDS)) httrack -q http://$BIP:8082/ -O /tmp/h -r4 -c2 -%c1 --max-rate=300000 >/dev/null 2>&1; sleep 1; done" ;;
  messaging)   for side in a b; do
                 c=$A; [ $side = b ] && c=$B
                 docker exec -d $c bash -c "rm -rf /tmp/irc$side; timeout $((dur+3)) ii -s $BIP -n user$side -i /tmp/irc$side"
               done
               sleep 4
               for side in a b; do c=$A; [ $side = b ] && c=$B; docker exec $c bash -c "echo '/j #lab' > /tmp/irc$side/$BIP/in"; done
               sleep 4
               docker exec -d $B bash -c "end=\$((SECONDS+$dur-3)); while [ \$SECONDS -lt \$end ]; do echo \"\$(head -c \$((15+RANDOM%140)) /dev/urandom | base64 -w0)\" > '/tmp/ircb/$BIP/#lab/in'; sleep \$(awk 'BEGIN{srand(); print 0.8+rand()*5}'); done"
               docker exec $A bash -c "end=\$((SECONDS+$dur-3)); while [ \$SECONDS -lt \$end ]; do echo \"\$(head -c \$((15+RANDOM%140)) /dev/urandom | base64 -w0)\" > '/tmp/irca/$BIP/#lab/in'; sleep \$(awk 'BEGIN{srand(); print 0.8+rand()*5}'); done" ;;
  interactive) docker exec $A bash -c "timeout $dur expect -c '
      set timeout 20
      set env(TERM) xterm
      set stty_init {rows 40 cols 120}
      spawn mosh {--ssh=ssh -o StrictHostKeyChecking=no -i /root/.ssh/id_ed25519} {--server=LANG=C.UTF-8 mosh-server} root@$BIP -- bash
      expect -re {#|\\\$}
      set cmds {{ls -la /usr/bin | head} {cat /etc/os-release} {ps aux} {uptime} {free -m} {ip route} {echo hi} {date}}
      while {1} {
        set c [lindex \$cmds [expr {int(rand()*[llength \$cmds])}]]
        foreach ch [split \$c {}] { send -- \$ch; after [expr {90+int(rand()*300)}] }
        send -- \"\\r\"
        after [expr {1500+int(rand()*4000)}]
      }' " >/dev/null 2>&1 ;;
  video)       docker exec -d $A bash -c "timeout $((dur+2)) gst-launch-1.0 -q udpsrc port=5600 caps='application/x-rtp,media=video,encoding-name=H264,payload=96' ! rtph264depay ! fakesink"
               sleep 1
               docker exec $B bash -c "timeout $dur gst-launch-1.0 -q videotestsrc is-live=true pattern=snow ! video/x-raw,width=640,height=360,framerate=25/1 ! x264enc tune=zerolatency bitrate=900 key-int-max=50 ! rtph264pay config-interval=1 ! udpsink host=$AIP port=5600" >/dev/null 2>&1 ;;
  voip)        for c in $A $B; do docker exec -d $c bash -c "timeout $((dur+2)) gst-launch-1.0 -q udpsrc port=5700 caps='application/x-rtp,media=audio,clock-rate=8000,encoding-name=PCMU,payload=0' ! rtppcmudepay ! fakesink"; done
               sleep 1
               docker exec -d $B bash -c "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audio/x-raw,rate=8000,channels=1 ! mulawenc ! rtppcmupay min-ptime=20000000 max-ptime=20000000 ! udpsink host=$AIP port=5700"
               docker exec $A bash -c "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audio/x-raw,rate=8000,channels=1 ! mulawenc ! rtppcmupay min-ptime=20000000 max-ptime=20000000 ! udpsink host=$BIP port=5700" >/dev/null 2>&1 ;;
  email)       docker exec $A bash -c "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do
                 { printf 'Subject: d\n\n'; head -c \$((500+RANDOM*(1+RANDOM%4))) /dev/urandom | base64; } | msmtp root >/dev/null 2>&1
                 sleep \$(awk 'BEGIN{srand(); print 2+rand()*6}'); done" ;;
  icmp)        docker exec $A bash -c "timeout $dur fping -l -p 1000 $BIP" >/dev/null 2>&1 ;;
  *) echo "unknown class $cls" >&2; return 2 ;;
  esac
}

case "${1:-}" in setup) setup ;; run) run "$2" "$3" ;; *) echo "usage: $0 setup | run <class> <seconds>" >&2; exit 2 ;; esac
