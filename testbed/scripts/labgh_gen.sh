#!/bin/bash
# Labs H (training, three link speeds) and G (final test) traffic generators for EXP-51. Every variant is a real tool or a real
# protocol exchange (testbed/images/labgh/labgh_tool.py); the lists below fix which belongs to which lab. No lab-H tool is a lab-G tool.
#   labgh_gen.sh setup                 start the servers on labg-b (idempotent)
#   labgh_gen.sh run <variant> <s>     one sustained session of <variant> from labg-a
#   labgh_gen.sh mix <variantA> <variantB> <s>   two variants at once (mixed traffic)
set -uo pipefail
A=sih26-labg-a; B=sih26-labg-b; BIP=10.10.2.54; AIP=10.10.1.54
T="python3 /usr/local/bin/labgh_tool.py"

VARIANTS_H="bulk.axel bulk.scp bulk.wgetcap web.chromium web.chromiumtls web.w3m interactive.sshpy interactive.sshless interactive.socatsh video.dash video.rtpjpeg video.mpeg4rtp voip.g726 voip.l16 voip.amrnb messaging.ws messaging.udpchat messaging.longpoll email.smtps email.pop3s email.imapsync icmp.mtr icmp.pingfast icmp.pyrand"
VARIANTS_G="bulk.sftp bulk.pyhttp web.firefox web.pyreq interactive.sshmc interactive.sshbc video.httplive video.rtpmp2v voip.siren voip.alaw60 messaging.sse messaging.tcpjson email.pysmtp email.mailx icmp.ping200 icmp.ping1s"

dA() { docker exec "$A" bash -c "$1"; }
dB() { docker exec "$B" bash -c "$1"; }
dAd() { docker exec -d "$A" bash -c "$1"; }
dBd() { docker exec -d "$B" bash -c "$1"; }
sink() { docker exec -d "$1" bash -c "timeout $(( $3 + 3 )) socat -u UDP-RECV:$2 /dev/null"; }   # a listener, so no ICMP port-unreachable comes back

setup() {
  docker exec -i $B bash -s <<'IN'
mkdir -p /run/sshd /root/.ssh /tmp/tls
python3 /usr/local/bin/labgh_tool.py site
[ -f /tmp/tls/k.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/tls/k.pem -out /tmp/tls/c.pem -days 30 -subj "/CN=labg-b" >/dev/null 2>&1
cat > /tmp/nginx.conf <<'C'
daemon on; pid /tmp/nginx.pid; error_log /tmp/nginx.err;
events {} http { access_log off; sendfile on;
  server { listen 8080; listen 8443 ssl http2; ssl_certificate /tmp/tls/c.pem; ssl_certificate_key /tmp/tls/k.pem;
           root /srv/site; location /dash/ { autoindex on; add_header Cache-Control no-store; } location /files/ { alias /srv/files/; } } }
C
ss -lnt | grep -q ":8080 " || nginx -c /tmp/nginx.conf
ss -lnt | grep -q ":22 " || /usr/sbin/sshd
id lab >/dev/null 2>&1 || (useradd -m lab && echo "lab:lab" | chpasswd)
if [ ! -d /home/lab/Maildir/new ]; then
python3 - <<'PY'
import os, random
random.seed(52)
d = "/home/lab/Maildir"
for s in ("new", "cur", "tmp"): os.makedirs(f"{d}/{s}", exist_ok=True)
for i in range(60):
    body = os.urandom(random.choice([600, 2_500, 9_000, 40_000, 150_000, 400_000])).hex()
    open(f"{d}/new/17910000{i:02d}.M1P1.labg-b", "w").write(f"From: a@lab\nTo: lab@labg-b\nSubject: m{i}\nDate: Wed, 07 Oct 2026 10:00:00 +0000\n\n{body}\n")
PY
chown -R lab:lab /home/lab/Maildir
fi
cat > /tmp/dovecot.conf <<'C'
protocols = imap pop3
listen = *
disable_plaintext_auth = no
auth_mechanisms = plain login
mail_location = maildir:~/Maildir
passdb {
  driver = pam
}
userdb {
  driver = passwd
}
ssl = yes
ssl_cert = </tmp/tls/c.pem
ssl_key = </tmp/tls/k.pem
log_path = /tmp/dovecot.log
C
ss -lnt | grep -q ":993 " || dovecot -c /tmp/dovecot.conf
postconf -e "inet_interfaces=all" "myhostname=labg-b" "mydestination=labg-b, localhost" "smtpd_tls_cert_file=/tmp/tls/c.pem" "smtpd_tls_key_file=/tmp/tls/k.pem" "smtpd_tls_security_level=may" "mynetworks=0.0.0.0/0" "message_size_limit=30000000" "mailbox_size_limit=0" "home_mailbox=Maildir/" >/dev/null 2>&1
postconf -M "smtps/inet=smtps inet n - y - - smtpd -o smtpd_tls_wrappermode=yes" >/dev/null 2>&1
ss -lnt | grep -q ":25 " || (postfix start >/dev/null 2>&1)
ss -lnt | grep -q ":5902 " || (nohup python3 /usr/local/bin/labgh_tool.py serve >/tmp/serve.log 2>&1 &)
IN
  docker exec -i $A bash -s <<IN
[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
[ -f /tmp/up.bin ] || head -c 150000000 /dev/urandom > /tmp/up.bin
postconf -e "inet_interfaces=loopback-only" "myhostname=labg-a" "relayhost=[$BIP]" "message_size_limit=30000000" >/dev/null 2>&1
ss -lnt | grep -q ":25 " || (postfix start >/dev/null 2>&1)
IN
  docker exec $A cat /root/.ssh/id_ed25519.pub | docker exec -i $B bash -c "cat > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys"
}

SSHO="-o StrictHostKeyChecking=no -o LogLevel=ERROR -i /root/.ssh/id_ed25519"
SSH="ssh $SSHO"
# an expect session: $1 seconds, $2 spawn command, $3 Tcl list of things to send, $4 per-key min ms, $5 per-key span ms, $6 gap min ms, $7 gap span ms, $8 line end
typed() {
  dA "timeout $1 expect -c '
    set timeout 20
    set env(TERM) xterm
    set stty_init {rows 40 cols 120}
    spawn $2
    after 1500
    set items $3
    while {1} {
      set c [lindex \$items [expr {int(rand()*[llength \$items])}]]
      foreach ch [split \$c {}] { send -- \$ch; after [expr {$4+int(rand()*$5)}] }
      send -- \"$8\"
      after [expr {$6+int(rand()*$7)}]
    }'" >/dev/null 2>&1
}
# single key presses (no typing): $1 seconds, $2 spawn command, $3 Tcl list of keys, $4 gap min ms, $5 gap span ms
keys() {
  dA "timeout $1 expect -c '
    set timeout 20
    set env(TERM) xterm
    set stty_init {rows 40 cols 120}
    spawn $2
    after 1500
    set items $3
    while {1} {
      send -- [lindex \$items [expr {int(rand()*[llength \$items])}]]
      after [expr {$4+int(rand()*$5)}]
    }'" >/dev/null 2>&1
}
rnd() { echo "\$(awk 'BEGIN{srand(); print $1+rand()*$2}')"; }
talk() { # talk spurts: $1 container, $2 seconds, $3 gst pipeline, $4 min spurt s, $5 min silence s
  docker exec "$1" bash -c "end=\$((SECONDS+$2)); while [ \$SECONDS -lt \$end ]; do s=\$(awk 'BEGIN{srand(); print $4+rand()*3}'); timeout \$s gst-launch-1.0 -q $3 >/dev/null 2>&1; sleep \$(awk 'BEGIN{srand(); print $5+rand()*2}'); done"
}
PYLINES='{{print(sum(range(1000)))} {import os} {os.getcwd()} {[x*x for x in range(12)]} {len(dir(os))} {"abc".upper()} {2**64} {help} {sorted(os.environ)[:3]}}'
SHLINES='{{ls -la /usr/bin | head} {cat /etc/os-release} {ps aux | head -20} {uptime} {free -m} {ip route} {echo hello} {date} {df -h}}'
BCLINES='{{12345*6789} {2^64} {scale=20; 22/7} {sqrt(2)} {355/113} {17%5} {1000000/7} {3.14159*2*2}}'

v() {
  local name="$1" dur="$2"
  case "$name" in
  # ---- H (training)
  bulk.axel)    dA "timeout $dur bash -c 'while true; do rm -f /tmp/ax.bin*; axel -q -n 4 -o /tmp/ax.bin http://$BIP:8080/files/big.bin; done'" >/dev/null 2>&1 ;;
  bulk.scp)     dA "timeout $dur bash -c 'while true; do scp -q $SSHO /tmp/up.bin root@$BIP:/tmp/up.bin; done'" >/dev/null 2>&1 ;;
  bulk.wgetcap) dA "timeout $dur wget -q --limit-rate=300k -O /dev/null http://$BIP:8080/files/big.bin" >/dev/null 2>&1 ;;
  web.chromium) dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do d=\$(mktemp -d); timeout 25 chromium --headless --no-sandbox --disable-gpu --disable-dev-shm-usage --user-data-dir=\$d --virtual-time-budget=8000 --dump-dom http://$BIP:8080/p\$((RANDOM%40)).html >/dev/null 2>&1; rm -rf \$d; sleep $(rnd 2 5); done" >/dev/null 2>&1 ;;
  web.chromiumtls) dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do d=\$(mktemp -d); timeout 25 chromium --headless --no-sandbox --disable-gpu --disable-dev-shm-usage --ignore-certificate-errors --user-data-dir=\$d --virtual-time-budget=8000 --dump-dom https://$BIP:8443/p\$((RANDOM%40)).html >/dev/null 2>&1; rm -rf \$d; sleep $(rnd 2 5); done" >/dev/null 2>&1 ;;
  web.w3m)      dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do w3m -dump http://$BIP:8080/p\$((RANDOM%40)).html >/dev/null 2>&1; sleep $(rnd 2 3); done" >/dev/null 2>&1 ;;
  interactive.sshpy)   typed "$dur" "$SSH -tt root@$BIP python3 -q" "$PYLINES" 70 220 1200 3500 '\\r' ;;
  interactive.sshless) keys "$dur" "$SSH -tt root@$BIP less /srv/files/big.txt" '{{ } {j} {j} {k} {d} {u} {G} {g} {/ipsum\\r} {n}}' 300 2700 ;;
  interactive.socatsh) dBd "timeout $((dur+4)) socat TCP-LISTEN:5900,reuseaddr EXEC:'bash -li',pty,stderr,setsid,sigint,sane"; sleep 1
                       typed "$dur" "socat -,raw,echo=0 TCP:$BIP:5900" "$SHLINES" 60 200 1000 3000 '\\r' ;;
  video.dash)   dBd "rm -f /srv/site/dash/*; timeout $((dur+6)) ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=854x480:rate=25 -c:v libx264 -preset ultrafast -b:v 1200k -g 50 -f dash -seg_duration 2 -window_size 5 -extra_window_size 2 /srv/site/dash/live.mpd"; sleep 5
                dA "$T dashpull $BIP $dur" >/dev/null 2>&1 ;;
  video.rtpjpeg) sink $A 5920 "$dur"
                dB "timeout $dur gst-launch-1.0 -q videotestsrc is-live=true pattern=ball ! video/x-raw,width=640,height=360,framerate=15/1 ! videoconvert ! video/x-raw,format=I420 ! jpegenc quality=60 ! rtpjpegpay ! udpsink host=$AIP port=5920" >/dev/null 2>&1 ;;
  video.mpeg4rtp) sink $A 5930 "$dur"; sink $A 5931 "$dur"
                dB "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=640x360:rate=25 -c:v mpeg4 -b:v 1200k -f rtp rtp://$AIP:5930" >/dev/null 2>&1 ;;
  voip.g726)    for p in 5940 5941; do sink $A $p "$dur"; sink $B $p "$dur"; done
                dBd "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=300' -ar 8000 -ac 1 -c:a g726 -b:a 32k -f rtp 'rtp://$AIP:5940?pkt_size=92'"
                dA "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=500' -ar 8000 -ac 1 -c:a g726 -b:a 32k -f rtp 'rtp://$BIP:5940?pkt_size=92'" >/dev/null 2>&1 ;;
  voip.l16)     sink $A 5950 "$dur"; sink $B 5950 "$dur"
                dBd "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audio/x-raw,rate=8000,channels=1 ! audioconvert ! rtpL16pay min-ptime=20000000 max-ptime=20000000 ! udpsink host=$AIP port=5950"
                dA "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audio/x-raw,rate=8000,channels=1 ! audioconvert ! rtpL16pay min-ptime=20000000 max-ptime=20000000 ! udpsink host=$BIP port=5950" >/dev/null 2>&1 ;;
  voip.amrnb)   for p in 5960 5961; do sink $A $p "$dur"; sink $B $p "$dur"; done
                dBd "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=300' -ar 8000 -ac 1 -c:a libopencore_amrnb -b:a 12.2k -f rtp rtp://$AIP:5960"
                dA "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=500' -ar 8000 -ac 1 -c:a libopencore_amrnb -b:a 12.2k -f rtp rtp://$BIP:5960" >/dev/null 2>&1 ;;
  messaging.ws)       dA "$T ws $BIP $dur" >/dev/null 2>&1 ;;
  messaging.udpchat)  dA "$T udpchat $BIP $dur" >/dev/null 2>&1 ;;
  messaging.longpoll) dA "$T longpoll $BIP $dur" >/dev/null 2>&1 ;;
  email.smtps)  dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do { printf 'From: a@lab\r\nTo: lab@labg-b\r\nSubject: s\r\n\r\n'; head -c \$((2000+RANDOM*(1+RANDOM%30))) /dev/urandom | base64; } > /tmp/m.txt; curl -s -k --url smtps://$BIP:465 --mail-from a@lab --mail-rcpt lab@labg-b -T /tmp/m.txt >/dev/null; sleep $(rnd 2 5); done" >/dev/null 2>&1 ;;
  email.pop3s)  dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do curl -s -k --url pop3s://$BIP/\$((1+RANDOM%60)) -u lab:lab -o /dev/null; sleep $(rnd 1.5 4.5); done" >/dev/null 2>&1 ;;
  email.imapsync) dA "$T imapsync $BIP $dur" >/dev/null 2>&1 ;;
  icmp.mtr)      dA "timeout $dur bash -c 'while true; do mtr -r -n -c 30 -i 0.4 $BIP >/dev/null; done'" >/dev/null 2>&1 ;;
  icmp.pingfast) dA "timeout $dur ping -i 0.05 -s 64 $BIP" >/dev/null 2>&1 ;;
  icmp.pyrand)   dA "$T pyicmp $BIP $dur" >/dev/null 2>&1 ;;
  # ---- G (test only)
  bulk.sftp)    dA "timeout $dur bash -c 'while true; do echo \"get /srv/files/big.bin /tmp/sf.bin\" | sftp -q $SSHO -b - root@$BIP; done'" >/dev/null 2>&1 ;;
  bulk.pyhttp)  dA "$T pyhttpdl $BIP $dur" >/dev/null 2>&1 ;;
  web.firefox)  dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do d=\$(mktemp -d); timeout 30 firefox-esr --headless --profile \$d --screenshot /tmp/s.png http://$BIP:8080/p\$((RANDOM%40)).html >/dev/null 2>&1; rm -rf \$d; sleep $(rnd 2 4); done" >/dev/null 2>&1 ;;
  web.pyreq)    dA "$T pyreq $BIP $dur" >/dev/null 2>&1 ;;
  interactive.sshmc) keys "$dur" "$SSH -tt root@$BIP mc -x" '{{\\033\\[B} {\\033\\[B} {\\033\\[A} {\\t} {\\r} {\\033\\[6~} {\\033\\[5~}}' 250 2250 ;;
  interactive.sshbc) typed "$dur" "$SSH -tt root@$BIP bc -q" "$BCLINES" 90 260 1000 3500 '\\r' ;;
  video.httplive) dBd "timeout $((dur+4)) ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=854x480:rate=25 -c:v libx264 -preset ultrafast -b:v 1500k -g 50 -f matroska -listen 1 http://0.0.0.0:5970/live"; sleep 2
                dA "timeout $dur curl -s http://$BIP:5970/live -o /dev/null" >/dev/null 2>&1 ;;
  video.rtpmp2v) sink $A 5980 "$dur"; sink $A 5981 "$dur"
                dB "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=640x360:rate=25 -c:v mpeg2video -b:v 1200k -f rtp rtp://$AIP:5980" >/dev/null 2>&1 ;;
  voip.siren)   sink $A 5990 "$dur"; sink $B 5990 "$dur"
                dBd "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audioresample ! audioconvert ! audio/x-raw,rate=16000,channels=1 ! sirenenc ! rtpsirenpay ! udpsink host=$AIP port=5990"
                dA "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audioresample ! audioconvert ! audio/x-raw,rate=16000,channels=1 ! sirenenc ! rtpsirenpay ! udpsink host=$BIP port=5990" >/dev/null 2>&1 ;;
  voip.alaw60)  sink $A 6000 "$dur"; sink $B 6000 "$dur"
                talk $B "$dur" "audiotestsrc is-live=true freq=300 ! audio/x-raw,rate=8000,channels=1 ! alawenc ! rtppcmapay min-ptime=60000000 max-ptime=60000000 ! udpsink host=$AIP port=6000" 2 1 >/dev/null 2>&1 &
                talk $A "$dur" "audiotestsrc is-live=true freq=500 ! audio/x-raw,rate=8000,channels=1 ! alawenc ! rtppcmapay min-ptime=60000000 max-ptime=60000000 ! udpsink host=$BIP port=6000" 2 1 >/dev/null 2>&1; wait ;;
  messaging.sse)     dA "$T sse $BIP $dur" >/dev/null 2>&1 ;;
  messaging.tcpjson) dA "$T tcpjson $BIP $dur" >/dev/null 2>&1 ;;
  email.pysmtp) dA "$T pysmtp $BIP $dur" >/dev/null 2>&1 ;;
  email.mailx)  dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do head -c \$((1500+RANDOM*(1+RANDOM%8))) /dev/urandom | base64 | mail -s \"note \$RANDOM\" lab@labg-b; sleep $(rnd 2 5); done" >/dev/null 2>&1 ;;
  icmp.ping200) dA "timeout $dur ping -i 0.2 -s 120 $BIP" >/dev/null 2>&1 ;;
  icmp.ping1s)  dA "timeout $dur ping -i 1 -s 600 $BIP" >/dev/null 2>&1 ;;
  *) echo "unknown variant $name" >&2; return 2 ;;
  esac
}

case "${1:-}" in
  setup) setup ;;
  run)   v "$2" "$3" ;;
  mix)   v "$2" "$4" & v "$3" "$4"; wait ;;
  list)  echo "H: $VARIANTS_H"; echo "G: $VARIANTS_G" ;;
  *) echo "usage: $0 setup | run <variant> <s> | mix <v1> <v2> <s> | list" >&2; exit 2 ;;
esac
