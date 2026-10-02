#!/bin/bash
# Labs E (training zoo) and F (final test) traffic generators for EXP-45. Every variant is a real tool; the PREREG lists which belong to which lab.
#   labef_gen.sh setup                 start the servers on labe-b (idempotent)
#   labef_gen.sh run <variant> <s>     one sustained session of <variant> from labe-a
#   labef_gen.sh mix <variantA> <variantB> <s>   two variants at once (mixed traffic)
# Variants: see VARIANTS below (class.tool).
set -uo pipefail
A=sih26-labe-a; B=sih26-labe-b; BIP=10.10.2.53; AIP=10.10.1.53

VARIANTS_E="bulk.rsync bulk.lftp bulk.curl web.curlpar web.siege web.lynx interactive.sshfast interactive.sshmid interactive.sshslow interactive.top1 interactive.top3 interactive.vim interactive.tmux video.srt300 video.srt2500 video.hlspull video.udpvbr voip.g722 voip.opus40 voip.speex messaging.redis messaging.mqtt2 messaging.redisq email.imap email.pop3 email.swaks icmp.hping icmp.nping icmp.pingrand"
VARIANTS_F="bulk.ncpv bulk.rsyncd bulk.ncdl web.nghttp web.h2load web.h2c interactive.nano interactive.watch interactive.cmatrix video.vp8 video.tstcp video.theora voip.opus60 voip.ilbc voip.gsm messaging.zmq messaging.mqtt0 messaging.zmqreq email.swakstls email.curltls email.imaps icmp.traceroute icmp.ping1000 icmp.npingts"

dA() { docker exec "$A" bash -c "$1"; }
dB() { docker exec "$B" bash -c "$1"; }
dAd() { docker exec -d "$A" bash -c "$1"; }
dBd() { docker exec -d "$B" bash -c "$1"; }

setup() {
  docker exec -i $B bash -s <<'IN'
mkdir -p /srv/www/img /srv/files /srv/hls /srv/ftp /run/sshd /root/.ssh /var/run/vsftpd/empty /tmp/rd /tmp/tls
if [ ! -f /srv/files/big400.bin ]; then
python3 - <<'PY'
import os, random
random.seed(45)
for i in range(60):
    open(f"/srv/www/img/i{i}.dat", "wb").write(os.urandom(random.choice([5_000, 18_000, 55_000, 120_000, 190_000])))
for i in range(40):
    links = " ".join(f'<a href="p{random.randrange(40)}.html">x</a>' for _ in range(5))
    imgs = " ".join(f'<img src="img/i{random.randrange(60)}.dat">' for _ in range(4))
    open(f"/srv/www/p{i}.html", "w").write(f"<html><body>{'text '*random.randint(60,900)}{links}{imgs}</body></html>")
open("/srv/www/index.html", "w").write('<a href="p0.html">p0</a>')
with open("/srv/files/big400.bin", "wb") as f:
    for _ in range(400): f.write(os.urandom(1 << 20))
PY
cp /srv/files/big400.bin /srv/ftp/big400.bin; ln -sf /srv/files/big400.bin /srv/www/big400.bin
fi
[ -f /tmp/tls/k.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/tls/k.pem -out /tmp/tls/c.pem -days 30 -subj "/CN=labe-b" >/dev/null 2>&1
# --- nginx (8080) and the HLS dir
cat > /tmp/nginx.conf <<'C'
daemon on; pid /tmp/nginx.pid; error_log /tmp/nginx.err;
events {} http { access_log off; server { listen 8080; root /srv/www; location /hls/ { alias /srv/hls/; } } }
C
ss -lnt | grep -q ":8080 " || nginx -c /tmp/nginx.conf
# --- sshd
ss -lnt | grep -q ":22 " || /usr/sbin/sshd
# --- vsftpd anonymous
cat > /tmp/vsftpd.conf <<'C'
listen=YES
anonymous_enable=YES
local_enable=NO
write_enable=NO
anon_root=/srv/ftp
seccomp_sandbox=NO
secure_chroot_dir=/var/run/vsftpd/empty
C
ss -lnt | grep -q ":21 " || (nohup vsftpd /tmp/vsftpd.conf >/tmp/vsftpd.log 2>&1 &)
# --- redis, mosquitto
ss -lnt | grep -q ":6379 " || redis-server --daemonize yes --protected-mode no --bind 0.0.0.0 >/dev/null
printf 'listener 1883\nallow_anonymous true\n' > /tmp/mq.conf
ss -lnt | grep -q ":1883 " || mosquitto -c /tmp/mq.conf -d
# --- dovecot with a populated Maildir for user lab
id lab >/dev/null 2>&1 || (useradd -m lab && echo "lab:lab" | chpasswd)
if [ ! -d /home/lab/Maildir/new ]; then
python3 - <<'PY'
import os, random
random.seed(46)
d = "/home/lab/Maildir"
for s in ("new", "cur", "tmp"): os.makedirs(f"{d}/{s}", exist_ok=True)
for i in range(60):
    body = os.urandom(random.choice([800, 3_000, 12_000, 60_000, 200_000])).hex()
    open(f"{d}/new/17900000{i:02d}.M1P1.labe-b", "w").write(f"From: a@lab\nTo: lab@labe-b\nSubject: m{i}\n\n{body}\n")
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
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
}
log_path = /tmp/dovecot.log
C
ss -lnt | grep -q ":143 " || dovecot -c /tmp/dovecot.conf
# --- postfix (SMTP 25, STARTTLS available) delivering locally
postconf -e "inet_interfaces=all" "mydestination=labe-b, localhost" "smtpd_tls_cert_file=/tmp/tls/c.pem" "smtpd_tls_key_file=/tmp/tls/k.pem" "smtpd_tls_security_level=may" "mynetworks=0.0.0.0/0" >/dev/null 2>&1
ss -lnt | grep -q ":25 " || (postfix start >/dev/null 2>&1)
# --- F: nghttpd (h2 over TLS 8443 and h2c 8081), rsync daemon, nc servers, zmq broker-less servers started per variant
cat > /tmp/rsyncd.conf <<'C'
[lab]
path = /srv/files
read only = yes
C
ss -lnt | grep -q ":873 " || rsync --daemon --config=/tmp/rsyncd.conf
ss -lnt | grep -q ":8443 " || (nohup nghttpd -d /srv/www 8443 /tmp/tls/k.pem /tmp/tls/c.pem >/tmp/nghttpd.log 2>&1 &)
ss -lnt | grep -q ":8081 " || (nohup nghttpd --no-tls -d /srv/www 8081 >/tmp/nghttpd2.log 2>&1 &)
IN
  docker exec $A bash -c "[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519; mkdir -p /tmp/rs /tmp/lf /tmp/rd"
  docker exec $A cat /root/.ssh/id_ed25519.pub | docker exec -i $B bash -c "cat > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys"
  docker exec $B bash -c "mkdir -p /tmp/work; echo 'hello world' > /tmp/work/x.txt"
}

SSH="ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -i /root/.ssh/id_ed25519"
# human-paced typing session over ssh in an expect script: $1 seconds, $2 min ms, $3 span ms, $4 gap min ms, $5 gap span ms, $6 remote command
typing() {
  dA "timeout $1 expect -c '
    set timeout 20
    set env(TERM) xterm
    set stty_init {rows 40 cols 120}
    spawn $SSH -tt root@$BIP $6
    expect -re {#|\\\$|~|\\|}
    set cmds {{ls -la /usr/bin | head} {cat /etc/os-release} {ps aux} {uptime} {free -m} {ip route} {echo hello} {date} {df -h}}
    while {1} {
      set c [lindex \$cmds [expr {int(rand()*[llength \$cmds])}]]
      foreach ch [split \$c {}] { send -- \$ch; after [expr {$2+int(rand()*$3)}] }
      send -- \"\\r\"
      after [expr {$4+int(rand()*$5)}]
    }'" >/dev/null 2>&1
}
sdp() { # $1 host-ip-of-receiver, $2 port, $3 payload type, $4 rtpmap
  printf 'v=0\no=- 0 0 IN IP4 %s\ns=call\nc=IN IP4 %s\nt=0 0\nm=audio %s RTP/AVP %s\na=rtpmap:%s %s\n' "$1" "$1" "$2" "$3" "$3" "$4"
}
gst_rx_audio() { # $1 container, $2 port, $3 caps-encoding, $4 depay, $5 seconds, $6 clock-rate
  docker exec -d "$1" bash -c "timeout $(( $5 + 2 )) gst-launch-1.0 -q udpsrc port=$2 caps='application/x-rtp,media=audio,clock-rate=$6,encoding-name=$3' ! $4 ! fakesink"
}
talk() { # half-duplex-ish talk spurts: $1 container, $2 seconds, $3 gst pipeline (ending in udpsink), $4 min spurt, $5 min silence
  docker exec "$1" bash -c "end=\$((SECONDS+$2)); while [ \$SECONDS -lt \$end ]; do s=\$(awk 'BEGIN{srand(); print $4+rand()*2}'); timeout \$s gst-launch-1.0 -q $3 >/dev/null 2>&1; sleep \$(awk 'BEGIN{srand(); print $5+rand()*2}'); done"
}

# ------------------------------------------------------------------ variants (client side, run from labe-a; server side where needed on labe-b)
v() {
  local name="$1" dur="$2"
  case "$name" in
  # ---- E
  bulk.rsync)  dA "timeout $dur rsync -a --bwlimit=1500 -e '$SSH' root@$BIP:/srv/files/big400.bin /tmp/rs/" >/dev/null 2>&1 ;;
  bulk.lftp)   dA "timeout $dur lftp -e 'set net:limit-rate 600000; get big400.bin -o /tmp/lf/big; bye' ftp://anonymous@$BIP" >/dev/null 2>&1 ;;
  bulk.curl)   dA "timeout $dur curl -s --limit-rate 700k -o /dev/null http://$BIP:8080/big400.bin" >/dev/null 2>&1 ;;
  web.curlpar) dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do p=\$((RANDOM%40)); curl -s http://$BIP:8080/p\$p.html -o /tmp/pg.html; u=\$(grep -o 'img/i[0-9]*.dat' /tmp/pg.html | sed 's#^#http://$BIP:8080/#' | tr '\n' ' '); curl -s --parallel --parallel-max 6 \$(for x in \$u; do echo -o /dev/null \$x; done) ; sleep \$(awk 'BEGIN{srand(); print 2+rand()*6}'); done" >/dev/null 2>&1 ;;
  web.siege)   dA "printf 'http://$BIP:8080/p1.html\nhttp://$BIP:8080/p2.html\nhttp://$BIP:8080/img/i3.dat\nhttp://$BIP:8080/img/i7.dat\nhttp://$BIP:8080/p9.html\n' > /tmp/urls.txt; siege -q -c3 -d3 -t${dur}S -f /tmp/urls.txt" >/dev/null 2>&1 ;;
  web.lynx)    dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do lynx -dump -nolist http://$BIP:8080/p\$((RANDOM%40)).html >/dev/null 2>&1; sleep \$(awk 'BEGIN{srand(); print 2+rand()*4}'); done" ;;
  interactive.sshfast) typing "$dur" 40 80 800 2000 "bash" ;;
  interactive.sshmid)  typing "$dur" 150 200 1500 3500 "bash" ;;
  interactive.sshslow) typing "$dur" 400 500 2500 5000 "bash" ;;
  interactive.top1)    dA "timeout $dur $SSH -tt root@$BIP 'TERM=xterm top -d 1' </dev/null" >/dev/null 2>&1 ;;
  interactive.top3)    dA "timeout $dur $SSH -tt root@$BIP 'TERM=xterm top -d 3' </dev/null" >/dev/null 2>&1 ;;
  interactive.vim)     dA "timeout $dur expect -c '
      set timeout 20
      set env(TERM) xterm
      set stty_init {rows 40 cols 120}
      spawn $SSH -tt root@$BIP vi /tmp/work/x.txt
      after 1500
      send -- \"i\"
      while {1} {
        foreach ch [split \"the quick brown fox jumps over the lazy dog \" {}] { send -- \$ch; after [expr {90+int(rand()*260)}] }
        send -- \"\\r\"
        after [expr {800+int(rand()*2500)}]
      }'" >/dev/null 2>&1 ;;
  interactive.tmux)    typing "$dur" 100 220 1200 3000 "tmux new -A -s lab" ;;
  video.srt300)  dBd "timeout $((dur+3)) ffmpeg -loglevel quiet -i 'srt://0.0.0.0:9100?mode=listener' -f null -" ; sleep 1
                 dA "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=640x360:rate=25 -c:v libx264 -preset ultrafast -b:v 300k -f mpegts 'srt://$BIP:9100?mode=caller'" >/dev/null 2>&1 ;;
  video.srt2500) dAd "timeout $((dur+3)) ffmpeg -loglevel quiet -i 'srt://0.0.0.0:9101?mode=listener' -f null -" ; sleep 1
                 dB "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=1280x720:rate=30 -c:v libx264 -preset ultrafast -b:v 2500k -f mpegts 'srt://$AIP:9101?mode=caller'" >/dev/null 2>&1 ;;
  video.hlspull) dBd "rm -f /srv/hls/*; timeout $((dur+4)) ffmpeg -loglevel quiet -re -f lavfi -i testsrc2=size=854x480:rate=25 -c:v libx264 -preset ultrafast -b:v 1200k -g 50 -f hls -hls_time 2 -hls_list_size 6 -hls_flags delete_segments /srv/hls/live.m3u8"; sleep 5
                 dA "end=\$((SECONDS+$dur)); last=''; while [ \$SECONDS -lt \$end ]; do curl -s http://$BIP:8080/hls/live.m3u8 -o /tmp/l.m3u8; for s in \$(grep -o 'live[0-9]*.ts' /tmp/l.m3u8); do [ -f /tmp/seg_\$s ] || { curl -s http://$BIP:8080/hls/\$s -o /tmp/seg_\$s; }; done; sleep 2; done" >/dev/null 2>&1 ;;
  video.udpvbr)  dAd "timeout $((dur+3)) ffmpeg -loglevel quiet -i 'udp://$AIP:5710?fifo_size=5000000&overrun_nonfatal=1' -f null -"; sleep 1
                 dB "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'testsrc2=size=1280x720:rate=30,noise=alls=20:allf=t' -c:v libx264 -preset ultrafast -b:v 6000k -maxrate 9000k -bufsize 3000k -f mpegts 'udp://$AIP:5710?pkt_size=1316'" >/dev/null 2>&1 ;;
  voip.g722)     sdp $AIP 5720 9 "G722/8000" | dA "cat > /tmp/a.sdp"; sdp $BIP 5722 9 "G722/8000" | dB "cat > /tmp/b.sdp"
                 dAd "timeout $((dur+3)) ffmpeg -loglevel quiet -protocol_whitelist file,udp,rtp -i /tmp/a.sdp -f null -"; dBd "timeout $((dur+3)) ffmpeg -loglevel quiet -protocol_whitelist file,udp,rtp -i /tmp/b.sdp -f null -"; sleep 1
                 dBd "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=300' -ar 16000 -c:a g722 -f rtp rtp://$AIP:5720"
                 dA "timeout $dur ffmpeg -loglevel quiet -re -f lavfi -i 'sine=frequency=500' -ar 16000 -c:a g722 -f rtp rtp://$BIP:5722" >/dev/null 2>&1 ;;
  voip.opus40)   gst_rx_audio $A 5730 OPUS rtpopusdepay $dur 48000; gst_rx_audio $B 5732 OPUS rtpopusdepay $dur 48000; sleep 1
                 talk $B "$dur" "audiotestsrc is-live=true freq=300 ! audioconvert ! audioresample ! opusenc frame-size=40 ! rtpopuspay ! udpsink host=$AIP port=5730" 1 1 >/dev/null 2>&1 &
                 talk $A "$dur" "audiotestsrc is-live=true freq=500 ! audioconvert ! audioresample ! opusenc frame-size=40 ! rtpopuspay ! udpsink host=$BIP port=5732" 1 2 >/dev/null 2>&1; wait ;;
  voip.speex)    gst_rx_audio $A 5740 SPEEX rtpspeexdepay $dur 8000; gst_rx_audio $B 5742 SPEEX rtpspeexdepay $dur 8000; sleep 1
                 dBd "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audio/x-raw,rate=8000,channels=1 ! speexenc ! rtpspeexpay ! udpsink host=$AIP port=5740"
                 dA "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audio/x-raw,rate=8000,channels=1 ! speexenc ! rtpspeexpay ! udpsink host=$BIP port=5742" >/dev/null 2>&1 ;;
  messaging.redis) dAd "timeout $((dur+2)) redis-cli -h $BIP subscribe chanb >/dev/null"; dBd "timeout $((dur+2)) redis-cli -h $BIP subscribe chana >/dev/null"; sleep 1
                 dBd "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do redis-cli -h $BIP publish chanb \"\$(head -c \$((10+RANDOM%150)) /dev/urandom | base64 -w0)\" >/dev/null; sleep \$(awk 'BEGIN{srand(); print 0.5+rand()*4}'); done"
                 dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do redis-cli -h $BIP publish chana \"\$(head -c \$((10+RANDOM%150)) /dev/urandom | base64 -w0)\" >/dev/null; sleep \$(awk 'BEGIN{srand(); print 0.5+rand()*4}'); done" ;;
  messaging.mqtt2) dAd "timeout $((dur+2)) mosquitto_sub -h $BIP -q 2 -t 'm/b' >/dev/null"; dBd "timeout $((dur+2)) mosquitto_sub -h $BIP -q 2 -t 'm/a' >/dev/null"; sleep 1
                 dBd "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do mosquitto_pub -h $BIP -q 2 -r -t m/b -m \"\$(head -c \$((10+RANDOM%120)) /dev/urandom | base64 -w0)\"; sleep \$(awk 'BEGIN{srand(); print 0.6+rand()*4}'); done"
                 dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do mosquitto_pub -h $BIP -q 2 -r -t m/a -m \"\$(head -c \$((10+RANDOM%120)) /dev/urandom | base64 -w0)\"; sleep \$(awk 'BEGIN{srand(); print 0.6+rand()*4}'); done" ;;
  messaging.redisq) dBd "timeout $((dur+2)) bash -c 'while true; do m=\$(redis-cli -h $BIP brpop q 2 | tail -1); [ -n \"\$m\" ] && redis-cli -h $BIP lpush ack ok >/dev/null; done'"; sleep 1
                 dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do redis-cli -h $BIP lpush q \"\$(head -c \$((20+RANDOM%200)) /dev/urandom | base64 -w0)\" >/dev/null; redis-cli -h $BIP brpop ack 2 >/dev/null; sleep \$(awk 'BEGIN{srand(); print 0.4+rand()*3}'); done" ;;
  email.imap)    dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do curl -s -k --ssl-reqd --url \"imap://$BIP/INBOX;MAILINDEX=\$((1+RANDOM%60))\" -u lab:lab -o /dev/null; sleep \$(awk 'BEGIN{srand(); print 1.5+rand()*5}'); done" >/dev/null 2>&1 ;;
  email.pop3)    dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do curl -s -k --ssl-reqd --url \"pop3://$BIP/\$((1+RANDOM%60))\" -u lab:lab -o /dev/null; sleep \$(awk 'BEGIN{srand(); print 1.5+rand()*5}'); done" >/dev/null 2>&1 ;;
  email.swaks)   dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do head -c \$((600+RANDOM*(1+RANDOM%4))) /dev/urandom | base64 > /tmp/body.txt; swaks --server $BIP --to lab@labe-b --from a@lab --body @/tmp/body.txt >/dev/null 2>&1; sleep \$(awk 'BEGIN{srand(); print 2+rand()*6}'); done" >/dev/null 2>&1 ;;
  icmp.hping)    dA "timeout $dur hping3 -1 -d \$((20+RANDOM%1100)) -i u\$((300000+RANDOM*30)) $BIP" >/dev/null 2>&1 ;;
  icmp.nping)    dA "timeout $dur nping --icmp -c 1000 --delay 0.5s --data-length \$((20+RANDOM%1100)) $BIP" >/dev/null 2>&1 ;;
  icmp.pingrand) dA "timeout $dur ping -s \$((56+RANDOM%1300)) -i \$(awk 'BEGIN{srand(); print 0.2+rand()*1.8}') $BIP" >/dev/null 2>&1 ;;
  # ---- F
  bulk.ncpv)     dBd "timeout $((dur+3)) nc -l 5570 >/dev/null"; sleep 1; dA "timeout $dur bash -c 'pv -q -L 600k /dev/urandom | nc $BIP 5570'" >/dev/null 2>&1 ;;
  bulk.rsyncd)   dA "timeout $dur rsync -a --bwlimit=3000 rsync://$BIP/lab/big400.bin /tmp/rd/" >/dev/null 2>&1 ;;
  bulk.ncdl)     dBd "timeout $((dur+3)) nc -l 5571 < /srv/files/big400.bin"; sleep 1; dA "timeout $dur bash -c 'nc $BIP 5571 | pv -q -L 800k >/dev/null'" >/dev/null 2>&1 ;;
  web.nghttp)    dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do nghttp -ans https://$BIP:8443/p\$((RANDOM%40)).html >/dev/null 2>&1; sleep \$(awk 'BEGIN{srand(); print 2+rand()*5}'); done" ;;
  web.h2load)    dA "h2load -n 100000 -c 1 -m 4 --rps 4 -D $dur https://$BIP:8443/img/i5.dat" >/dev/null 2>&1 ;;
  web.h2c)       dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do curl -s --http2-prior-knowledge http://$BIP:8081/p\$((RANDOM%40)).html -o /tmp/p.html; for i in 1 2 3; do curl -s --http2-prior-knowledge http://$BIP:8081/img/i\$((RANDOM%60)).dat -o /dev/null; done; sleep \$(awk 'BEGIN{srand(); print 1.5+rand()*5}'); done" >/dev/null 2>&1 ;;
  interactive.nano) dA "timeout $dur expect -c '
      set timeout 20
      set env(TERM) xterm
      set stty_init {rows 40 cols 120}
      spawn $SSH -tt root@$BIP nano /tmp/work/y.txt
      while {1} {
        foreach ch [split \"the quick brown fox jumps over the lazy dog \" {}] { send -- \$ch; after [expr {110+int(rand()*300)}] }
        send -- \"\\r\"
        after [expr {1000+int(rand()*3000)}]
      }'" >/dev/null 2>&1 ;;
  interactive.watch)   dA "timeout $dur $SSH -tt root@$BIP 'TERM=xterm watch -n 0.5 date' </dev/null" >/dev/null 2>&1 ;;
  interactive.cmatrix) dA "timeout $dur $SSH -tt root@$BIP 'TERM=xterm cmatrix -b -u 5' </dev/null" >/dev/null 2>&1 ;;
  video.vp8)     dAd "timeout $((dur+2)) gst-launch-1.0 -q udpsrc port=5750 caps='application/x-rtp,media=video,encoding-name=VP8,payload=96,clock-rate=90000' ! rtpvp8depay ! fakesink"; sleep 1
                 dB "timeout $dur gst-launch-1.0 -q videotestsrc is-live=true pattern=smpte ! video/x-raw,width=640,height=360,framerate=25/1 ! vp8enc deadline=1 target-bitrate=800000 keyframe-max-dist=50 ! rtpvp8pay ! udpsink host=$AIP port=5750" >/dev/null 2>&1 ;;
  video.tstcp)   dAd "timeout $((dur+2)) gst-launch-1.0 -q tcpclientsrc host=$BIP port=5760 ! fakesink"; dBd "timeout $((dur+3)) gst-launch-1.0 -q videotestsrc is-live=true pattern=ball ! video/x-raw,width=640,height=360,framerate=25/1 ! x264enc tune=zerolatency bitrate=1000 ! mpegtsmux ! tcpserversink host=0.0.0.0 port=5760"; sleep $dur ;;
  video.theora)  dAd "timeout $((dur+2)) gst-launch-1.0 -q udpsrc port=5770 caps='application/x-rtp,media=video,encoding-name=THEORA,clock-rate=90000,payload=96' ! rtptheoradepay ! fakesink"; sleep 1
                 dB "timeout $dur gst-launch-1.0 -q videotestsrc is-live=true pattern=snow ! video/x-raw,width=480,height=270,framerate=20/1 ! theoraenc bitrate=700 ! rtptheorapay config-interval=2 ! udpsink host=$AIP port=5770" >/dev/null 2>&1 ;;
  voip.opus60)   gst_rx_audio $A 5780 OPUS rtpopusdepay $dur 48000; gst_rx_audio $B 5782 OPUS rtpopusdepay $dur 48000; sleep 1
                 dBd "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audioconvert ! audioresample ! opusenc frame-size=60 ! rtpopuspay ! udpsink host=$AIP port=5780"
                 dA "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audioconvert ! audioresample ! opusenc frame-size=60 ! rtpopuspay ! udpsink host=$BIP port=5782" >/dev/null 2>&1 ;;
  voip.ilbc)     gst_rx_audio $A 5790 ILBC rtpilbcdepay $dur 8000; gst_rx_audio $B 5792 ILBC rtpilbcdepay $dur 8000; sleep 1
                 dBd "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audio/x-raw,rate=8000,channels=1 ! ilbcenc mode=30 ! rtpilbcpay mode=30 ! udpsink host=$AIP port=5790"
                 dA "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audio/x-raw,rate=8000,channels=1 ! ilbcenc mode=30 ! rtpilbcpay mode=30 ! udpsink host=$BIP port=5792" >/dev/null 2>&1 ;;
  voip.gsm)      gst_rx_audio $A 5800 GSM rtpgsmdepay $dur 8000; gst_rx_audio $B 5802 GSM rtpgsmdepay $dur 8000; sleep 1
                 dBd "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=300 ! audio/x-raw,rate=8000,channels=1 ! gsmenc ! rtpgsmpay ! udpsink host=$AIP port=5800"
                 dA "timeout $dur gst-launch-1.0 -q audiotestsrc is-live=true freq=500 ! audio/x-raw,rate=8000,channels=1 ! gsmenc ! rtpgsmpay ! udpsink host=$BIP port=5802" >/dev/null 2>&1 ;;
  messaging.zmq) dBd "timeout $((dur+3)) python3 -c \"
import zmq,time,random,os
c=zmq.Context(); p=c.socket(zmq.PUB); p.bind('tcp://0.0.0.0:5810'); s=c.socket(zmq.SUB); s.connect('tcp://$AIP:5811'); s.setsockopt(zmq.SUBSCRIBE,b'')
e=time.time()+$dur
while time.time()<e:
    p.send(os.urandom(random.randint(10,150))); time.sleep(0.5+random.random()*4)
\""; dAd "timeout $((dur+3)) python3 -c \"
import zmq
c=zmq.Context(); s=c.socket(zmq.SUB); s.connect('tcp://$BIP:5810'); s.setsockopt(zmq.SUBSCRIBE,b'')
while True: s.recv()
\""
                 dA "python3 -c \"
import zmq,time,random,os
c=zmq.Context(); p=c.socket(zmq.PUB); p.bind('tcp://0.0.0.0:5811')
e=time.time()+$dur
while time.time()<e:
    p.send(os.urandom(random.randint(10,150))); time.sleep(0.5+random.random()*4)
\"" >/dev/null 2>&1 ;;
  messaging.mqtt0) dBd "timeout $((dur+2)) mosquitto_sub -h $BIP -q 0 -t 'f/#' >/dev/null"; sleep 1
                 dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do mosquitto_pub -h $BIP -q 0 -t f/a -m \"\$(head -c \$((6+RANDOM%40)) /dev/urandom | base64 -w0)\"; sleep \$(awk 'BEGIN{srand(); print 0.1+rand()*0.9}'); done" >/dev/null 2>&1 ;;
  messaging.zmqreq) dBd "timeout $((dur+3)) python3 -c \"
import zmq,os,random
c=zmq.Context(); r=c.socket(zmq.REP); r.bind('tcp://0.0.0.0:5812')
while True: r.recv(); r.send(os.urandom(random.randint(8,90)))
\""; sleep 1
                 dA "timeout $((dur+1)) python3 -c \"
import zmq,os,random,time
c=zmq.Context(); q=c.socket(zmq.REQ); q.connect('tcp://$BIP:5812')
e=time.time()+$dur
while time.time()<e:
    q.send(os.urandom(random.randint(10,160))); q.recv(); time.sleep(0.5+random.random()*3.5)
\"" >/dev/null 2>&1 ;;
  email.swakstls) dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do head -c \$((900+RANDOM*(1+RANDOM%3))) /dev/urandom | base64 > /tmp/body.txt; swaks --tls --server $BIP --to lab@labe-b --from a@lab --body @/tmp/body.txt >/dev/null 2>&1; sleep \$(awk 'BEGIN{srand(); print 2+rand()*6}'); done" >/dev/null 2>&1 ;;
  email.curltls)  dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do { printf 'From: a@lab\r\nTo: lab@labe-b\r\nSubject: s\r\n\r\n'; head -c \$((500+RANDOM*(1+RANDOM%3))) /dev/urandom | base64; } > /tmp/m.txt; curl -s -k --ssl-reqd --url smtp://$BIP:25 --mail-from a@lab --mail-rcpt lab@labe-b -T /tmp/m.txt >/dev/null; sleep \$(awk 'BEGIN{srand(); print 2+rand()*6}'); done" >/dev/null 2>&1 ;;
  email.imaps)    dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do curl -s -k --url \"imaps://$BIP/INBOX;MAILINDEX=\$((1+RANDOM%60))\" -u lab:lab -o /dev/null; sleep \$(awk 'BEGIN{srand(); print 1.5+rand()*5}'); done" >/dev/null 2>&1 ;;
  icmp.traceroute) dA "end=\$((SECONDS+$dur)); while [ \$SECONDS -lt \$end ]; do traceroute -I -q 3 -w 1 -m 12 $BIP >/dev/null 2>&1; sleep 1; done" >/dev/null 2>&1 ;;
  icmp.ping1000)  dA "timeout $dur ping -s 1000 -i 0.3 $BIP" >/dev/null 2>&1 ;;
  icmp.npingts)   dA "timeout $dur nping --icmp --icmp-type time -c 1000 --delay 0.6s $BIP" >/dev/null 2>&1 ;;
  *) echo "unknown variant $name" >&2; return 2 ;;
  esac
}

case "${1:-}" in
  setup) setup ;;
  run)   v "$2" "$3" ;;
  mix)   v "$2" "$4" & v "$3" "$4"; wait ;;
  list)  echo "E: $VARIANTS_E"; echo "F: $VARIANTS_F" ;;
  *) echo "usage: $0 setup | run <variant> <s> | mix <v1> <v2> <s> | list" >&2; exit 2 ;;
esac
