#!/bin/bash
# EXP-16: bring up the real servers on apps-b (lab-only content, no third party).
#   nginx (HTTPS, self-signed) serving a generated multi-asset page + an MP4
#   OpenSSH (interactive shell + SFTP) with a 50 MB file
#   Postfix (SMTP on 25, local delivery only)
#   Prosody (XMPP, two local accounts)
#   ffmpeg RTP sink is started per session by the client script
set -e
B=sih26-apps-b
docker exec -i $B bash -s <<'IN'
set -e
mkdir -p /srv/www /srv/files
# --- a real page with real assets (generated locally, not copied from the web)
python3 - <<'PY'
import os, random
random.seed(16)
os.makedirs("/srv/www/assets", exist_ok=True)
imgs = []
for i in range(8):                      # "photos": random JPEG-sized blobs
    n = random.randint(40_000, 260_000)
    open(f"/srv/www/assets/img{i}.bin", "wb").write(os.urandom(n))
    imgs.append(f"assets/img{i}.bin")
open("/srv/www/assets/site.css","w").write("body{font:16px system-ui;margin:0}"*400)
open("/srv/www/assets/app.js","w").write("window.x=%s;\n" % random.random() + "function f(){return 1}\n"*2000)
tags = "\n".join(f'<img src="{p}" width="10">' for p in imgs)
open("/srv/www/index.html","w").write(f"""<!doctype html><html><head><meta charset=utf-8>
<link rel=stylesheet href=assets/site.css><script src=assets/app.js defer></script><title>Lab page</title></head>
<body><h1>Lab page</h1><p>{'lorem ipsum dolor sit amet. ' * 400}</p>{tags}
<p>{'more text here. ' * 800}</p></body></html>""")
open("/srv/www/video.html","w").write("""<!doctype html><html><body style="margin:0">
<video src="clip.mp4" autoplay muted playsinline></video></body></html>""")
PY
# --- a real MP4 (generated test pattern + tone) and a big file for SFTP
[ -f /srv/www/clip.mp4 ] || ffmpeg -loglevel error -f lavfi -i testsrc2=size=1280x720:rate=25 \
    -f lavfi -i sine=frequency=440 -t 60 -c:v libx264 -preset veryfast -b:v 2500k -c:a aac -shortest /srv/www/clip.mp4
[ -f /srv/files/blob.bin ] || head -c 52428800 /dev/urandom > /srv/files/blob.bin
# --- TLS + nginx
[ -f /etc/ssl/private/lab.key ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout /etc/ssl/private/lab.key -out /etc/ssl/certs/lab.crt -subj "/CN=lab.test" 2>/dev/null
cat > /etc/nginx/sites-available/default <<'NG'
server {
    listen 443 ssl http2;
    ssl_certificate /etc/ssl/certs/lab.crt; ssl_certificate_key /etc/ssl/private/lab.key;
    root /srv/www; location / { add_header Cache-Control "no-store"; } 
}
server { listen 80; root /srv/www; location / { add_header Cache-Control "no-store"; } }
NG
nginx -t >/dev/null 2>&1 && (nginx -s reload 2>/dev/null || nginx)
# --- SSH (a real login for the interactive and SFTP classes)
id labuser >/dev/null 2>&1 || useradd -m -s /bin/bash labuser
echo 'labuser:labpass-not-a-secret' | chpasswd
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
ln -sf /srv/files/blob.bin /home/labuser/blob.bin
mkdir -p /run/sshd; pgrep sshd >/dev/null || /usr/sbin/sshd
# --- Postfix (accepts mail from the lab network, delivers locally)
postconf -e "inet_interfaces = all" "mynetworks = 10.10.0.0/16 127.0.0.0/8" \
         "message_size_limit = 52428800" "smtpd_recipient_restrictions = permit_mynetworks,reject" >/dev/null
postfix start >/dev/null 2>&1 || postfix reload >/dev/null 2>&1
# --- Prosody (XMPP), two local accounts
cat > /etc/prosody/prosody.cfg.lua <<'PR'
admins = {}
modules_enabled = { "roster","saslauth","tls","dialback","disco","private","vcard","ping","register","carbons","smacks" }
allow_registration = true
c2s_require_encryption = false
s2s_require_encryption = false
authentication = "internal_plain"
pidfile = "/var/run/prosody/prosody.pid"
log = { error = "/var/log/prosody/prosody.err" }
VirtualHost "lab.test"
PR
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends \
    lua-sec lua-expat lua-filesystem lua-socket lua-event lua-bitop >/dev/null 2>&1 || true
mkdir -p /var/log/prosody /var/lib/prosody && chown -R prosody:prosody /var/log/prosody /var/lib/prosody
mkdir -p /var/run/prosody && chown prosody:prosody /var/run/prosody
# Prosody refuses to run as root (it half-starts: a process exists but nothing listens), so run it as its own
# user, always from a clean start, and WAIT until port 5222 is actually open.
pkill -f "lua.*prosody" 2>/dev/null; sleep 1
touch /var/log/prosody/stdout.log && chown prosody:prosody /var/log/prosody/stdout.log
setsid su -s /bin/sh prosody -c prosody >/var/log/prosody/stdout.log 2>&1 &
for _ in $(seq 1 20); do ss -lnt 2>/dev/null | grep -q ":5222 " && break; sleep 1; done
su -s /bin/sh prosody -c "prosodyctl register alice lab.test labpass-not-a-secret" 2>/dev/null || true
su -s /bin/sh prosody -c "prosodyctl register bob lab.test labpass-not-a-secret" 2>/dev/null || true
echo "servers up: nginx $(pgrep -c nginx), sshd $(pgrep -c sshd), postfix $(pgrep -c master), prosody $(pgrep -cf "lua.*prosody")"
IN
