#!/usr/bin/env python3
"""Small servers and clients for labs H and G (EXP-51), standard library plus `websockets`. Each is one real protocol exchange
driven at a human or application pace; none shapes packets directly (only the ICMP sender builds its own packet).

    labgh_tool.py site                      build /srv/site (pages with css, js and images) and /srv/files
    labgh_tool.py serve                     start the chat/poll/event servers (ports below) and stay up
    labgh_tool.py <client> <host> <seconds> one client session
"""
import asyncio
import http.client
import http.server
import json
import os
import random
import re
import socket
import socketserver
import struct
import sys
import threading
import time

WS, LONGPOLL, SSE, TCPJSON, UDPCHAT, PYHTTP = 5901, 5902, 5903, 5904, 5905, 5906


def text(lo=8, hi=160):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz     ") for _ in range(random.randint(lo, hi)))


def pause(lo, hi):
    time.sleep(lo + random.random() * (hi - lo))


# ------------------------------------------------------------------ content
def site():
    rnd = random.Random(51)
    for d in ("/srv/site/a", "/srv/site/dash", "/srv/files"):
        os.makedirs(d, exist_ok=True)
    if os.path.exists("/srv/site/index.html"):
        return
    sizes = [1_500, 4_000, 9_000, 20_000, 45_000, 90_000, 180_000, 400_000]
    for i in range(160):
        ext = rnd.choice(["jpg", "jpg", "png", "js", "css", "woff2"])
        open(f"/srv/site/a/a{i}.{ext}", "wb").write(os.urandom(rnd.choice(sizes)))
    assets = sorted(os.listdir("/srv/site/a"))
    for p in range(40):
        mine = rnd.sample(assets, rnd.randint(12, 45))
        tags = []
        for a in mine:
            if a.endswith(".js"):
                tags.append(f'<script src="a/{a}"></script>')
            elif a.endswith(".css"):
                tags.append(f'<link rel="stylesheet" href="a/{a}">')
            elif a.endswith(".woff2"):
                tags.append(f'<link rel="preload" as="font" href="a/{a}" crossorigin>')
            else:
                tags.append(f'<img src="a/{a}">')
        links = " ".join(f'<a href="p{rnd.randrange(40)}.html">next</a>' for _ in range(6))
        body = " ".join("word" for _ in range(rnd.randint(300, 6000)))
        open(f"/srv/site/p{p}.html", "w").write(f"<!doctype html><html><head><title>p{p}</title></head><body><p>{body}</p>{links}{''.join(tags)}</body></html>")
    open("/srv/site/index.html", "w").write('<a href="p0.html">p0</a>')
    with open("/srv/files/big.bin", "wb") as f:
        for _ in range(300):
            f.write(os.urandom(1 << 20))
    with open("/srv/files/big.txt", "w") as f:
        for i in range(60000):
            f.write(f"{i:06d} " + "lorem ipsum dolor sit amet " * rnd.randint(1, 4) + "\n")


# ------------------------------------------------------------------ servers
class Hub:
    """Messages from 'the other person': a bot that writes at a human pace; listeners wait on a condition."""

    def __init__(self):
        self.cv, self.msgs = threading.Condition(), []
        threading.Thread(target=self.bot, daemon=True).start()

    def bot(self):
        while True:
            pause(0.6, 5.0)
            with self.cv:
                self.msgs.append(text()); self.cv.notify_all()

    def wait(self, seen, timeout):
        with self.cv:
            self.cv.wait_for(lambda: len(self.msgs) > seen, timeout)
            return self.msgs[seen:], len(self.msgs)


def serve():
    hub = Hub()

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(204); self.send_header("Content-Length", "0"); self.end_headers()

        def do_GET(self):
            if self.path.startswith("/poll"):
                new, n = hub.wait(len(hub.msgs), 25)
                b = json.dumps({"n": n, "msgs": new}).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
            elif self.path.startswith("/events"):
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.send_header("Connection", "close"); self.end_headers()
                seen = len(hub.msgs)
                try:
                    while True:
                        new, seen = hub.wait(seen, 15)
                        for m in new or [None]:
                            self.wfile.write((f"data: {m}\n\n" if m else ": keep-alive\n\n").encode()); self.wfile.flush()
                except OSError:
                    pass
            elif self.path.startswith("/blob"):
                n = int(self.path.split("=")[1])
                self.send_response(200); self.send_header("Content-Length", str(n)); self.end_headers()
                left = n
                while left > 0:
                    k = min(left, 1 << 16); self.wfile.write(os.urandom(k)); left -= k
            else:
                self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()

    class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
    for port in (LONGPOLL, SSE, PYHTTP):
        threading.Thread(target=TS(("0.0.0.0", port), H).serve_forever, daemon=True).start()

    def tcpjson(conn):
        seen = len(hub.msgs)
        conn.settimeout(0.5)
        try:
            while True:
                try:
                    d = conn.recv(4096)
                    if not d:
                        return
                    if b'"ping"' in d:
                        conn.sendall(b'{"type":"pong"}\n')
                    else:
                        conn.sendall(b'{"type":"ack"}\n')
                except socket.timeout:
                    pass
                new, seen = hub.wait(seen, 0.01)
                for m in new:
                    conn.sendall((json.dumps({"type": "msg", "from": "peer", "body": m}) + "\n").encode())
        except OSError:
            pass

    def tcp_listen():
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", TCPJSON)); s.listen()
        while True:
            c, _ = s.accept(); threading.Thread(target=tcpjson, args=(c,), daemon=True).start()
    threading.Thread(target=tcp_listen, daemon=True).start()

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", UDPCHAT)); s.settimeout(0.5)
        peer, seen = None, len(hub.msgs)
        while True:
            try:
                _, peer = s.recvfrom(4096)
            except socket.timeout:
                pass
            new, seen = hub.wait(seen, 0.01)
            if peer:
                for m in new:
                    s.sendto(m.encode(), peer)
    threading.Thread(target=udp, daemon=True).start()

    async def ws_main():
        import websockets

        async def handler(sock, *_):
            seen = len(hub.msgs)

            async def push():
                nonlocal seen
                while True:
                    await asyncio.sleep(0.2)
                    if len(hub.msgs) > seen:
                        for m in hub.msgs[seen:]:
                            await sock.send(m)
                        seen = len(hub.msgs)
            t = asyncio.ensure_future(push())
            try:
                async for _ in sock:
                    pass
            finally:
                t.cancel()
        async with websockets.serve(handler, "0.0.0.0", WS):
            await asyncio.Future()
    asyncio.run(ws_main())


# ------------------------------------------------------------------ clients
def c_ws(host, dur):
    async def run():
        import websockets
        async with websockets.connect(f"ws://{host}:{WS}") as s:
            end = time.time() + dur

            async def rx():
                async for _ in s:
                    pass
            t = asyncio.ensure_future(rx())
            while time.time() < end:
                await s.send(text()); await asyncio.sleep(0.5 + random.random() * 4.5)
            t.cancel()
    asyncio.run(run())


def c_udpchat(host, dur):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.2)
    end = time.time() + dur
    nxt = time.time()
    while time.time() < end:
        if time.time() >= nxt:
            # a line typed in a burst of a few datagrams, then a pause
            for _ in range(random.randint(1, 3)):
                s.sendto(text(4, 90).encode(), (host, UDPCHAT)); time.sleep(0.05 + random.random() * 0.3)
            nxt = time.time() + 0.8 + random.random() * 4
        try:
            s.recvfrom(4096)
        except socket.timeout:
            pass


def c_longpoll(host, dur):
    end = time.time() + dur

    def poll():
        while time.time() < end:
            try:
                c = http.client.HTTPConnection(host, LONGPOLL, timeout=30); c.request("GET", "/poll"); c.getresponse().read(); c.close()
            except OSError:
                time.sleep(0.5)
    threading.Thread(target=poll, daemon=True).start()
    while time.time() < end:
        c = http.client.HTTPConnection(host, LONGPOLL, timeout=10); c.request("POST", "/send", body=text().encode()); c.getresponse().read(); c.close()
        pause(0.7, 5)


def c_sse(host, dur):
    end = time.time() + dur

    def listen():
        try:
            c = http.client.HTTPConnection(host, SSE, timeout=dur + 5); c.request("GET", "/events"); r = c.getresponse()
            while time.time() < end and r.readline():
                pass
        except OSError:
            pass
    threading.Thread(target=listen, daemon=True).start()
    while time.time() < end:
        c = http.client.HTTPConnection(host, SSE, timeout=10); c.request("POST", "/send", body=text().encode()); c.getresponse().read(); c.close()
        pause(0.8, 6)


def c_tcpjson(host, dur):
    s = socket.create_connection((host, TCPJSON)); s.settimeout(0.3)
    end, last_ping, nxt = time.time() + dur, time.time(), time.time()
    while time.time() < end:
        now = time.time()
        if now - last_ping > 10:
            s.sendall(b'{"type":"ping"}\n'); last_ping = now
        if now >= nxt:
            s.sendall((json.dumps({"type": "typing"}) + "\n").encode()); time.sleep(0.3 + random.random() * 1.5)
            s.sendall((json.dumps({"type": "msg", "body": text()}) + "\n").encode())
            nxt = time.time() + 1 + random.random() * 5
        try:
            s.recv(4096)
        except socket.timeout:
            pass


def c_pyreq(host, dur):
    """A scripted page visit without a browser: the page, then its assets over six keep-alive connections, then think time."""
    end = time.time() + dur
    while time.time() < end:
        c = http.client.HTTPConnection(host, 8080, timeout=20); c.request("GET", f"/p{random.randrange(40)}.html"); page = c.getresponse().read().decode(); c.close()
        urls = re.findall(r'(?:src|href)="(a/[^"]+)"', page)
        lock = threading.Lock()

        def worker():
            k = http.client.HTTPConnection(host, 8080, timeout=20)
            while True:
                with lock:
                    if not urls:
                        break
                    u = urls.pop()
                k.request("GET", "/" + u); k.getresponse().read()
            k.close()
        ts = [threading.Thread(target=worker) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        pause(2, 7)


def c_pyhttpdl(host, dur):
    end = time.time() + dur
    while time.time() < end:
        c = http.client.HTTPConnection(host, PYHTTP, timeout=dur + 5); c.request("GET", "/blob?n=200000000"); r = c.getresponse()
        while time.time() < end and r.read(1 << 16):
            pass
        c.close()


def c_dashpull(host, dur):
    """A player's fetch loop: list the live segments once a second and fetch each new one once."""
    end, seen = time.time() + dur, set()
    while time.time() < end:
        try:
            c = http.client.HTTPConnection(host, 8080, timeout=10); c.request("GET", "/dash/"); listing = c.getresponse().read().decode()
            for seg in re.findall(r'href="([^"]+\.(?:m4s|mpd))"', listing):
                if seg.endswith(".mpd") or seg not in seen:
                    seen.add(seg); c.request("GET", "/dash/" + seg); c.getresponse().read()
            c.close()
        except OSError:
            pass
        time.sleep(1)


def c_imapsync(host, dur):
    import imaplib
    import ssl
    end = time.time() + dur
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    while time.time() < end:
        m = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx); m.login("lab", "lab"); m.select("INBOX")
        _, d = m.search(None, "ALL"); ids = d[0].split()
        m.fetch(b"1:*", "(FLAGS BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])")
        for i in random.sample(ids, min(len(ids), random.randint(2, 6))):
            m.fetch(i, "(RFC822)"); pause(0.3, 2.0)
        m.logout(); pause(2, 7)


def c_pysmtp(host, dur):
    import smtplib
    import ssl
    from email.message import EmailMessage
    end = time.time() + dur
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    while time.time() < end:
        msg = EmailMessage(); msg["From"] = "a@lab"; msg["To"] = "lab@labg-b"; msg["Subject"] = text(5, 40)
        msg.set_content(text(100, 3000))
        if random.random() < 0.6:
            msg.add_attachment(os.urandom(random.choice([40_000, 120_000, 350_000, 800_000])), maintype="application", subtype="octet-stream", filename="f.bin")
        s = smtplib.SMTP(host, 25, timeout=30); s.starttls(context=ctx); s.send_message(msg); s.quit()
        pause(2, 7)


def c_pyicmp(host, dur):
    """ICMP echo requests with a random payload size and a random gap each."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    end, seq = time.time() + dur, 0
    while time.time() < end:
        seq += 1
        body = os.urandom(random.randint(16, 1300))
        hdr = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, seq & 0xFFFF)
        b = hdr + body
        if len(b) % 2:
            b += b"\0"
        c = sum(struct.unpack(f"!{len(b) // 2}H", b)); c = (c >> 16) + (c & 0xFFFF); c += c >> 16
        s.sendto(struct.pack("!BBHHH", 8, 0, ~c & 0xFFFF, os.getpid() & 0xFFFF, seq & 0xFFFF) + body, (host, 0))
        pause(0.05, 1.2)


CLIENTS = {"ws": c_ws, "udpchat": c_udpchat, "longpoll": c_longpoll, "sse": c_sse, "tcpjson": c_tcpjson, "pyreq": c_pyreq,
           "pyhttpdl": c_pyhttpdl, "dashpull": c_dashpull, "imapsync": c_imapsync, "pysmtp": c_pysmtp, "pyicmp": c_pyicmp}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "site":
        site()
    elif cmd == "serve":
        serve()
    elif cmd in CLIENTS:
        CLIENTS[cmd](sys.argv[2], float(sys.argv[3]))
    else:
        sys.exit(__doc__)
