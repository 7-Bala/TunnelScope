#!/usr/bin/env python3
"""Seeded, stdlib-only traffic generator for EXP-05 (metadata leakage).

  server:  tgen.py server <bind_ip>
  client:  tgen.py client <class> <server_ip> <duration_s> <seed> [bind_ip]

Classes model the traffic *shapes* the PS lists (VoIP, web, file/bulk,
interactive, video). They are shape models, not application replays: what a
passive ESP observer sees is size/timing/direction, and that's what these
control. Every random draw comes from random.Random(seed), so a session is
reproducible from (class, seed).

Ports: voip udp 5004 · web tcp 8080 · bulk tcp 5201 · interactive tcp 2222 ·
video tcp 8090.
"""
import random
import socket
import socketserver
import struct
import sys
import threading
import time

PORTS = {"voip": 5004, "web": 8080, "bulk": 5201, "interactive": 2222, "video": 8090}


# ----------------------------------------------------------------- server ---
class _TCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


class WebHandler(socketserver.BaseRequestHandler):
    # request: 4-byte big-endian object size; reply: that many bytes
    def handle(self):
        try:
            while True:
                (size,) = struct.unpack("!I", _recv_exact(self.request, 4))
                self.request.sendall(b"w" * size)
        except (ConnectionError, OSError):
            pass


class BulkHandler(socketserver.BaseRequestHandler):
    def handle(self):  # sink
        try:
            while self.request.recv(65536):
                pass
        except OSError:
            pass


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):  # interactive: echo each keystroke burst
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    return
                self.request.sendall(data)
        except OSError:
            pass


def serve(bind):
    for cls, handler in (("web", WebHandler), ("bulk", BulkHandler),
                         ("interactive", EchoHandler), ("video", WebHandler)):
        srv = _TCP((bind, PORTS[cls]), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((bind, PORTS["voip"]))
    while True:  # voip: reflect each frame (the far end talks back at the same cadence)
        data, peer = udp.recvfrom(2048)
        udp.sendto(data, peer)


# ----------------------------------------------------------------- client ---
def voip(dst, dur, rng, bind):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if bind:
        s.bind((bind, 0))
    s.settimeout(0.001)
    frame = b"v" * 172          # 160 B G.711 payload + 12 B RTP header, 20 ms ptime
    t0 = time.time(); nxt = t0
    while time.time() - t0 < dur:
        s.sendto(frame, (dst, PORTS["voip"]))
        nxt += 0.020 + rng.uniform(-0.001, 0.001)
        try:
            s.recv(2048)
        except (socket.timeout, OSError):
            pass
        time.sleep(max(0, nxt - time.time()))


def _tcp(dst, port, bind):
    s = socket.create_connection((dst, port), timeout=10, source_address=(bind, 0) if bind else None)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def web(dst, dur, rng, bind):
    t0 = time.time()
    while time.time() - t0 < dur:
        with _tcp(dst, PORTS["web"], bind) as s:            # a "page": 1-6 objects per connection
            for _ in range(rng.randint(1, 6)):
                size = int(min(max(rng.lognormvariate(9.9, 1.2), 300), 400_000))  # median ~20 KB
                s.sendall(struct.pack("!I", size))
                _recv_exact(s, size)
        time.sleep(min(rng.expovariate(1 / 0.8), 4))         # think time


def bulk(dst, dur, rng, bind, mbit=20.0):
    # Rate-capped at ~20 Mbit/s: a realistic WAN file transfer, and it keeps
    # captures small (an uncapped stream over a Docker bridge runs at multiple
    # Gbit/s and would write gigabytes per 20-second session).
    block = b"b" * 16384
    t0 = time.time(); sent = 0
    with _tcp(dst, PORTS["bulk"], bind) as s:
        while time.time() - t0 < dur:
            s.sendall(block); sent += len(block)
            ahead = sent * 8 / (mbit * 1e6 * rng.uniform(0.95, 1.05)) - (time.time() - t0)
            if ahead > 0:
                time.sleep(ahead)


def interactive(dst, dur, rng, bind):
    t0 = time.time()
    with _tcp(dst, PORTS["interactive"], bind) as s:
        while time.time() - t0 < dur:
            n = 1 if rng.random() < 0.7 else rng.randint(2, 50)   # mostly single keystrokes
            s.sendall(b"k" * n)
            s.recv(4096)
            time.sleep(min(rng.expovariate(1 / 0.15), 2))


def video(dst, dur, rng, bind):
    t0 = time.time()
    with _tcp(dst, PORTS["video"], bind) as s:
        while time.time() - t0 < dur:
            seg_start = time.time()
            size = int(250_000 * rng.uniform(0.85, 1.15))         # ~2 Mbit/s ABR segment
            s.sendall(struct.pack("!I", size))
            _recv_exact(s, size)
            time.sleep(max(0, 1.0 - (time.time() - seg_start)))


CLIENTS = {"voip": voip, "web": web, "bulk": bulk, "interactive": interactive, "video": video}


def main():
    if sys.argv[1] == "server":
        serve(sys.argv[2])
    else:
        cls, dst, dur, seed = sys.argv[2], sys.argv[3], float(sys.argv[4]), int(sys.argv[5])
        bind = sys.argv[6] if len(sys.argv) > 6 else None
        CLIENTS[cls](dst, dur, random.Random(seed), bind)


if __name__ == "__main__":
    main()
