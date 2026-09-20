#!/usr/bin/env python3
"""EXP-16 real-application client drivers (run inside sih26-apps-a).

Each class drives REAL software against the lab servers on apps-b:
  web         headless Chromium loading an HTTPS page with its assets, repeatedly
  video       headless Chromium playing an MP4 over HTTP (progressive + range)
  bulk        SFTP download of a 50 MB file (OpenSSH)
  interactive real SSH session with slow keystrokes and small outputs
  email       swaks SMTP submissions to Postfix, some with attachments
  messaging   real XMPP client (slixmpp) sending messages, receipts and a photo-sized blob
  voip        real RTP audio stream (ffmpeg, Opus, 20 ms frames) with an RTCP-carrying sink
  icmp        ping

Usage: apps_client.py <class> <peer-ip> <duration_s> <seed>
"""
import random
import subprocess
import sys
import time

CH = ["chromium", "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
      "--ignore-certificate-errors", "--disk-cache-dir=/dev/null", "--autoplay-policy=no-user-gesture-required"]
SSH = ["sshpass"]  # not installed; we use a key-free expect wrapper instead


def run(cmd, timeout=None, **kw):
    try:
        return subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
    except subprocess.TimeoutExpired:
        return None


def web(peer, dur, rng):
    end = time.time() + dur
    while time.time() < end:
        run(CH + ["--virtual-time-budget=8000", "--dump-dom", f"https://{peer}/"], timeout=25)
        time.sleep(rng.uniform(0.3, 1.5))


def video(peer, dur, rng):
    # No --virtual-time-budget here: that fast-forwards Chromium's clock, so the
    # whole clip downloads at once instead of playing. Let it play in real time.
    p = subprocess.Popen(CH + ["--remote-debugging-port=0", f"http://{peer}/video.html"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(dur)
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()


def _expect(script, timeout):
    return run(["expect", "-c", script], timeout=timeout)


def bulk(peer, dur, rng):
    _expect(f'''set timeout {int(dur) + 20}
spawn sftp -l 12000 -o StrictHostKeyChecking=no labuser@{peer}
expect "password:" {{ send "labpass-not-a-secret\\r" }}
expect "sftp>" {{ send "get blob.bin /tmp/blob.bin\\r" }}
expect "sftp>" {{ send "quit\\r" }}
expect eof''', dur + 30)


def interactive(peer, dur, rng):
    lines = "".join(f'expect "$ " {{ send "{c}\\r" }}\nsleep {rng.uniform(0.2, 1.4):.2f}\n'
                    for c in ["ls -l /etc", "whoami", "uptime", "grep -c . /etc/services", "date", "ps aux | head",
                              "cat /etc/hostname", "df -h", "echo hello", "ls /usr/bin | head -40"] * 3)
    _expect(f'''set timeout {int(dur) + 20}
spawn ssh -o StrictHostKeyChecking=no labuser@{peer}
expect "password:" {{ send "labpass-not-a-secret\\r" }}
{lines}
send "exit\\r"
expect eof''', dur + 30)


def email(peer, dur, rng):
    end = time.time() + dur
    n = 0
    while time.time() < end:
        size = int(min(max(rng.lognormvariate(9.0, 1.0), 800), 200_000))
        if rng.random() < 0.25:
            size += rng.randint(200_000, 900_000)
        body = "/tmp/body.txt"
        open(body, "w").write("Lab message %d.\n" % n + "x" * size)
        run(["swaks", "--to", "labuser@localhost", "--from", "tester@lab.test", "--server", peer,
             "--body", "@" + body, "--header", "Subject: lab message %d" % n, "--timeout", "20"], timeout=30)
        n += 1
        time.sleep(min(rng.expovariate(1 / 1.5), 5))


def messaging(peer, dur, rng):
    code = f'''
import asyncio, random, sys, time
from slixmpp import ClientXMPP
rng = random.Random({rng.randint(0, 10**6)})
class Bot(ClientXMPP):
    def __init__(self):
        super().__init__("alice@lab.test", "labpass-not-a-secret")
        self.add_event_handler("session_start", self.go)
    async def go(self, _):
        self.send_presence(); await self.get_roster()
        end = time.time() + {dur}
        while time.time() < end:
            for _ in range(rng.randint(1, 4)):
                self.send_message(mto="bob@lab.test", mbody="m" * rng.randint(60, 400))
                await asyncio.sleep(rng.uniform(0.05, 0.6))
            if rng.random() < 0.15:
                self.send_message(mto="bob@lab.test", mbody="p" * rng.randint(30000, 200000))
            await asyncio.sleep(min(rng.expovariate(1 / 1.2), 5))
        self.disconnect()
b = Bot(); b.connect(("{peer}", 5222), use_ssl=False, disable_starttls=True); b.process(forever=False)
'''
    open("/tmp/xmpp.py", "w").write(code)
    run(["python3", "/tmp/xmpp.py"], timeout=dur + 30)


def voip(peer, dur, rng):
    # real RTP: Opus, 20 ms frames, the cadence a softphone produces
    run(["ffmpeg", "-loglevel", "error", "-re", "-f", "lavfi", "-i", "sine=frequency=480:sample_rate=48000",
         "-t", str(int(dur)), "-c:a", "libopus", "-b:a", "24k", "-frame_duration", "20",
         "-f", "rtp", f"rtp://{peer}:5006?rtcpport=5007"], timeout=dur + 20)


def icmp(peer, dur, rng):
    run(["ping", "-q", "-c", str(int(dur)), "-i", "1", "-s", str(rng.choice([56, 56, 56, 64, 120])), peer], timeout=dur + 20)


CLIENTS = dict(web=web, video=video, bulk=bulk, interactive=interactive, email=email,
               messaging=messaging, voip=voip, icmp=icmp)

if __name__ == "__main__":
    cls, peer, dur, seed = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
    CLIENTS[cls](peer, dur, random.Random(seed))
