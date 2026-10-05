"""Drive a FortiGate-VM (or any serial console) over QEMU's tcp serial socket. Lab tool for T-118 step 2.

    from fgt_console import Console
    c = Console(); c.login("admin", "<lab password>"); print(c.run("get system status"))
"""
import os
import re
import socket
import time

PROMPT = re.compile(rb"\n?[\w\-.]+ (?:\([\w\-. ]+\) )?[#$] $")      # 'FortiGate-ARM64-KVM # ', 'FortiGate (root) # ', '(vpn) #'


class Console:
    def __init__(self, host="127.0.0.1", port=4555, timeout=5, user="admin", prompt=None, autologin=True,
                 password_file=os.environ.get("FGT_LAB_PASSWORD_FILE", os.path.expanduser("~/Documents/SIH-2026-fortilab/lab-password.txt"))):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(0.5)
        self.user, self.password_file = user, password_file
        self.prompt = re.compile(prompt) if prompt else PROMPT
        if autologin:
            self.ensure()

    def ensure(self):
        """FortiOS logs an idle console out; log back in (lab password from a file outside the repo) if needed."""
        self.send("")
        out = self._read(until=re.compile(rb"(login: $|[#$] $)"), limit=15)
        if re.search(rb"login: $", out):
            self.login(self.user, open(self.password_file).read().strip())

    def _read(self, wait=1.0, until=None, limit=60):
        buf, t0, last = b"", time.time(), time.time()
        while time.time() - t0 < limit:
            try:
                d = self.s.recv(65536)
                if not d:
                    break
                buf += d
                last = time.time()
                if until and until.search(buf):
                    break
            except socket.timeout:
                if time.time() - last > wait and not until:
                    break
        return buf

    def send(self, text, enter=True):
        self.s.sendall(text.encode() + (b"\r" if enter else b""))

    def expect(self, pattern, limit=60):
        return self._read(until=re.compile(pattern if isinstance(pattern, bytes) else pattern.encode()), limit=limit)

    def run(self, cmd, limit=60):
        """Send one command, return its output (echo and prompt stripped)."""
        self._read(wait=0.3)                      # drain
        self.send(cmd)
        out = self._read(until=self.prompt, limit=limit).decode("utf8", "replace")
        lines = out.replace("\r", "").split("\n")
        return "\n".join(lines[1:-1] if len(lines) > 2 else lines).strip()

    def login(self, user, password, limit=90):
        self.send("")
        out = self.expect(rb"(login: |# $)", limit=limit)
        if b"login: " in out[-40:]:
            self.send(user)
            self.expect(rb"Password: ", limit=10)
            self.send(password)
            out = self.expect(rb"(# $|New Password:|login: )", limit=30)
        return out.decode("utf8", "replace")
