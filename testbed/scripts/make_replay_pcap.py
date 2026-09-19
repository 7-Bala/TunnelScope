#!/usr/bin/env python3
"""Synthetic replay captures for the RFC4303-SEQ check (T-083).

Takes a real lab capture and writes two copies (classic pcap, stdlib only):
  replay-attack.pcap        one captured ESP packet re-sent 5 s after the last
                            packet (what an on-path replay looks like on the wire)
  replay-capture-dup.pcap   one ESP packet recorded twice 0.2 ms apart with the
                            same bytes (a second tap / span-port duplicate), which
                            must NOT be called a replay
Marked synthetic in the dataset (split: excluded). Source: cs-aes256gcm16.pcap.
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "testbed/captures/cs-aes256gcm16.pcap"
OUT = ROOT / "testbed/captures/synthetic"


def read(p):
    b = p.read_bytes()
    gh, off, recs = b[:24], 24, []
    endian = "<" if b[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    while off < len(b):
        ts, tu, incl, orig = struct.unpack(endian + "IIII", b[off:off + 16])
        recs.append([ts, tu, b[off + 16:off + 16 + incl], orig])
        off += 16 + incl
    return gh, endian, recs


def write(p, gh, endian, recs):
    with open(p, "wb") as f:
        f.write(gh)
        for ts, tu, data, orig in recs:
            f.write(struct.pack(endian + "IIII", ts, tu, len(data), orig) + data)


def is_esp(data):   # Ethernet + IPv4, protocol 50
    return len(data) > 34 and data[12:14] == b"\x08\x00" and data[23] == 50


gh, e, recs = read(SRC)
esp = [r for r in recs if is_esp(r[2])]
victim = esp[len(esp) // 2]
last = recs[-1]
replay = [last[0] + 5, last[1], victim[2], victim[3]]
write(OUT / "replay-attack.pcap", gh, e, recs + [replay])
i = recs.index(victim)
dup = [victim[0], victim[1] + 200, victim[2], victim[3]]
write(OUT / "replay-capture-dup.pcap", gh, e, recs[:i + 1] + [dup] + recs[i + 1:])
print("wrote replay-attack.pcap, replay-capture-dup.pcap from", SRC.name)
