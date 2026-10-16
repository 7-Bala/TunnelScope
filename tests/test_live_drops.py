"""T-165: live mode reports the packets the capture process dropped. dumpcap writes an Interface Statistics Block (ISB)
with the counters at the end of each pcapng file; `capture_stats` reads it. A file without counters is UNKNOWN, never
"zero drops". The ISB layout below is the one real dumpcap files have (decoded from testbed/captures/exp33/*.pcapng:
comment, start time, end time, isb_ifrecv, isb_ifdrop)."""
import json
import os
import struct
import time
from pathlib import Path

import pytest

from tunnelscope.cli import main
from tunnelscope.live.live import LiveMonitor, capture_stats

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
EXP33 = CAP / "exp33"
SRC = CAP / "pq-mlkem768.pcap"


def _opt(e, code, value):
    if isinstance(value, int):
        return struct.pack(e + "HHQ", code, 8, value)
    raw = value.encode()
    return struct.pack(e + "HH", code, len(raw)) + raw + b"\0" * (-len(raw) % 4)


def _block(e, typ, body):
    tl = 12 + len(body)
    return struct.pack(e + "II", typ, tl) + body + struct.pack(e + "I", tl)


def _isb(e, iface, recv, drop, with_drop=True):
    body = struct.pack(e + "III", iface, 0, 0) + _opt(e, 1, "Counters provided by dumpcap") + _opt(e, 2, 0) + _opt(e, 3, 0) + _opt(e, 4, recv)
    if with_drop:
        body += _opt(e, 5, drop)
    return _block(e, 5, body + struct.pack(e + "HH", 0, 0))


def pcapng(src, isbs, e="<"):
    """A pcapng copy of a classic little-endian pcap (the same packets), followed by the given ISBs."""
    d = src.read_bytes()
    assert d[:4] == b"\xd4\xc3\xb2\xa1"
    link, snap = struct.unpack("<I", d[20:24])[0], struct.unpack("<I", d[16:20])[0]
    shb = _block(e, 0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _block(e, 1, struct.pack(e + "HHI", link, 0, snap))
    out, off, n = [shb, idb], 24, 0
    while off + 16 <= len(d):
        sec, usec, cap, orig = struct.unpack("<IIII", d[off:off + 16])
        data = d[off + 16:off + 16 + cap]
        ts = sec * 1_000_000 + usec
        out.append(_block(e, 6, struct.pack(e + "IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, cap, orig) + data + b"\0" * (-cap % 4)))
        off += 16 + cap
        n += 1
    return b"".join(out) + b"".join(isbs), n


def test_counters_are_read_from_the_isb_in_either_byte_order(tmp_path):
    for e in ("<", ">"):
        data, n = pcapng(SRC, [_isb(e, 0, 100, 7)], e)
        f = tmp_path / f"a{ord(e)}.pcapng"
        f.write_bytes(data)
        assert capture_stats(f) == {"received": 100, "dropped": 7}
    data, _ = pcapng(SRC, [_isb("<", 0, 100, 7), _isb("<", 1, 50, 3)])   # headers-only mode opens the interface twice
    f = tmp_path / "two.pcapng"
    f.write_bytes(data)
    assert capture_stats(f) == {"received": 150, "dropped": 10}


def test_a_file_without_counters_is_unknown_not_zero(tmp_path):
    assert capture_stats(SRC) is None                                      # classic pcap: tcpdump -G writes these
    assert capture_stats(tmp_path / "missing.pcapng") is None
    plain, _ = pcapng(SRC, [])
    f = tmp_path / "plain.pcapng"
    f.write_bytes(plain)
    assert capture_stats(f) is None                                        # pcapng without an ISB
    noisy, _ = pcapng(SRC, [_isb("<", 0, 100, 0, with_drop=False)])
    f2 = tmp_path / "nodrop.pcapng"
    f2.write_bytes(noisy)
    assert capture_stats(f2) is None                                       # a received count alone says nothing about loss
    good, _ = pcapng(SRC, [_isb("<", 0, 100, 0)])
    f3 = tmp_path / "cut.pcapng"
    f3.write_bytes(good[:-6])                                              # a file cut short
    assert capture_stats(f3) is None
    junk = tmp_path / "junk.pcapng"
    junk.write_bytes(b"\n\r\r\n" + b"\x00" * 40)
    assert capture_stats(junk) is None


def test_only_the_tail_of_a_large_file_is_read(tmp_path, monkeypatch):
    data, _ = pcapng(SRC, [_isb("<", 0, 12345, 9)])
    f = tmp_path / "big.pcapng"
    f.write_bytes(data)
    reads = []
    real_open = open

    class Spy:
        def __init__(self, fh):
            self.fh = fh

        def read(self, k=-1):
            reads.append(k)
            return self.fh.read(k)

        def __getattr__(self, name):
            return getattr(self.fh, name)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.fh.close()

    monkeypatch.setattr("tunnelscope.live.live.open", lambda p, m="r": Spy(real_open(p, m)), raising=False)
    assert capture_stats(f) == {"received": 12345, "dropped": 9}
    assert -1 not in reads and sum(reads) < 2000 < len(data)


def _follow(tmp_path, windows):
    d = tmp_path / "follow"
    d.mkdir()
    old = time.time() - 3600
    for i, content in enumerate(windows):
        f = d / f"w-{i:03d}.{'pcap' if content is SRC else 'pcapng'}"
        if content is SRC:
            f.write_bytes(SRC.read_bytes())
        else:
            f.write_bytes(content)
        os.utime(f, (old + i, old + i))
    return d


def test_live_status_shows_windows_with_drops_and_windows_with_unknown_loss(tmp_path):
    with_drops, _ = pcapng(SRC, [_isb("<", 0, 500, 7)])
    more_drops, _ = pcapng(SRC, [_isb("<", 0, 500, 3)])
    clean, _ = pcapng(SRC, [_isb("<", 0, 500, 0)])
    d = _follow(tmp_path, [with_drops, more_drops, clean, SRC, SRC])
    mon = LiveMonitor(follow=str(d), window=5, keep=True)
    rows = mon.poll_once()
    assert [r["ok"] for r in rows] == [True] * 5                              # the analysis itself still runs
    assert [r["capture_incomplete"] for r in rows] == [True, True, False, None, None]
    assert rows[0]["capture"] == {"received": 500, "dropped": 7}
    assert rows[3]["capture"] is None
    st = mon.status()
    assert st["capture_stats"]["windows_with_drops"] == 2
    assert st["capture_stats"]["windows_without_counters"] == 2
    assert st["capture_stats"]["last"] is None                                  # the newest window has no counters


def test_cli_warns_when_a_window_dropped_packets(tmp_path, capsys):
    data, _ = pcapng(SRC, [_isb("<", 0, 500, 7)])
    d = _follow(tmp_path, [data])
    assert main(["live", "--follow", str(d), "--window", "5", "--max-windows", "1"]) in (0, None)
    out = capsys.readouterr().out
    assert "WARNING the capture dropped 7 of 500 packets" in out
    d2 = tmp_path / "f2"
    d2.mkdir()
    clean, _ = pcapng(SRC, [_isb("<", 0, 500, 0)])
    (d2 / "w-000.pcapng").write_bytes(clean)
    os.utime(d2 / "w-000.pcapng", (time.time() - 3600,) * 2)
    main(["live", "--follow", str(d2), "--window", "5", "--max-windows", "1", "--json"])
    row = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert row["capture"] == {"received": 500, "dropped": 0} and row["capture_incomplete"] is False


if (EXP33 / "reference.pcapng").exists():       # real dumpcap files (git-ignored: only on the machine that captured them)
    def test_real_dumpcap_files_give_the_packet_counts_they_hold():
        assert capture_stats(EXP33 / "reference.pcapng") == {"received": 807, "dropped": 0}
        assert capture_stats(EXP33 / "headers.pcapng") == {"received": 807, "dropped": 0}   # 75 + 732 over two interfaces
