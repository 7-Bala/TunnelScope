"""EXP-49 generator: classic pcap files of native ESP over IPv4 with known ground truth (pure numpy, no new dependency).

    gen(path, n, pairs=1, caplen=80, origlen=1400, rate=50000, base_ts=1791000000, seed=1) -> truth dict

Frame = Ethernet (14) + IPv4 (20, proto 50, valid header checksum) + ESP (SPI, sequence, then pseudo-random bytes). The record keeps `origlen` as the original length and
stores `caplen` bytes (80 = the shipped headers-only sensor, DEC-044). Packets alternate direction; each (pair, direction) has its own SPI and a sequence counting from 1.
"""
import json
import struct

import numpy as np

ETH, IP, ESPH = 14, 20, 8


def _checksum(hdr: np.ndarray) -> np.ndarray:
    words = hdr.reshape(len(hdr), -1, 2).astype(np.uint32)
    s = ((words[:, :, 0] << 8) | words[:, :, 1]).sum(axis=1)
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s & 0xFFFF).astype(np.uint16)


def gen(path, n, pairs=1, caplen=80, origlen=1400, rate=50000, base_ts=1791000000, seed=1):
    assert caplen >= ETH + IP + ESPH and caplen <= origlen
    rng = np.random.default_rng(seed)
    rec = 16 + caplen
    buf = np.zeros((n, rec), dtype=np.uint8)
    i = np.arange(n, dtype=np.uint64)
    pair = (i % pairs).astype(np.uint32)
    direction = ((i // pairs) % 2).astype(np.uint32)          # alternate within each pair
    k = (i // (2 * pairs)).astype(np.uint32) + 1               # sequence counter per (pair, direction)
    t = i.astype(np.float64) / rate
    sec = (base_ts + np.floor(t)).astype(np.uint32)
    usec = np.round((t - np.floor(t)) * 1e6).astype(np.uint32)
    usec = np.minimum(usec, 999999)
    buf[:, 0:4] = sec.astype("<u4").view(np.uint8).reshape(n, 4)
    buf[:, 4:8] = usec.astype("<u4").view(np.uint8).reshape(n, 4)
    buf[:, 8:12] = np.full(n, caplen, dtype="<u4").view(np.uint8).reshape(n, 4)
    buf[:, 12:16] = np.full(n, origlen, dtype="<u4").view(np.uint8).reshape(n, 4)
    f = buf[:, 16:]
    a = (10, 100 + pair // 250, 1 + pair % 250, 1)             # host A of the pair; host B is 10.200+.x.1 (never equal to A)
    ip_a = np.stack([np.full(n, 10), 100 + pair // 250, 1 + pair % 250, np.full(n, 1)], axis=1).astype(np.uint8)
    ip_b = np.stack([np.full(n, 10), 200 + pair // 250, 1 + pair % 250, np.full(n, 1)], axis=1).astype(np.uint8)
    src = np.where(direction[:, None] == 0, ip_a, ip_b)
    dst = np.where(direction[:, None] == 0, ip_b, ip_a)
    f[:, 0:6] = np.array([2, 0, 0, 0, 0, 2], dtype=np.uint8)    # Ethernet: locally administered MACs
    f[:, 6:12] = np.array([2, 0, 0, 0, 0, 1], dtype=np.uint8)
    f[:, 12] = 0x08
    f[:, 13] = 0x00
    ip = np.zeros((n, IP), dtype=np.uint8)
    ip[:, 0] = 0x45
    ip[:, 2:4] = np.full(n, origlen - ETH, dtype=">u2").view(np.uint8).reshape(n, 2)
    ip[:, 4:6] = (i & 0xFFFF).astype(">u2").view(np.uint8).reshape(n, 2)
    ip[:, 8] = 64
    ip[:, 9] = 50
    ip[:, 12:16] = src
    ip[:, 16:20] = dst
    ip[:, 10:12] = _checksum(ip).astype(">u2").view(np.uint8).reshape(n, 2)
    f[:, ETH:ETH + IP] = ip
    spi = (np.uint32(0x10000000) + pair * np.uint32(2) + direction).astype(">u4")
    f[:, ETH + IP:ETH + IP + 4] = spi.view(np.uint8).reshape(n, 4)
    f[:, ETH + IP + 4:ETH + IP + 8] = k.astype(">u4").view(np.uint8).reshape(n, 4)
    rest = caplen - (ETH + IP + ESPH)
    if rest:
        f[:, ETH + IP + ESPH:] = rng.integers(0, 256, size=(n, rest), dtype=np.uint8)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        fh.write(buf.tobytes())
    return {"packets": int(n), "esp_packets": int(n), "sum_ip_len": int(n) * (origlen - ETH), "sum_origlen": int(n) * origlen,
            "host_pairs": int(pairs), "caplen": caplen, "origlen": origlen, "rate_pps": rate, "capture_seconds": n / rate,
            "file_bytes": 24 + n * rec}


def classic_esp_truth(path):
    """Independent count of native-ESP packets and their IP total lengths in a classic little-endian pcap (Ethernet, IPv4), no tshark involved."""
    data = open(path, "rb").read()
    off, n, ip_len, orig_all = 24, 0, 0, 0
    while off + 16 <= len(data):
        caplen = struct.unpack_from("<I", data, off + 8)[0]
        fr = off + 16
        if fr + caplen > len(data):
            break
        orig_all += struct.unpack_from("<I", data, off + 12)[0]
        if caplen >= 34 and data[fr + 12:fr + 14] == b"\x08\x00" and data[fr + 23] == 50:
            n += 1
            ip_len += struct.unpack_from(">H", data, fr + 16)[0]
        off = fr + caplen
    return {"esp_packets": n, "sum_ip_len": ip_len, "sum_origlen_all": orig_all}
