#!/usr/bin/env python3
"""EXP-20: convert USBVPN2022's L2TP-over-IPsec captures into the packet arrays analyze.py reads.

  .venv/bin/python experiments/exp20-real-ipsec-and-users/convert_usbvpn.py

Input: ~/Datasets/usbvpn2022/encrypted_vpn_dataset/VPN/L2TP IPsec/*.json (unzipped from
encrypted_vpn_dataset.zip, Zenodo 7301756, CC BY 4.0). Output (outside the repo):
~/Datasets/usbvpn2022/converted/usbvpn_l2tpipsec_packets.npz, plus results/conversion_usbvpn.json.

Decisions made from the file structure only (no metric looked at), recorded in the plan (build/14 §3.2):
- `bytes` is the IP length (a NAT-T keepalive is 29 = 20 IP + 8 UDP + 1), its sign is the direction;
- only the tunnel records are kept: UDP with port 4500 on both ends (ESP in UDP). ICMP and the
  router's management port (8291) are not traffic inside the tunnel;
- "out" = the sign of the record's first packet (the side that started it), as in EXP-19;
- a row with `packets` n > 1 holds n same-direction packets stamped with one timestamp and `bytes` =
  their sum. It is split into n packets whose sizes are the most frequent combination of that
  capture file's own single-packet sizes (same direction) that sums exactly; only when no
  combination fits is it split evenly. The share of each case is reported.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

ROOT = Path.home() / "Datasets/usbvpn2022"
ZIP = ROOT / "encrypted_vpn_dataset.zip"
SRC = ROOT / "encrypted_vpn_dataset/VPN/L2TP IPsec"
OUT = ROOT / "converted/usbvpn_l2tpipsec_packets.npz"
RESULTS = Path(__file__).resolve().parent / "results"
LABEL = {"mail": "email", "meet": "voip", "streaming": "video", "non_streaming": "web", "ssh": "interactive"}
VOCAB = 20          # most frequent single-packet sizes per file and direction used to split merged rows
MAX_N = 4           # the largest merge seen (measured: 2, 3 or 4 packets)


def records(path: Path):
    """Stream the pretty-printed JSON: yield (header, [(signed bytes, n, timestamp string)])."""
    hdr, pk, b, n = {}, [], None, None
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s.startswith('"ip_proto"'):
                if pk or hdr:
                    yield hdr, pk
                hdr, pk = {"ip_proto": s.split('"')[3]}, []
            elif s.startswith('"port_dst"') or s.startswith('"port_src"'):
                hdr[s.split('"')[1]] = int(s.split(":")[1].strip(' ,"'))
            elif s.startswith('"bytes"'):
                b = int(s.split('"')[3])
            elif s.startswith('"packets"'):
                n = int(s.split('"')[3])
            elif s.startswith('"timestamp_start"'):
                pk.append((b, n, s.split('"')[3]))
    if pk or hdr:
        yield hdr, pk


def is_tunnel(h: dict) -> bool:
    return h.get("ip_proto") == "udp" and h.get("port_src") == 4500 and h.get("port_dst") == 4500


def ts(s: str) -> float:
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()


def splitter(single: Counter):
    """sum -> best combination of n sizes from the vocabulary, per n (max product of frequencies)."""
    vocab = [s for s, _ in single.most_common(VOCAB)]
    best: dict[tuple[int, int], tuple[float, tuple[int, ...]]] = {}
    for n in range(2, MAX_N + 1):
        for combo in itertools.combinations_with_replacement(vocab, n):
            score = float(np.prod([single[c] for c in combo]))
            key = (n, sum(combo))
            if key not in best or score > best[key][0]:
                best[key] = (score, combo)
    return {k: v[1] for k, v in best.items()}


def main() -> None:
    zip_sha = hashlib.sha256(ZIP.read_bytes()).hexdigest()
    t_all, out_all, size_all, offsets, labels, caps = [], [], [], [0], [], []
    stats = {"files": {}}
    for fn in sorted(SRC.glob("*.json")):
        key = fn.stem
        # pass 1: single-packet size vocabulary per direction (structure only)
        single = {1: Counter(), -1: Counter()}
        for h, pk in records(fn):
            if is_tunnel(h):
                for b, n, _ in pk:
                    if n == 1:
                        single[1 if b > 0 else -1][abs(b)] += 1
        split = {d: splitter(c) for d, c in single.items()}
        st = Counter()
        # pass 2: packets
        for k, (h, pk) in enumerate(records(fn)):
            if not is_tunnel(h):
                st["records_dropped_not_tunnel"] += 1
                continue
            st["records"] += 1
            first = 1 if pk[0][0] > 0 else -1
            t, o, z = [], [], []
            for b, n, s in pk:
                d, tt = (1 if b > 0 else -1), ts(s)
                if n == 1:
                    sizes = (abs(b),)
                else:
                    combo = split[d].get((n, abs(b)))
                    if combo:
                        sizes = combo
                        st["merged_rows_exact"] += 1
                    else:
                        q, r = divmod(abs(b), n)
                        sizes = tuple(q + (1 if i < r else 0) for i in range(n))
                        st["merged_rows_even"] += 1
                    st["packets_from_merged"] += n
                for z1 in sizes:
                    t.append(tt); o.append(d == first); z.append(z1)
            order = np.argsort(np.array(t), kind="stable")
            t_all.append(np.array(t)[order]); out_all.append(np.array(o)[order]); size_all.append(np.array(z)[order])
            offsets.append(offsets[-1] + len(t)); labels.append(LABEL[key]); caps.append(f"usbvpn-l2tpipsec/{key}#{k}")
            st["packets"] += len(t)
        stats["files"][fn.name] = dict(st)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUT, t=np.concatenate(t_all), out=np.concatenate(out_all), size=np.concatenate(size_all),
                        offsets=np.array(offsets), label=np.array(labels), capture=np.array(caps))
    info = {"source_zip": ZIP.name, "source_zip_bytes": ZIP.stat().st_size, "source_zip_sha256": zip_sha,
            "folder": "VPN/L2TP IPsec", "tunnel_selection": "UDP, port 4500 on both ends (ESP in UDP)",
            "size_unit": "IP length (bytes)", "out_direction": "sign of the record's first packet",
            "label_by_file": LABEL, "merged_row_rule": f"exact sum from the file's top {VOCAB} single sizes per direction, else even split",
            "tunnel_records": len(labels), "packets": int(offsets[-1]), "per_file": stats["files"], "output": str(OUT)}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "conversion_usbvpn.json").write_text(json.dumps(info, indent=1) + "\n")
    print(json.dumps(info, indent=1))


if __name__ == "__main__":
    main()
