#!/usr/bin/env python3
"""EXP-19: convert MIT VNAT's dataframe into the packet arrays analyze.py reads.

Runs in a separate environment that has pandas + PyTables (not TunnelScope dependencies):
  ~/Datasets/vnat/.venv-convert/bin/python experiments/exp19-real-public-traffic/convert_vnat.py

Decisions made from the file's structure only (no label or metric looked at), per PREREG.md:
- sizes are IP lengths (the most common small non-VPN packet is 52 bytes, a TCP ACK with timestamps
  at the IP layer; as a frame it would be 66), so nothing is subtracted;
- only the OpenVPN tunnel flow of each `vpn_*` capture is used: UDP with port 1195 on both ends
  (82 flows, one per file). The other connections recorded in those files (TCP to cloud hosts, one
  STUN flow) are not traffic inside the tunnel;
- "out" = the side that sent the flow's first packet (the VPN client that started it), the same way
  our lab defines the initiator's direction.
"""
import hashlib
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

H5 = Path.home() / "Datasets/vnat/VNAT_Dataframe_release_1.h5"
OUT = Path.home() / "Datasets/vnat/converted/vnat_vpn_packets.npz"
RESULTS = Path(__file__).resolve().parent / "results"
MAP = {"netflix": "video", "youtube": "video", "vimeo": "video", "voip": "voip", "skype-chat": "messaging",
       "ssh": "interactive", "rdp": "interactive", "sftp": "bulk", "rsync": "bulk", "scp": "bulk"}
NAME = re.compile(r"^vpn_(.+?)_capture_?\d+\.pcap$")


def main() -> None:
    sha = hashlib.sha256(H5.read_bytes()).hexdigest()
    df = pd.read_hdf(H5, "/data")
    vpn = df[df.file_names.str.startswith("vpn_")]
    tun = vpn[[c[4] == 17 and c[1] == 1195 and c[3] == 1195 for c in vpn.connection]]
    t_all, out_all, size_all, offsets, labels, files = [], [], [], [0], [], []
    unmapped = set()
    for _, r in tun.iterrows():
        m = NAME.match(r.file_names)
        key = m.group(1) if m else None
        if key not in MAP:
            unmapped.add(r.file_names)
            continue
        ts = np.asarray(r.timestamps, float)
        order = np.argsort(ts, kind="stable")
        ts, dirs, sz = ts[order], np.asarray(r.directions)[order], np.asarray(r.sizes, int)[order]
        t_all.append(ts)
        out_all.append(dirs == dirs[0])
        size_all.append(sz)
        offsets.append(offsets[-1] + len(ts))
        labels.append(MAP[key])
        files.append(r.file_names)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUT, t=np.concatenate(t_all), out=np.concatenate(out_all), size=np.concatenate(size_all),
                        offsets=np.array(offsets), label=np.array(labels), capture=np.array(files))
    info = {"source_file": H5.name, "source_bytes": H5.stat().st_size, "source_sha256": sha,
            "connections_total": int(len(df)), "vpn_files": int(vpn.file_names.nunique()),
            "vpn_connections": int(len(vpn)), "tunnel_flows_used": len(labels), "unmapped_files": sorted(unmapped),
            "packets": int(offsets[-1]), "size_unit": "IP length (bytes)", "out_direction": "sender of the flow's first packet",
            "tunnel_selection": "UDP, port 1195 on both ends", "output": str(OUT)}
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "conversion.json").write_text(json.dumps(info, indent=1) + "\n")
    print(json.dumps(info, indent=1))


if __name__ == "__main__":
    main()
