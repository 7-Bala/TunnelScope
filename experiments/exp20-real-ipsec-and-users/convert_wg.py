#!/usr/bin/env python3
"""EXP-20: convert the WireGuard matched-view dataset (Razooqi & Pekar, Zenodo 18945858, CC BY 4.0)
into per-flow packet arrays: the real OUTER (encrypted WireGuard) packets and the real INNER packets
they carry. Runs in a separate environment with pandas + pyarrow (not TunnelScope dependencies):

  ~/Datasets/vnat/.venv-convert/bin/python experiments/exp20-real-ipsec-and-users/convert_wg.py

Decisions made from structure and label names only (no metric looked at), recorded in build/14 §3.3:
- a flow is one nDPI inner flow; its packets are the matched rows with the same canonical 5-tuple
  whose inner time lies inside the flow's [start, end];
- labels: nDPI category, only when `application_is_guessed` == 0. VoIP -> voip, Chat -> messaging,
  Email -> email, Download -> bulk, Web -> web (Web is a separate arm: it probably contains video);
  every other category is not mapped;
- kept only if >= 20 matched packets and >= 6 s long (fewer cannot give 3 two-second windows);
- outer size = UDP length + 20 (IPv4 header), i.e. the IP length, the unit the tool measures;
  inner size = the inner packet's IP length; "out" = direction of the flow's first packet.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

BASE = Path.home() / "Datasets/wg-matched/VPN-nonVPN-Dataset/Data"
OUT = Path.home() / "Datasets/wg-matched/converted/wg_flows_packets.npz"
RESULTS = Path(__file__).resolve().parent / "results"
MAP = {"VoIP": "voip", "Chat": "messaging", "Email": "email", "Download": "bulk", "Web": "web"}
PKT_COLS = ["direction", "inner_time", "inner_length", "inner_proto", "outer_time", "outer_udp_length",
            "canon_ip_a", "canon_ip_b", "canon_port_a", "canon_port_b"]
FLOW_COLS = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "flow_start_ms", "flow_end_ms",
             "application_name", "application_category_name", "application_is_guessed", "matched_packets",
             "outer_duration_ms"]


def canon(a_ip, b_ip, a_port, b_port):
    """Same as the dataset's canonical_key (Code/packet_matching.py): IPs sorted, ports sorted separately."""
    return tuple(sorted((a_ip, b_ip))) + tuple(sorted((int(a_port), int(b_port))))


def main() -> None:
    sha = {}
    t_o, s_o, t_i, s_i, out_all, offsets, labels, apps, caps, sess = [], [], [], [], [], [0], [], [], [], []
    stats = {}
    for s in (1, 2):
        fp = BASE / f"session{s}/session{s}_flows.parquet"
        pp = BASE / f"session{s}/session{s}_packet_matches.parquet"
        sha[fp.name] = hashlib.sha256(fp.read_bytes()).hexdigest()
        sha[pp.name] = hashlib.sha256(pp.read_bytes()).hexdigest()
        fl = pd.read_parquet(fp, columns=FLOW_COLS)
        keep = fl[(fl.application_is_guessed == 0) & fl.application_category_name.isin(list(MAP))
                  & (fl.matched_packets >= 20) & (fl.outer_duration_ms >= 6000)].copy()
        pk = pd.read_parquet(pp, columns=PKT_COLS)
        # sort the packets once by their canonical key, then each flow is a contiguous slice of plain
        # arrays (a per-flow DataFrame lookup on 41M rows took hours)
        keys = ["canon_ip_a", "canon_ip_b", "canon_port_a", "canon_port_b", "inner_proto"]
        code = pk.groupby(keys, sort=False).ngroup().to_numpy()
        order = np.argsort(code, kind="stable")
        code_sorted = code[order]
        starts = np.flatnonzero(np.r_[True, code_sorted[1:] != code_sorted[:-1]])
        ends = np.r_[starts[1:], len(order)]
        first_rows = pk.iloc[order[starts]][keys]
        where = {tuple(k): (a, b) for k, a, b in zip(first_rows.itertuples(index=False, name=None), starts, ends)}
        a_ti = pk.inner_time.to_numpy(float); a_to = pk.outer_time.to_numpy(float)
        a_li = pk.inner_length.to_numpy(np.int32); a_lo = (pk.outer_udp_length.to_numpy(np.int64) + 20).astype(np.int32)
        a_dir = (pk.direction.to_numpy() == "OUTBOUND")
        del pk, code, code_sorted, first_rows
        st = {"flows_labelled_kept": int(len(keep)), "flows_without_packets": 0, "packets": 0,
              "count_within_5pct_of_dataset_matched_packets": 0}
        for r in keep.itertuples(index=False):
            key = canon(r.src_ip, r.dst_ip, r.src_port, r.dst_port) + (int(r.protocol),)
            span = where.get(key)
            if span is None:
                st["flows_without_packets"] += 1
                continue
            idx = order[span[0]:span[1]]
            ti = a_ti[idx]
            idx = idx[(ti * 1000 >= r.flow_start_ms - 1) & (ti * 1000 <= r.flow_end_ms + 1)]
            if len(idx) < 20:
                st["flows_without_packets"] += 1
                continue
            idx = idx[np.argsort(a_to[idx], kind="stable")]
            if abs(len(idx) - r.matched_packets) <= 0.05 * r.matched_packets:
                st["count_within_5pct_of_dataset_matched_packets"] += 1
            d = a_dir[idx]
            t_o.append(a_to[idx]); s_o.append(a_lo[idx]); t_i.append(a_ti[idx]); s_i.append(a_li[idx])
            out_all.append(d == d[0])
            offsets.append(offsets[-1] + len(idx)); labels.append(MAP[r.application_category_name])
            apps.append(r.application_name); caps.append(f"wg-s{s}/flow{r.flow_id}"); sess.append(s)
            st["packets"] += int(len(idx))
        st["flows_converted"] = st["flows_labelled_kept"] - st["flows_without_packets"]
        stats[f"session{s}"] = st
    OUT.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUT, t_outer=np.concatenate(t_o), size_outer=np.concatenate(s_o),
                        t_inner=np.concatenate(t_i), size_inner=np.concatenate(s_i), out=np.concatenate(out_all),
                        offsets=np.array(offsets), label=np.array(labels), app=np.array(apps),
                        capture=np.array(caps), session=np.array(sess))
    lab = np.array(labels)
    info = {"source": "Zenodo 18945858 VPN-nonVPN-Dataset v3.0.0", "sha256": sha, "label_map": MAP,
            "rules": {"guessed_labels": "excluded", "min_matched_packets": 20, "min_outer_duration_s": 6},
            "size_unit": "outer: UDP length + 20 (IP length); inner: inner IP length",
            "out_direction": "direction of the flow's first packet", "per_session": stats,
            "flows_per_class": {c: int((lab == c).sum()) for c in sorted(set(labels))}, "output": str(OUT)}
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "conversion_wg.json").write_text(json.dumps(info, indent=1) + "\n")
    print(json.dumps(info, indent=1))


if __name__ == "__main__":
    main()
