#!/usr/bin/env python3
"""T-156: one loader for every traffic family, as raw per-session packet streams (time, direction, IP length).

Families (a family = one source of traffic generators; holding a whole family out is the honest test of
"traffic it has never seen"):

  lab-tgen       our seeded shape generator: EXP-05, EXP-15, EXP-16 (Libreswan arm), EXP-17 synthetic arms
  lab-real-apps  our real applications: EXP-16 real arm, EXP-17 real arms
  vnat           MIT LL VNAT, real OpenVPN tunnels (~/Datasets/vnat/converted)
  usbvpn         USBVPN2022, real L2TP-over-IPsec (~/Datasets/usbvpn2022/converted)
  wireguard      real people's WireGuard traffic (~/Datasets/wg-matched/converted); its nDPI "web" is excluded
                 exactly as the shipped model excludes it (EXP-20 Q5)
  lab-a          ipsec-pcap-lab (other team, permission relayed by the owner), via the product's own packet reader
  lab-b          ashwin02 SIH_2026 real_captures (other team, permission relayed by the owner), same reader
  lab-c          our EXP-41 lab C (tables in testbed/captures/exp41)

Mixed (mux) sessions are never training or test data here (they are the abstain test). Nothing is downloaded by this
module; external paths come from the environment or the defaults below, and a missing family is reported, not faked.
"""
from __future__ import annotations

import csv
import gzip
import os
import pickle
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

DATASETS = Path(os.environ.get("TUNNELSCOPE_DATASETS", Path.home() / "Datasets"))
LAB_A = os.environ.get("TUNNELSCOPE_LAB_A")          # .../ipsec-pcap-lab (with pcaps/known, metadata.csv)
LAB_B = os.environ.get("TUNNELSCOPE_LAB_B")          # .../SIH_2026 (with real_captures, manifest.csv)
CACHE = Path(os.environ.get("TUNNELSCOPE_CORPUS_CACHE", ROOT / ".corpus_cache"))
CLASSES = ["bulk", "email", "icmp", "interactive", "messaging", "video", "voip", "web"]
FAMILIES = ["lab-tgen", "lab-real-apps", "vnat", "usbvpn", "wireguard", "lab-a", "lab-b", "lab-c"]

LAB_SOURCES = [("EXP-05", "exp05", ("base", "tfc")), ("EXP-15", "exp15/traffic", ("tun", "tfc", "tra", "cbc")),
               ("EXP-16", "exp16", ("real", "lsw")), ("EXP-17", "exp17", ("wan-syn", "lossy-syn", "wan-real", "lossy-real"))]
REAL_ARMS = {"real", "wan-real", "lossy-real"}


@dataclass
class Session:
    family: str
    sid: str          # unique session id (never split across train and test)
    label: str
    t: np.ndarray     # seconds, ascending
    out: np.ndarray   # bool: direction from the side that is "out" for this session
    size: np.ndarray  # IP length of the (encrypted) packet


def _mk(family, sid, label, t, out, size):
    o = np.argsort(t, kind="stable")
    return Session(family, sid, label, np.asarray(t, float)[o], np.asarray(out, bool)[o], np.asarray(size, int)[o])


def _table(path):
    t, o, s = [], [], []
    with gzip.open(path, "rt") as f:
        next(f)
        for line in f:
            a, d, n = line.strip().split(",")
            if n:
                t.append(float(a)); o.append(d == "out"); s.append(int(n))
    return t, o, s


def packets(path) -> list[tuple[float, str, int]]:
    """A capture's per-packet table as [(t, 'out'|'in', ip_len)], the form the product's window features take."""
    t, o, s = _table(path)
    return [(a, "out" if d else "in", n) for a, d, n in zip(t, o, s)]


def lab_sessions() -> list[Session]:
    out = []
    for tag, rel, arms in LAB_SOURCES:
        cap = ROOT / "testbed/captures" / rel
        seen = set()
        for row in csv.reader(open(cap / "manifest.csv")):
            t, a, cls = row[0], row[1], row[2]
            if t in seen or a not in arms:
                continue
            seen.add(t)
            tt, oo, ss = _table(cap / f"{t}.pkts.csv.gz")
            out.append(_mk("lab-real-apps" if a in REAL_ARMS else "lab-tgen", f"{tag}:{t}", cls, tt, oo, ss))
    return out


def _npz_flows(path, family, tkey="t", skey="size", label_ok=lambda lab: True, sid_key="capture"):
    if not path.exists():
        print(f"[corpus] {family}: {path} not found, family skipped", file=sys.stderr)
        return []
    d = np.load(path, allow_pickle=False)
    off, lab, sid = d["offsets"], d["label"], d[sid_key]
    T, O, S = d[tkey], d["out"], d[skey]           # each array decompressed ONCE (an npz re-reads on every access)
    out = []
    for i in range(len(lab)):
        if not label_ok(str(lab[i])):
            continue
        a, b = off[i], off[i + 1]
        out.append(_mk(family, f"{family}:{sid[i]}:{i}", str(lab[i]), T[a:b], O[a:b], S[a:b]))
    return out


def vnat_sessions():
    return _npz_flows(DATASETS / "vnat/converted/vnat_vpn_packets.npz", "vnat")


def usbvpn_sessions():
    return _npz_flows(DATASETS / "usbvpn2022/converted/usbvpn_l2tpipsec_packets.npz", "usbvpn")


def wireguard_sessions():
    return _npz_flows(DATASETS / "wg-matched/converted/wg_flows_packets.npz", "wireguard", tkey="t_outer", skey="size_outer",
                      label_ok=lambda lab: lab != "web")


def _pcap_streams(paths):
    from concurrent.futures import ProcessPoolExecutor
    with ProcessPoolExecutor(4) as ex:
        return list(ex.map(_one_pcap, paths))


def _one_pcap(path):
    from tunnelscope.evidence.extract import build_records
    try:
        recs = build_records(path)
    except Exception as e:                      # reported, never silently dropped
        return {"error": f"{type(e).__name__}: {e}"}
    rec = max(recs, key=lambda r: len(getattr(r, "_esp", [])), default=None)
    esp = [p for p in getattr(rec, "_esp", []) if p.get("ip_len")] if rec else []
    if not esp:
        return {"error": "no ESP"}
    src = rec.src if any(p["src"] == rec.src for p in esp) else esp[0]["src"]
    return {"t": [p["t"] for p in esp], "out": [p["src"] == src for p in esp], "size": [p["ip_len"] for p in esp]}


def lab_a_sessions():
    if not LAB_A:
        print("[corpus] lab-a: TUNNELSCOPE_LAB_A not set, family skipped", file=sys.stderr)
        return []
    base = Path(LAB_A)
    meta = {r["pcap_path"]: r["canonical_label"] for r in csv.DictReader(open(base / "metadata.csv"))}
    files = sorted(p for p in base.glob("pcaps/known/**/*.pcap"))
    res = _cached("lab-a", files, _pcap_streams)
    m = {"file_transfer": "bulk"}
    return [_mk("lab-a", f"lab-a:{f.name}", m.get(meta[str(f.relative_to(base))], meta[str(f.relative_to(base))]),
                r["t"], r["out"], r["size"]) for f, r in zip(files, res) if "error" not in r]


def lab_b_sessions():
    if not LAB_B:
        print("[corpus] lab-b: TUNNELSCOPE_LAB_B not set, family skipped", file=sys.stderr)
        return []
    base = Path(LAB_B)
    man = {r["filename"]: r["traffic_class"] for r in csv.DictReader(open(base / "manifest.csv"))}
    files = sorted(p for p in (base / "real_captures").glob("*.pcap") if man.get(p.name, "handshake") != "handshake")
    res = _cached("lab-b", files, _pcap_streams)
    m = {"file_transfer": "bulk"}
    return [_mk("lab-b", f"lab-b:{f.name}", m.get(man[f.name], man[f.name]), r["t"], r["out"], r["size"])
            for f, r in zip(files, res) if "error" not in r]


def lab_c_sessions():
    out = []
    for p in sorted((ROOT / "testbed/captures/exp41").glob("exp41-*.pkts.csv.gz")):
        m = re.match(r"exp41-(gcm|cbc)-(\w+)-rep(\d)\.pkts\.csv\.gz", p.name)
        t, o, s = _table(p)
        out.append(_mk("lab-c", f"lab-c:{p.name}", m[2], t, o, s))
    return out


def _cached(name, files, fn):
    CACHE.mkdir(parents=True, exist_ok=True)
    key = CACHE / f"{name}.pkl"
    sig = [(str(f), f.stat().st_size) for f in files]
    if key.exists():
        c = pickle.load(open(key, "rb"))
        if c.get("sig") == sig:
            return c["res"]
    res = fn([str(f) for f in files])
    pickle.dump({"sig": sig, "res": res}, open(key, "wb"))
    return res


LOADERS = {"lab-tgen": None, "lab-real-apps": None, "vnat": vnat_sessions, "usbvpn": usbvpn_sessions,
           "wireguard": wireguard_sessions, "lab-a": lab_a_sessions, "lab-b": lab_b_sessions, "lab-c": lab_c_sessions}


def load(families=None) -> list[Session]:
    families = families or FAMILIES
    out: list[Session] = []
    if {"lab-tgen", "lab-real-apps"} & set(families):
        out += [s for s in lab_sessions() if s.family in families]
    for fam in families:
        if LOADERS.get(fam):
            out += LOADERS[fam]()
    return out


if __name__ == "__main__":
    from collections import Counter
    ss = load()
    for fam in FAMILIES:
        sub = [s for s in ss if s.family == fam]
        print(f"{fam:14} sessions={len(sub):5} packets={sum(len(s.t) for s in sub):10}  {dict(Counter(s.label for s in sub))}")
