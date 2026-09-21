#!/usr/bin/env python3
"""T-089: generate dataset/TRAFFIC-DATASHEET.md from traffic manifests and packet tables.

Standard library only: csv, gzip, hashlib, pathlib, collections.
Deterministic output: sorted keys/tables, no timestamps.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
import gzip
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "dataset" / "TRAFFIC-DATASHEET.md"

MANIFEST_DEFS = [
    ("EXP-05", "testbed/captures/exp05/manifest.csv", "testbed/captures/exp05"),
    ("EXP-15", "testbed/captures/exp15/traffic/manifest.csv", "testbed/captures/exp15/traffic"),
    ("EXP-16", "testbed/captures/exp16/manifest.csv", "testbed/captures/exp16"),
]

HOW_IT_WAS_MADE = (
    "Sessions were recorded at a keyless router between two IPsec gateways, headers only, "
    "so what the file holds is what a passive observer sees. EXP-05 and EXP-15 use a seeded "
    "traffic generator (testbed/scripts/tgen.py) that imitates eight traffic shapes: voip, "
    "web, bulk (file transfer), interactive (SSH-like), video, email (SMTP-like), messaging "
    "(WhatsApp-like) and icmp. EXP-16 adds real software (headless Chromium, OpenSSH and SFTP, "
    "Postfix with swaks, an XMPP client and server, ffmpeg RTP, ping) talking to lab servers "
    "through the tunnel, and the generator's traffic carried by Libreswan instead of strongSwan. "
    "Arms: tun/base tunnel mode AES-GCM-256; tfc traffic-flow-confidentiality padding to the MTU; "
    "tra transport mode; cbc AES-CBC-128 with HMAC-SHA-256; mux two traffic types at once; "
    "real real applications; lsw Libreswan."
)

FILES_AND_FORMAT = (
    "each session is one <tag>.pkts.csv.gz (columns t seconds since first packet, dir out|in, "
    "len outer IP length in bytes) plus a row in the source's manifest.csv with the SHA-256 of "
    "the original capture. The original .pcap files are not committed (large); they are hashed."
)

KNOWN_LIMITS = (
    "One lab network with no internet delay or packet loss. Two IPsec implementations. "
    "Traffic is generated against our own servers, so it is not representative of any organisation's "
    "real traffic. A classifier trained only on the synthetic sessions scored 0.461 on the "
    "real-application sessions (EXP-16), so synthetic and real sessions should not be treated as "
    "interchangeable. Class labels describe traffic shapes, not the applications named in them."
)


def load_manifests(
    root: Path | None = None,
    manifest_defs: list[tuple[str, str, str]] | None = None,
) -> list[dict]:
    """Load the three manifests, dedupe by tag (keeping first row), and record sessions."""
    base = root or ROOT
    defs = manifest_defs if manifest_defs is not None else MANIFEST_DEFS
    seen_tags: set[str] = set()
    sessions: list[dict] = []

    for source, rel_manifest, rel_dir in defs:
        manifest_path = base / rel_manifest
        pkts_dir = base / rel_dir
        if not manifest_path.exists():
            continue
        with open(manifest_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                tag, arm, cls, rep, seed, packets, sha256 = row
                if tag in seen_tags:
                    continue
                seen_tags.add(tag)
                sessions.append({
                    "source": source,
                    "tag": tag,
                    "arm": arm,
                    "class": cls,
                    "rep": int(rep),
                    "seed": seed,
                    "packets": int(packets),
                    "sha256": sha256,
                    "pkts_dir": pkts_dir,
                })
    return sessions


def check_discrepancies(sessions: list[dict]) -> list[str]:
    """Verify that per-packet tables exist and row counts match manifest packets."""
    discrepancies: list[str] = []
    for s in sessions:
        pkt_file = s["pkts_dir"] / f"{s['tag']}.pkts.csv.gz"
        if not pkt_file.exists():
            msg = f"WARNING: missing table {pkt_file}"
            print(msg)
            discrepancies.append(f"{s['tag']}: missing table ({pkt_file.name})")
            continue
        try:
            with gzip.open(pkt_file, "rt", newline="", encoding="utf-8") as gz:
                first = gz.readline()
                if not first:
                    count = 0
                elif first.strip() == "t,dir,len":
                    count = sum(1 for _ in gz)
                else:
                    count = 1 + sum(1 for _ in gz)
            if count != s["packets"]:
                msg = f"WARNING: {s['tag']} row count mismatch: manifest={s['packets']}, table={count}"
                print(msg)
                discrepancies.append(f"{s['tag']}: row count mismatch (manifest={s['packets']}, table={count})")
        except Exception as exc:
            msg = f"WARNING: {s['tag']} error reading table: {exc}"
            print(msg)
            discrepancies.append(f"{s['tag']}: error reading table ({exc})")
    return sorted(discrepancies)


def count_by_source(sessions: list[dict]) -> dict[str, int]:
    counts = Counter(s.get("source", "") for s in sessions)
    return {k: counts[k] for k in sorted(counts.keys())}


def count_by_arm(sessions: list[dict]) -> dict[str, int]:
    counts = Counter(s.get("arm", "") for s in sessions)
    return {k: counts[k] for k in sorted(counts.keys())}


def count_by_class(sessions: list[dict]) -> dict[str, int]:
    counts = Counter(s.get("class", "") for s in sessions)
    return {k: counts[k] for k in sorted(counts.keys())}


def count_by_rep(sessions: list[dict]) -> dict[int, int]:
    counts = Counter(s.get("rep", 0) for s in sessions)
    return {k: counts[k] for k in sorted(counts.keys())}


def count_class_by_arm(sessions: list[dict]) -> tuple[list[str], list[str], dict[tuple[str, str], int]]:
    classes = sorted(set(s.get("class", "") for s in sessions))
    arms = sorted(set(s.get("arm", "") for s in sessions))
    matrix: dict[tuple[str, str], int] = defaultdict(int)
    for s in sessions:
        matrix[(s.get("class", ""), s.get("arm", ""))] += 1
    return classes, arms, matrix


def format_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def build_datasheet_text(sessions: list[dict] | None = None, discrepancies: list[str] | None = None) -> str:
    if sessions is None:
        sessions = load_manifests()
    if discrepancies is None:
        discrepancies = check_discrepancies(sessions)

    total_sessions = len(sessions)
    total_packets = sum(s["packets"] for s in sessions)

    by_src = count_by_source(sessions)
    by_arm = count_by_arm(sessions)
    by_cls = count_by_class(sessions)
    by_rep = count_by_rep(sessions)
    classes, arms, class_arm = count_class_by_arm(sessions)

    src_rows = [[src, str(cnt)] for src, cnt in sorted(by_src.items())]
    arm_rows = [[arm, str(cnt)] for arm, cnt in sorted(by_arm.items())]
    cls_rows = [[cls, str(cnt)] for cls, cnt in sorted(by_cls.items())]
    rep_rows = [[str(rep), str(cnt)] for rep, cnt in sorted(by_rep.items())]

    matrix_headers = ["Class"] + arms
    matrix_rows = []
    for cls in classes:
        row = [cls] + [str(class_arm[(cls, arm)]) for arm in arms]
        matrix_rows.append(row)

    if discrepancies:
        disc_text = "\n".join(f"- {d}" for d in discrepancies)
    else:
        disc_text = "none"

    lines = [
        "# TunnelScope Traffic Dataset — Datasheet",
        "",
        "## Contents",
        "",
        f"- Total sessions: {total_sessions}",
        f"- Total packets: {total_packets}",
        "",
        "### By source",
        "",
        format_markdown_table(["Source", "Sessions"], src_rows),
        "",
        "### By arm",
        "",
        format_markdown_table(["Arm", "Sessions"], arm_rows),
        "",
        "### By class",
        "",
        format_markdown_table(["Class", "Sessions"], cls_rows),
        "",
        "### By repetition",
        "",
        format_markdown_table(["Repetition", "Sessions"], rep_rows),
        "",
        "### Class by arm",
        "",
        format_markdown_table(matrix_headers, matrix_rows),
        "",
        "## How it was made",
        "",
        HOW_IT_WAS_MADE,
        "",
        "## Files and format",
        "",
        FILES_AND_FORMAT,
        "",
        "## Known limits",
        "",
        KNOWN_LIMITS,
        "",
        "## Licence",
        "",
        "TBD (owner decision)",
        "",
        "## Citation",
        "",
        "TBD (owner decision)",
        "",
        "## Discrepancies",
        "",
        disc_text,
        "",
    ]
    return "\n".join(lines)


def build_datasheet(output_path: Path | None = None, root: Path | None = None) -> str:
    out_file = output_path or DEFAULT_OUT
    sessions = load_manifests(root)
    discrepancies = check_discrepancies(sessions)
    text = build_datasheet_text(sessions, discrepancies)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(text, encoding="utf-8")
    return text


def main() -> None:
    sessions = load_manifests()
    discrepancies = check_discrepancies(sessions)
    text = build_datasheet_text(sessions, discrepancies)
    DEFAULT_OUT.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUT.write_text(text, encoding="utf-8")
    print(f"TRAFFIC-DATASHEET.md written: {len(sessions)} sessions, {sum(s['packets'] for s in sessions)} packets")


if __name__ == "__main__":
    main()
