"""Tamper-evident evidence ledger (T-155, DEC-053).

An analysis becomes an ordered list of entries. Entry 0 binds the capture (its SHA-256 and size), the tool version and a
hash of the rule baselines it was judged against; then one entry per finding and one per rule verdict, record by record.
Each entry carries the hash of the one before it, so changing, removing, inserting or reordering any entry breaks every
entry after it, and a ledger can be checked against the capture it claims to describe.

Deterministic on purpose: no timestamps inside the chain, file paths reduced to their names, canonical JSON. The same
capture analysed by the same version and rules gives the same head hash on any machine, so a third party can re-run the
analysis and compare heads (verify_ledger(..., reanalyse=True)).

This proves the record was not altered after it was made. It does not prove the analysis was right, and it does not
replace keeping the capture.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

FORMAT = "tunnelscope-ledger/1"
ZERO = "0" * 64


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _strip_paths(obj: Any) -> Any:
    """Absolute paths differ between machines; the capture is bound by its hash, so its name is enough."""
    if isinstance(obj, dict):
        return {k: (os.path.basename(v) if k in ("pcap", "source_pcap") and isinstance(v, str) else _strip_paths(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_paths(x) for x in obj]
    return obj


def _entry(seq: int, kind: str, data: dict, prev: str) -> dict:
    body = {"seq": seq, "kind": kind, "data": data, "prev": prev}
    return {**body, "hash": hashlib.sha256(_canon(body).encode()).hexdigest()}


def _tool_version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("tunnelscope")
    except PackageNotFoundError:
        return "unknown"


def build_ledger(pcap: str, records=None, baselines=None) -> dict:
    """Analyse `pcap` (or use the given records) and return the hash-chained ledger."""
    from ..assess.engine import assess_record, load_baselines
    from ..evidence.extract import build_records
    baselines = baselines if baselines is not None else load_baselines()
    records = records if records is not None else build_records(pcap)
    entries = [_entry(0, "capture", {
        "pcap": os.path.basename(pcap), "pcap_sha256": _sha256_file(pcap), "bytes": os.path.getsize(pcap),
        "tool": "tunnelscope", "tool_version": _tool_version(),
        "rules_sha256": hashlib.sha256(_canon(baselines).encode()).hexdigest(),
        "baselines": sorted(b["baseline"] for b in baselines)}, ZERO)]
    for rec in sorted(records, key=lambda r: (r.key(), r.child_spi_in, r.child_spi_out)):
        d = _strip_paths(rec.to_dict())
        sa = {k: d[k] for k in ("sa_key", "ike_spi_i", "ike_spi_r", "child_spi_in", "child_spi_out", "src", "dst")}
        for attr in sorted(d["findings"]):
            entries.append(_entry(len(entries), "finding", {"sa": sa, **d["findings"][attr]}, entries[-1]["hash"]))
        for v in sorted(assess_record(rec, baselines), key=lambda v: (v.baseline, v.rule_id)):
            vd = _strip_paths(v.to_dict())
            entries.append(_entry(len(entries), "verdict", {"sa": sa, **vd}, entries[-1]["hash"]))
    return {"format": FORMAT, "head": entries[-1]["hash"], "count": len(entries), "entries": entries}


def verify_ledger(ledger: dict, pcap: str | None = None, reanalyse: bool = False) -> dict:
    """Check every hash and link. With `pcap`, also check the capture is the one entry 0 binds. With `reanalyse`, also
    re-run the analysis and require the same head (same capture, same version, same rules => same ledger)."""
    def bad(i, why):
        return {"ok": False, "first_bad": i, "reason": why, "count": len(ledger.get("entries") or [])}
    if ledger.get("format") != FORMAT:
        return bad(None, f"not a {FORMAT} ledger")
    entries = ledger.get("entries") or []
    if not entries:
        return bad(None, "no entries")
    prev = ZERO
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return bad(i, f"entry {i} has sequence number {e.get('seq')!r} (removed, inserted or reordered)")
        if e.get("prev") != prev:
            return bad(i, f"entry {i} does not link to the entry before it")
        body = {k: e.get(k) for k in ("seq", "kind", "data", "prev")}
        if hashlib.sha256(_canon(body).encode()).hexdigest() != e.get("hash"):
            return bad(i, f"entry {i} ({e.get('kind')}) was changed after it was written")
        prev = e["hash"]
    if ledger.get("head") != prev:
        return bad(len(entries) - 1, "the head hash does not match the last entry (entries removed from the end?)")
    if entries[0].get("kind") != "capture":
        return bad(0, "entry 0 does not bind a capture")
    if pcap is not None:
        if _sha256_file(pcap) != entries[0]["data"].get("pcap_sha256"):
            return bad(0, "this capture is not the one the ledger was made from (SHA-256 differs)")
        if reanalyse and build_ledger(pcap)["head"] != ledger["head"]:
            return bad(None, "re-analysing the capture gives a different ledger (different tool version or rules, "
                             "or the ledger was rebuilt from altered results)")
    return {"ok": True, "first_bad": None, "reason": "", "count": len(entries), "head": prev}
