"""tshark ingestion (ADR-001, invariant I6).

We do not parse IKE/ESP bytes ourselves — tshark is mature and better tested,
and shelling out keeps a clean GPL boundary and gives an independent oracle.
This module turns a pcap into normalized IKE and ESP record dicts; the
extractors in tunnelscope/evidence build Findings from them.
"""
from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from collections import OrderedDict
from pathlib import Path

from ..errors import DependencyError, InputError

# A capture that makes tshark hang would otherwise hang a whole fleet scan
# with no output at all. Bounded per invocation; override for huge captures.
DEFAULT_TIMEOUT_S = int(os.environ.get("TUNNELSCOPE_TSHARK_TIMEOUT", "120"))

# IANA IKEv2 Key Exchange Method registry (Transform Type 4) — we carry the
# ID->name map ourselves so PQ transforms are named even on a tshark that
# prints them numerically (T-024: released tshark shows "36", master names it).
KE_METHOD = {
    14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096", 19: "ECP-256", 20: "ECP-384",
    21: "ECP-521", 31: "Curve25519", 32: "Curve448",
    35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024",
}
EXCHANGE = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
            37: "INFORMATIONAL", 43: "IKE_INTERMEDIATE"}
TRANSFORM_TYPE = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "ESN",
                  6: "ADDKE1", 7: "ADDKE2", 8: "ADDKE3", 9: "ADDKE4",
                  10: "ADDKE5", 11: "ADDKE6", 12: "ADDKE7"}


def tshark_bin() -> str:
    b = shutil.which("tshark")
    if not b:
        raise DependencyError(
            "tshark not found on PATH (ADR-001 runtime dependency). "
            "Install it with: apt-get install tshark  |  brew install wireshark"
        )
    return b


def _int(s, default=None):
    """Parse tshark ints that may be hex (0x..), decimal, or empty."""
    if s is None or s == "":
        return default
    s = s.split(",")[0]
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return default


def _flags(s) -> int:
    """ISAKMP flags are hex. tshark prints them 0x-prefixed today, but a bare
    "20" read as decimal would be 0x14 — the responder bit would read clear,
    ike_sa_crypto() would return {} and the whole crypto finding would vanish
    with no error. One interpretation, used by every caller.
    """
    if not s:
        return 0
    s = s.split(",")[0].strip()
    try:
        return int(s, 16)
    except ValueError:
        return 0


def _float(s, default=0.0):
    """Timestamps come straight from tshark; an unparseable one is a gap in
    the evidence, not a reason to abort the capture."""
    try:
        return float(s) if s else default
    except (TypeError, ValueError):
        return default


def _run_fields(pcap: str, display_filter: str, fields: list[str],
                timeout: int | None = None) -> list[list[str]]:
    p = Path(pcap)
    if not p.exists():
        raise InputError(f"capture not found: {pcap}")
    args = [tshark_bin(), "-r", str(pcap), "-Y", display_filter, "-T", "fields",
            "-E", "occurrence=a"]
    for f in fields:
        args += ["-e", f]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout or DEFAULT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise InputError(
            f"tshark timed out after {timeout or DEFAULT_TIMEOUT_S}s on {pcap} — "
            "raise TUNNELSCOPE_TSHARK_TIMEOUT if this capture is genuinely large"
        ) from None
    if proc.returncode != 0:
        # tshark's own stderr says WHY (not a capture file, truncated, unreadable).
        # Swallowing it into a CalledProcessError leaves the caller guessing.
        why = (proc.stderr or "").strip().splitlines()
        detail = why[-1] if why else f"tshark exited {proc.returncode}"
        raise InputError(f"tshark could not read {pcap}: {detail}")
    return [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]


# --------------------------------------------------------------------------- #
# Per-capture memo.                                                            #
#                                                                              #
# Each reader below spawns tshark, which re-reads the WHOLE capture. One       #
# analyze() costs 3 of those (ike, esp, crypto) and ike_sa_crypto() is called  #
# once per SA on the same file, so a multi-SA capture re-parses it repeatedly; #
# a fleet scan multiplies that by every file. Results are memoised on          #
# (path, mtime_ns, size) so a capture that changes on disk is re-read rather   #
# than served stale.                                                           #
#                                                                              #
# Contract: cached values are shared, so callers must treat them as READ-ONLY. #
# Every caller in this package only reads them (verified before this landed);  #
# test_ingest_cache.py guards that.                                            #
# --------------------------------------------------------------------------- #
_CACHE_CAPTURES = int(os.environ.get("TUNNELSCOPE_CACHE_CAPTURES", "8"))
_CACHE: "OrderedDict[tuple, object]" = OrderedDict()
_MISS = object()


def _fingerprint(pcap: str) -> tuple:
    st = Path(pcap).stat()
    return (str(Path(pcap).resolve()), st.st_mtime_ns, st.st_size)


def clear_cache() -> None:
    """Drop every memoised capture (tests, and long-lived callers)."""
    _CACHE.clear()


def _memo(fn):
    """Memoise a single-argument capture reader."""
    @functools.wraps(fn)
    def wrapper(pcap: str):
        if _CACHE_CAPTURES <= 0:
            return fn(pcap)
        try:
            key = (fn.__name__, _fingerprint(pcap))
        except OSError:
            return fn(pcap)   # missing/unstattable: let the reader raise the real error
        hit = _CACHE.get(key, _MISS)
        if hit is not _MISS:
            _CACHE.move_to_end(key)
            return hit
        val = fn(pcap)
        _CACHE[key] = val
        _CACHE.move_to_end(key)
        # three readers per capture, so cap entries at 3x the capture budget
        while len(_CACHE) > _CACHE_CAPTURES * 3:
            _CACHE.popitem(last=False)
        return val
    return wrapper


def tshark_version() -> str:
    """Version string of the tshark actually on PATH, for report provenance."""
    try:
        out = subprocess.run([tshark_bin(), "-v"], capture_output=True, text=True,
                             timeout=DEFAULT_TIMEOUT_S).stdout
    except subprocess.TimeoutExpired:
        raise DependencyError("tshark -v timed out") from None
    m = re.search(r"(\d+\.\d+\.\d+)", out.splitlines()[0] if out else "")
    return m.group(1) if m else "unknown"


# Every tshark field an extractor reads. tshark's IKE dissector field names do
# move between releases (T-024 saw ADDKE naming change on master), and a field
# that silently stops resolving yields an EMPTY finding rather than an error —
# which is exactly the "absence read as compliance" failure this project
# refuses to ship. So we assert them up front instead of discovering it in a
# verdict.
REQUIRED_FIELDS = (
    "frame.number", "frame.time_relative", "ip.src", "ip.dst", "ip.len",
    "isakmp.ispi", "isakmp.rspi", "isakmp.exchangetype", "isakmp.flags",
    "isakmp.messageid", "isakmp.length", "isakmp.notify.msgtype",
    "isakmp.tf.type", "isakmp.tf.id", "isakmp.vid_string",
    "isakmp.certreq.type", "isakmp.tf.id.encr", "isakmp.ike2.attr.key_length",
    "isakmp.tf.id.prf", "isakmp.tf.id.integ", "isakmp.tf.id.dh",
    "esp.spi", "esp.sequence",
)


@functools.lru_cache(maxsize=1)
def _known_fields() -> frozenset[str]:
    """Field abbreviations this tshark build actually exposes (`-G fields`)."""
    try:
        out = subprocess.run([tshark_bin(), "-G", "fields"], capture_output=True,
                             text=True, timeout=DEFAULT_TIMEOUT_S).stdout
    except subprocess.TimeoutExpired:
        raise DependencyError("tshark -G fields timed out") from None
    names = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and parts[0] == "F" and len(parts) > 2:
            names.add(parts[2])
    return frozenset(names)


def preflight() -> dict:
    """Verify the analysis stack before trusting anything it produces.

    Returns provenance (binary, version) on success; raises DependencyError
    naming the exact fields that vanished if tshark has drifted.
    """
    missing = sorted(f for f in REQUIRED_FIELDS if f not in _known_fields())
    if missing:
        raise DependencyError(
            f"this tshark ({tshark_version()}) does not expose "
            f"{len(missing)} field(s) TunnelScope reads: {', '.join(missing)}. "
            "Findings derived from them would be silently empty, so the run is "
            "refused rather than under-reporting."
        )
    return {"tshark": tshark_bin(), "tshark_version": tshark_version()}


@_memo
def ike_messages(pcap: str) -> list[dict]:
    """One dict per IKE message (ISAKMP). Plaintext fields only — payload
    contents beyond IKE_SA_INIT are encrypted."""
    fields = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "ip.len",
              "isakmp.ispi", "isakmp.rspi", "isakmp.exchangetype", "isakmp.flags",
              "isakmp.messageid", "isakmp.length",
              "isakmp.notify.msgtype", "isakmp.tf.type", "isakmp.tf.id",
              "isakmp.vid_string", "isakmp.certreq.type"]
    rows = _run_fields(pcap, "isakmp", fields)
    msgs = []
    for r in rows:
        r = (r + [""] * len(fields))[:len(fields)]
        (fn, t, src, dst, iplen, ispi, rspi, exch, flags, mid, ilen,
         notify, tftype, tfid, vid, certreq) = r

        def ints(s):
            # tolerant on purpose: tshark may print these hex or decimal, and a
            # single unparseable entry must not abort the whole capture.
            vals = [_int(x) for x in s.split(",") if x != ""]
            return [v for v in vals if v is not None]

        exch_i = _int(exch)
        flags_i = _flags(flags)
        msgs.append(dict(
            frame=_int(fn), t=_float(t),
            src=src, dst=dst, ip_len=_int(iplen, 0),
            ispi=ispi, rspi=rspi,
            exchange=exch_i, exchange_name=EXCHANGE.get(exch_i, str(exch_i)),
            is_response=bool(flags_i & 0x20), is_initiator=bool(flags_i & 0x08),
            message_id=_int(mid),
            isakmp_len=_int(ilen, 0),
            notify_types=ints(notify),
            transform_types=ints(tftype), transform_ids=ints(tfid),
            vendor_ids=[v for v in vid.split(",") if v] if vid else [],
            has_certreq=bool(certreq),
        ))
    return msgs


@_memo
def esp_packets(pcap: str) -> list[dict]:
    """One dict per ESP packet (native proto-50). Outer header + SPI/seq are
    always plaintext; content length is ip.len - 20(outer v4) - 8(SPI+seq)."""
    fields = ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
              "ip.len", "esp.spi", "esp.sequence"]
    rows = _run_fields(pcap, "esp", fields)
    pkts = []
    for r in rows:
        r = (r + [""] * len(fields))[:len(fields)]
        fn, t, src, dst, iplen, spi, seq = r
        ip_len = _int(iplen, 0)
        pkts.append(dict(
            frame=_int(fn), t=_float(t),
            src=src, dst=dst, ip_len=ip_len,
            esp_content=max(ip_len - 20 - 8, 0),
            spi=spi, seq=_int(seq),
        ))
    return pkts


def capture_summary(pcap: str) -> dict:
    """Quick shape of a capture: does it contain IKE, ESP, which exchanges."""
    p = Path(pcap)
    if not p.exists():
        raise InputError(f"capture not found: {pcap}")
    ike = ike_messages(pcap)
    esp = esp_packets(pcap)
    exch = sorted({m["exchange_name"] for m in ike if m["exchange"] is not None})
    return {"pcap": str(pcap), "n_ike": len(ike), "n_esp": len(esp),
            "exchanges": exch,
            "has_ike_sa_init": any(m["exchange"] == 34 for m in ike)}


# IKEv2 Encryption (Transform Type 1) and Integrity (Type 3) id -> name (IANA)
IKE_ENCR = {12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12",
            16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
            28: "ChaCha20-Poly1305", 3: "3DES", 11: "NULL"}
IKE_INTEG = {0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 5: "AES-XCBC-96",
             12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}
IKE_PRF = {1: "PRF-HMAC-MD5", 2: "PRF-HMAC-SHA1", 5: "PRF-HMAC-SHA2-256",
           6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512"}


@_memo
def ike_sa_crypto(pcap: str) -> dict:
    """The IKE SA's negotiated crypto suite from the plaintext IKE_SA_INIT
    RESPONSE (the responder's single selected proposal). T1-observable. This is
    the IKE SA key length (observable), NOT the ESP key length (F-05, unobservable)."""
    fields = ["ip.src", "isakmp.flags", "isakmp.tf.id.encr", "isakmp.ike2.attr.key_length",
              "isakmp.tf.id.prf", "isakmp.tf.id.integ", "isakmp.tf.id.dh"]
    rows = _run_fields(pcap, "isakmp.exchangetype==34", fields)
    for r in rows:
        r = (r + [""] * len(fields))[:len(fields)]
        src, flags, encr, klen, prf, integ, dh = r
        if not (_flags(flags) & 0x20):   # responder message only = the selected suite
            continue
        e = _int(encr); d = _int(dh); i = _int(integ); pr = _int(prf); kl = _int(klen)
        return {
            "encr": IKE_ENCR.get(e, f"encr-{e}") if e is not None else None,
            "encr_keylen": kl,
            "prf": IKE_PRF.get(pr, f"prf-{pr}") if pr is not None else None,
            "integ": IKE_INTEG.get(i, f"integ-{i}") if i is not None else None,
            "dh": KE_METHOD.get(d, f"dh-{d}") if d is not None else None,
            "dh_id": d,
        }
    return {}
