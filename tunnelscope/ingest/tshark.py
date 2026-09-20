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
    0: "NONE",
    # every classical group a real endpoint may offer (EXP-13: AWS's default set
    # includes 2, 5, 17, 18 and 22-24, which were unnamed here and read "dh-N")
    1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536",
    14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192",
    19: "ECP-256", 20: "ECP-384", 21: "ECP-521",
    22: "MODP-1024-S160", 23: "MODP-2048-S224", 24: "MODP-2048-S256",
    31: "Curve25519", 32: "Curve448",
    35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024",
}
EXCHANGE = {2: "IKEv1_MAIN_MODE", 4: "IKEv1_AGGRESSIVE_MODE", 5: "IKEv1_INFORMATIONAL",
            32: "IKEv1_QUICK_MODE", 33: "IKEv1_NEW_GROUP_MODE",
            34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
            37: "INFORMATIONAL", 43: "IKE_INTERMEDIATE"}
TRANSFORM_TYPE = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "ESN",
                  6: "ADDKE1", 7: "ADDKE2", 8: "ADDKE3", 9: "ADDKE4",
                  10: "ADDKE5", 11: "ADDKE6", 12: "ADDKE7"}


# T-085: an ICMP error QUOTES the header of the packet that caused it, so a
# "destination unreachable" carries an ESP/AH/ISAKMP header inside it. tshark's
# display filters match those too, and with occurrence=a the quoted packet's
# ip.len is read instead of the real one. Found on a third-party capture
# (Wireshark wiki ipsec_esp_capture_2: half the "ESP" frames were ICMP errors
# quoting ESP), where it made the cipher sieve exclude the true cipher.
#
# Excluding every frame that contains ICMP would be wrong: AH does not encrypt,
# so a genuine AH packet carrying a ping legitimately contains ICMP. The layer
# order decides it - "ip:icmp:ip:esp" is quoted, "ip:ah:ip:icmp" is real - so
# each row carries frame.protocols and is kept only when the IPsec layer comes
# before any ICMP layer.
def _outermost(protocols: str, layer: str) -> bool:
    if not protocols:
        return True
    parts = protocols.split(":")
    if layer not in parts:
        return True
    first_icmp = min((parts.index(p) for p in ("icmp", "icmpv6") if p in parts), default=len(parts))
    return parts.index(layer) < first_icmp


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
    "esp.spi", "esp.sequence", "frame.protocols",
    # T-057: IPv6 and UDP-encapsulated ESP offsets
    "ip.hdr_len", "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.nxt", "udp.length",
    # T-083: AH (RFC 4302), whose header is not encrypted
    "ah.spi", "ah.sequence", "ah.next_header", "ah.icv",
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
              "ipv6.src", "ipv6.dst", "ipv6.plen",
              "isakmp.ispi", "isakmp.rspi", "isakmp.exchangetype", "isakmp.flags",
              "isakmp.messageid", "isakmp.length",
              "isakmp.notify.msgtype", "isakmp.tf.type", "isakmp.tf.id",
              "isakmp.vid_string", "isakmp.certreq.type",
              "isakmp.tf.id.dh", "isakmp.tf.id.integ", "frame.protocols"]
    rows = _run_fields(pcap, "isakmp", fields)
    msgs = []
    for r in rows:
        r = (r + [""] * len(fields))[:len(fields)]
        (fn, t, src, dst, iplen, src6, dst6, plen6, ispi, rspi, exch, flags, mid, ilen,
         notify, tftype, tfid, vid, certreq, tfdh, tfinteg, protos) = r
        if not _outermost(protos, "isakmp"):
            continue                      # quoted inside an ICMP error, not a real message

        def ints(s):
            # tolerant on purpose: tshark may print these hex or decimal, and a
            # single unparseable entry must not abort the whole capture.
            vals = [_int(x) for x in s.split(",") if x != ""]
            return [v for v in vals if v is not None]

        exch_i = _int(exch)
        flags_i = _flags(flags)
        msgs.append(dict(
            frame=_int(fn), t=_float(t),
            src=_first(src) or _first(src6), dst=_first(dst) or _first(dst6),
            ip_len=_ipv4_equivalent_len(iplen, plen6),
            ispi=ispi, rspi=rspi,
            exchange=exch_i, exchange_name=EXCHANGE.get(exch_i, str(exch_i)),
            is_response=bool(flags_i & 0x20), is_initiator=bool(flags_i & 0x08),
            message_id=_int(mid),
            isakmp_len=_int(ilen, 0),
            notify_types=ints(notify),
            transform_types=ints(tftype), transform_ids=ints(tfid),
            vendor_ids=[v for v in vid.split(",") if v] if vid else [],
            has_certreq=bool(certreq),
            # every KE / INTEG transform in this message's SA payload: for an
            # IKE_SA_INIT request, the groups the initiator would accept
            offered_dh=ints(tfdh), offered_integ=ints(tfinteg),
        ))
    return msgs


def _first(s: str) -> str:
    """First occurrence of a multi-valued tshark field ('' if absent)."""
    return s.split(",")[0] if s else ""


def _ipv4_equivalent_len(iplen: str, plen6: str) -> int:
    """IKE message size as an IPv4 total length. The IKE size rules (EXP-03 PFS,
    EXP-06 112 B) were measured on IPv4 captures; over IPv6 the same message has
    a 40 B header instead of 20 B, so an IPv6 packet is counted as payload + 20
    and the rules keep their meaning (T-057)."""
    if iplen:
        return _int(iplen, 0)
    p = _int(plen6)
    return p + 20 if p is not None else 0


@_memo
def esp_packets(pcap: str) -> list[dict]:
    """One dict per ESP packet: native ESP over IPv4 or IPv6, or UDP-encapsulated
    ESP (RFC 3948, port 4500). The outer headers and SPI/seq are plaintext;
    esp_content is what follows the 8 B SPI+sequence (IV + ciphertext + ICV).

    T-057: this used to be ip.len - 20 - 8 for every packet, which is only right
    for native ESP over option-less IPv4. UDP encapsulation adds an 8 B UDP
    header (the cipher sieve then eliminated CBC on a real CBC tunnel), and IPv6
    has no ip.len at all. Where the offset can't be known (IPv6 extension
    headers), esp_content is 0 and esp_content_known False, so downstream
    measurements skip the packet instead of using a wrong length."""
    fields = ["frame.number", "frame.time_relative", "ip.src", "ip.dst",
              "ip.len", "ip.hdr_len", "ipv6.src", "ipv6.dst", "ipv6.plen", "ipv6.nxt",
              "udp.length", "esp.spi", "esp.sequence", "frame.protocols"]
    rows = _run_fields(pcap, "esp", fields)
    pkts = []
    for r in rows:
        r = (r + [""] * len(fields))[:len(fields)]
        fn, t, src, dst, iplen, hdrlen, src6, dst6, plen6, nxt6, udplen, spi, seq, protos = r
        if not _outermost(protos, "esp"):
            continue                      # an ICMP error quoting this ESP header, not a real packet
        content, encap = None, "native"
        if udplen:
            encap = "udp"
            content = _int(udplen, 0) - 8 - 8
        elif iplen:
            content = _int(iplen, 0) - _int(hdrlen, 20) - 8
        elif plen6 and _int(nxt6) == 50:   # ESP directly after the fixed IPv6 header
            content = _int(plen6, 0) - 8
        pkts.append(dict(
            frame=_int(fn), t=_float(t),
            src=_first(src) or _first(src6), dst=_first(dst) or _first(dst6),
            ip_len=_ipv4_equivalent_len(iplen, plen6),
            ip_version=4 if iplen else 6,
            encap=encap,
            esp_content=max(content, 0) if content is not None else 0,
            esp_content_known=content is not None,
            spi=_first(spi), seq=_int(seq),
        ))
    return pkts


@_memo
def ah_packets(pcap: str) -> list[dict]:
    """AH packets (RFC 4302). AH authenticates but does not encrypt, so its
    header is readable: next_header (4 = IPv4, 41 = IPv6 inside -> tunnel mode;
    an upper-layer protocol -> transport mode) and the ICV, whose length names
    the integrity algorithm's output size."""
    fields = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "ip.len",
              "ipv6.src", "ipv6.dst", "ipv6.plen", "ah.spi", "ah.sequence", "ah.next_header", "ah.icv",
              "frame.protocols"]
    pkts = []
    for r in _run_fields(pcap, "ah", fields):
        r = (r + [""] * len(fields))[:len(fields)]
        fn, t, src, dst, iplen, src6, dst6, plen6, spi, seq, nh, icv, protos = r
        if not _outermost(protos, "ah"):
            continue
        pkts.append(dict(frame=_int(fn), t=_float(t), src=_first(src) or _first(src6),
                         dst=_first(dst) or _first(dst6), ip_len=_ipv4_equivalent_len(iplen, plen6),
                         spi=_first(spi), seq=_int(_first(seq)), next_header=_int(_first(nh)),
                         icv_len=len(_first(icv) or "") // 2))
    return pkts


def capture_summary(pcap: str) -> dict:
    """Quick shape of a capture: does it contain IKE, ESP, which exchanges."""
    p = Path(pcap)
    if not p.exists():
        raise InputError(f"capture not found: {pcap}")
    ike = ike_messages(pcap)
    esp = esp_packets(pcap)
    ah = ah_packets(pcap)
    exch = sorted({m["exchange_name"] for m in ike if m["exchange"] is not None})
    return {"pcap": str(pcap), "n_ike": len(ike), "n_esp": len(esp), "n_ah": len(ah),
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
def _ike_sa_init_responses(pcap: str) -> list[dict]:
    """Every IKE_SA_INIT RESPONSE's selected suite, in capture order (memoised
    once per capture; ike_sa_crypto() filters it per SA)."""
    fields = ["ip.src", "isakmp.flags", "isakmp.ispi", "isakmp.tf.id.encr", "isakmp.ike2.attr.key_length",
              "isakmp.tf.id.prf", "isakmp.tf.id.integ", "isakmp.tf.id.dh"]
    out = []
    for r in _run_fields(pcap, "isakmp.exchangetype==34", fields):
        r = (r + [""] * len(fields))[:len(fields)]
        src, flags, row_ispi, encr, klen, prf, integ, dh = r
        if not (_flags(flags) & 0x20):   # responder message only = the selected suite
            continue
        e = _int(encr); d = _int(dh); i = _int(integ); pr = _int(prf); kl = _int(klen)
        out.append({"ispi": row_ispi.lower().removeprefix("0x").split(",")[0], "suite": {
            "encr": IKE_ENCR.get(e, f"encr-{e}") if e is not None else None,
            "encr_keylen": kl,
            "prf": IKE_PRF.get(pr, f"prf-{pr}") if pr is not None else None,
            "integ": IKE_INTEG.get(i, f"integ-{i}") if i is not None else None,
            "dh": KE_METHOD.get(d, f"dh-{d}") if d is not None else None,
            "dh_id": d,
        }})
    return out


def ike_sa_crypto(pcap: str, ispi: str | None = None) -> dict:
    """The IKE SA's negotiated crypto suite from the plaintext IKE_SA_INIT
    RESPONSE (the responder's single selected proposal). T1-observable. This is
    the IKE SA key length (observable), NOT the ESP key length (F-05, unobservable).
    With `ispi`, only that SA's response counts (T-051: one NO_PROPOSAL_CHOSEN
    must not blank every other SA in the capture)."""
    want = ispi.lower().removeprefix("0x") if ispi else None
    rows = [r for r in _ike_sa_init_responses(pcap) if not (want and r["ispi"] and r["ispi"] != want)]
    # An error-only response (INVALID_KE_PAYLOAD asking for another DH group,
    # COOKIE, NO_PROPOSAL_CHOSEN) selects nothing; after a retry the LAST
    # response that carries a selection is the one that stands. Taking the
    # first lost the whole suite whenever the initiator's first KE guess was
    # refused (found by EXP-13: a cloud endpoint opening with DH group 2).
    selecting = [r for r in rows if any(v is not None for v in r["suite"].values())]
    if selecting:
        return dict(selecting[-1]["suite"])   # a copy: the memoised rows stay read-only
    return dict(rows[-1]["suite"]) if rows else {}
