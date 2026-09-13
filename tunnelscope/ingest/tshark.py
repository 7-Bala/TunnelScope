"""tshark ingestion (ADR-001, invariant I6).

We do not parse IKE/ESP bytes ourselves — tshark is mature and better tested,
and shelling out keeps a clean GPL boundary and gives an independent oracle.
This module turns a pcap into normalized IKE and ESP record dicts; the
extractors in tunnelscope/evidence build Findings from them.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

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
        raise RuntimeError("tshark not found (ADR-001 runtime dependency)")
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


def _run_fields(pcap: str, display_filter: str, fields: list[str]) -> list[list[str]]:
    args = [tshark_bin(), "-r", str(pcap), "-Y", display_filter, "-T", "fields",
            "-E", "occurrence=a"]
    for f in fields:
        args += ["-e", f]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line.strip()]


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
            return [int(x) for x in s.split(",") if x != ""]

        exch_i = _int(exch)
        flags_i = int(flags, 16) if flags else 0
        msgs.append(dict(
            frame=_int(fn), t=float(t) if t else 0.0,
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
            frame=_int(fn), t=float(t) if t else 0.0,
            src=src, dst=dst, ip_len=ip_len,
            esp_content=max(ip_len - 20 - 8, 0),
            spi=spi, seq=_int(seq),
        ))
    return pkts


def capture_summary(pcap: str) -> dict:
    """Quick shape of a capture: does it contain IKE, ESP, which exchanges."""
    p = Path(pcap)
    if not p.exists():
        raise FileNotFoundError(pcap)
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
        if not (_int(flags, 0) & 0x20):   # responder message only = the selected suite
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
