"""Protocol identification, AH, mode and replay/sequence evidence (T-083).

Everything here is read from plaintext header fields or derived by stated
arithmetic from them; nothing is guessed. Each finding carries its basis.

- ipsec_protocols  which IPsec protocols carry this SA's traffic (ESP / AH)
- ah_integrity     AH's ICV is not encrypted: its length narrows the algorithm
- mode             AH: the plaintext next-header gives the mode exactly.
                   ESP: transport is PROVEN when a packet is smaller than any
                   tunnel-mode packet could be (EXP-14 size floor); otherwise
                   the mode is not provable from the capture.
- sequence_integrity  per-SPI sequence numbers: duplicates, resets, reordering
"""
from __future__ import annotations

from collections import defaultdict

from .record import EvidencePtr, EvidenceRecord, Finding, Status, Vantage

# AH ICV length (bytes) -> the integrity algorithms that produce it (IANA / RFC 8221 §6 names)
AH_ICV = {12: ["HMAC-MD5-96", "HMAC-SHA1-96", "AES-XCBC-96"],
          16: ["HMAC-SHA2-256-128", "AES-128-GMAC"],
          24: ["HMAC-SHA2-384-192"],
          32: ["HMAC-SHA2-512-256", "AES-256-GMAC"]}
TUNNEL_NH = {4: "IPv4", 41: "IPv6"}
UPPER = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 50: "ESP", 132: "SCTP"}

# EXP-14: the smallest possible tunnel-mode inner packet: 20-byte IPv4 header +
# the smallest real upper-layer header (8 bytes, ICMP/UDP). An IPv6 inner header
# is larger, so using IPv4 keeps the floor safe for both.
MIN_INNER = 20 + 8


def _align(n: int, a: int) -> int:
    return -(-n // a) * a


def tunnel_floor(families: list[str]) -> int | None:
    """Smallest ESP content a tunnel-mode packet can have, over every cipher
    family still possible for the SA (EXP-01 sieve constants)."""
    from .extract import _SIEVE
    fl = [s["iv"] + _align(MIN_INNER + 2, s["align"]) + s["icv"] for f in families if (s := _SIEVE.get(f))]
    return min(fl) if fl else None


def extract_ipsec_protocols(r: EvidenceRecord) -> None:
    esp, ah = getattr(r, "_esp", []), getattr(r, "_ah", [])
    protos = (["ESP"] if esp else []) + (["AH"] if ah else [])
    if not protos:
        r.add(Finding("ipsec_protocols", Status.UNKNOWN, Vantage.T0, "protocol_id",
                      note="no ESP or AH packet for this SA in the capture (IKE only)"))
        return
    ev = []
    if esp:
        ev.append(EvidencePtr(r.source_pcap, esp[0]["frame"], "ip.proto / esp.spi", f"ESP spi {esp[0].get('spi')}"))
    if ah:
        ev.append(EvidencePtr(r.source_pcap, ah[0]["frame"], "ip.proto / ah.spi", f"AH spi {ah[0].get('spi')}"))
    note = ("AH authenticates but does not encrypt: payloads are readable on the wire"
            if protos == ["AH"] else "")
    r.add(Finding("ipsec_protocols", Status.OBSERVED, Vantage.T0, "protocol_id", value=protos,
                  confidence=1.0, evidence=ev, note=note))


def extract_ah(r: EvidenceRecord) -> None:
    ah = getattr(r, "_ah", [])
    if not ah:
        return
    lens = sorted({p["icv_len"] for p in ah if p["icv_len"]})
    ev = [EvidencePtr(r.source_pcap, ah[0]["frame"], "ah.icv", f"{ah[0]['icv_len']} bytes")]
    if len(lens) != 1 or lens[0] not in AH_ICV:
        r.add(Finding("ah_integrity", Status.UNKNOWN, Vantage.T0, "ah_icv_length",
                      note=f"AH ICV length(s) {lens} do not map to one known algorithm family"))
        return
    cands = AH_ICV[lens[0]]
    r.add(Finding("ah_integrity", Status.OBSERVED if len(cands) == 1 else Status.INFERRED, Vantage.T0,
                  "ah_icv_length", value=cands, confidence=1.0 if len(cands) == 1 else 0.9, evidence=ev,
                  note=f"{lens[0]}-byte ICV in the unencrypted AH header"
                       + ("" if len(cands) == 1 else f"; {len(cands)} algorithms produce this length")))


def extract_mode(r: EvidenceRecord) -> None:
    """Tunnel vs transport (PS c). Three sources, most direct first."""
    ah = getattr(r, "_ah", [])
    if ah:
        nhs = [p["next_header"] for p in ah if p["next_header"] is not None]
        tun = [n for n in nhs if n in TUNNEL_NH]
        ev = [EvidencePtr(r.source_pcap, ah[0]["frame"], "ah.next_header", str(ah[0]["next_header"]))]
        if nhs and len(tun) in (0, len(nhs)):
            mode = "tunnel" if tun else "transport"
            inner = TUNNEL_NH.get(nhs[0]) or UPPER.get(nhs[0], f"protocol {nhs[0]}")
            r.add(Finding("mode", Status.OBSERVED, Vantage.T0, "ah_next_header", value=mode, confidence=1.0,
                          evidence=ev, note=f"AH next header = {nhs[0]} ({inner}), readable because AH does not encrypt"))
            return
        r.add(Finding("mode", Status.CONTRADICTORY, Vantage.T0, "ah_next_header",
                      evidence=ev, note=f"AH next headers mix tunnel and transport values: {sorted(set(nhs))}"))
        return

    esp = [p for p in getattr(r, "_esp", []) if p.get("esp_content_known", True) and p["esp_content"] > 0]
    fam = r.findings.get("esp_cipher_family")
    families = fam.value if fam is not None and fam.status == Status.INFERRED else None
    lens = [p["esp_content"] for p in esp]
    padded = len(set(lens)) == 1 and len(lens) >= 5 and lens[0] >= 1200     # TFC: all MTU-sized
    floor = tunnel_floor(families) if families else None
    small = [p for p in esp if floor is not None and p["esp_content"] < floor]
    if small and not padded:
        p = min(small, key=lambda x: x["esp_content"])
        r.add(Finding("mode", Status.INFERRED, Vantage.T0, "size_floor (EXP-14)", value="transport",
                      confidence=0.97,
                      evidence=[EvidencePtr(r.source_pcap, p["frame"], "esp content length", str(p["esp_content"]))],
                      note=f"{len(small)} ESP packet(s) as small as {p['esp_content']} B; a tunnel-mode packet with any "
                           f"of the {len(families)} possible ciphers is at least {floor} B (it carries a whole inner IP "
                           "header). Assumes no TFC dummy packets (none detected)."))
        return
    from ..leakage.mode_model import infer_mode      # exploratory model (EXP-14 addendum), may abstain
    m = infer_mode(r, families)
    if m is not None:
        r.add(m)
        return
    why = ("TFC padding makes every packet the same size" if padded else
           "no packet below the tunnel-mode size floor, and the mode model abstained or could not run"
           if esp else "no ESP traffic to measure")
    r.add(Finding("mode", Status.UNKNOWN, Vantage.T0, "mode (EXP-08/14)",
                  note=f"not provable from this capture ({why}). The mode is negotiated inside the encrypted "
                       "IKE_AUTH; endpoint telemetry (T2, crosstier) states it exactly."))


def extract_sequence(r: EvidenceRecord) -> None:
    """RFC 4303 §3.3.3 / RFC 4302 §3.3.2: a sender's sequence counter starts at
    1 and increases by one per packet, and MUST NOT cycle on one SA. On the wire
    that means: per SPI, no value should appear twice. A repeat is either a
    replayed packet or a broken sender. Whether the RECEIVER drops it (anti-
    replay enforcement, DISA V-207212) is not visible passively."""
    pkts = [(p, "ESP") for p in getattr(r, "_esp", [])] + [(p, "AH") for p in getattr(r, "_ah", [])]
    by_spi = defaultdict(list)
    for p, proto in pkts:
        if p.get("spi") and p.get("seq") is not None:
            by_spi[(proto, p["spi"])].append(p)
    if not by_spi:
        return
    replayed, capture_dup, reorder, resets, max_seq, ev = 0, 0, 0, 0, 0, []
    for (proto, spi), ps in by_spi.items():
        ps.sort(key=lambda p: (p["t"], p["frame"]))
        seen: dict[int, dict] = {}
        hi = 0
        for p in ps:
            s = p["seq"]
            max_seq = max(max_seq, s)
            if s in seen:
                first = seen[s]
                if abs(p["t"] - first["t"]) < 0.001 and p.get("ip_len") == first.get("ip_len"):
                    capture_dup += 1          # the same packet recorded twice (two taps / span port)
                else:
                    replayed += 1
                    if len(ev) < 3:
                        ev.append(EvidencePtr(r.source_pcap, p["frame"], f"{proto.lower()}.sequence",
                                              f"spi {spi} seq {s} again (first frame {first['frame']})"))
                continue
            seen[s] = p
            if s < hi:
                if s <= 2 and hi > 16:
                    resets += 1
                else:
                    reorder += 1
            hi = max(hi, s)
    value = {"spis": len(by_spi), "packets": sum(len(v) for v in by_spi.values()),
             "replayed": replayed, "resets": resets, "reordered": reorder,
             "capture_duplicates": capture_dup, "max_seq": max_seq}
    note = ("no sequence number repeated on any SA" if not (replayed or resets) else
            f"{replayed} packet(s) re-sent with an already-used sequence number"
            + (f", {resets} counter reset(s) on a live SPI" if resets else "")
            + ": a replay on this path or a sender violating RFC 4303 §3.3.3")
    if capture_dup:
        note += f"; {capture_dup} identical copies within 1 ms treated as capture duplicates, not replays"
    note += ". Whether the receiver DROPS replays (anti-replay window) is not visible passively."
    if max_seq > 0.9 * 2**32:
        note += " Counter is above 90% of 2^32: the SA must be rekeyed before it cycles."
    r.add(Finding("sequence_integrity", Status.OBSERVED, Vantage.T0, "sequence (RFC 4303 §3.3.3)", value=value,
                  confidence=1.0, evidence=ev or [EvidencePtr(r.source_pcap, pkts[0][0]["frame"], "esp/ah.sequence",
                                                              f"{len(by_spi)} SPI(s)")], note=note))
