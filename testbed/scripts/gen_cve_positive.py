#!/usr/bin/env python3
"""Generate a *plaintext-structural* positive capture for CVE-2026-78135
(T-022 sensitivity validation).

HONESTY NOTE — read before using this file as evidence:
  This is NOT a live cryptographic exploit. Every IKEv2 message after
  IKE_SA_INIT is encrypted under negotiated keys, so a real exploit capture
  needs a patched/malicious IKE stack (see EXP-09 RESULT.md "What is NOT done").
  What the TunnelScope detector actually reads is the *plaintext ISAKMP header*
  — exchange type, message id, SPIs — which are unencrypted in every IKEv2
  message. This capture forges exactly those header fields to reproduce the
  on-wire exchange-type/message-id sequence the CVE produces:
      IKE_SA_INIT (msgid 0)  ->  CREATE_CHILD_SA (msgid 1)   [no IKE_AUTH]
  It therefore faithfully exercises the detector's decision surface and proves
  its SENSITIVITY. It does NOT prove that a real exploit emits this exact
  sequence (that is an assumption grounded in RFC 7296 + the CVE description),
  nor that the encrypted payloads would be valid. Labelled accordingly in the
  dataset as synthetic / plaintext-structural.
"""
import os
import struct
import sys

from scapy.all import IP, UDP, Raw, wrpcap

IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA = 34, 35, 36
INIT = "1122334455667788"   # initiator SPI (constant across the SA)
RESP = "99aabbccddeeff00"   # responder SPI (0 in the very first request)


def ike_header(ispi_hex, rspi_hex, exch, flags, msgid, payload=b""):
    """Build a bare 28-byte IKEv2 header (RFC 7296 sec 3.1) + optional body."""
    hdr = bytes.fromhex(ispi_hex) + bytes.fromhex(rspi_hex)
    hdr += struct.pack("!BBBB", 0, 0x20, exch, flags)   # next_payload=0, version=2.0
    hdr += struct.pack("!I", msgid)
    hdr += struct.pack("!I", 28 + len(payload))
    return hdr + payload


def pkt(src, dst, sport, dport, body):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=body)


def main():
    a, b = "10.0.0.1", "10.0.0.2"
    F_INIT, F_RESP = 0x08, 0x20   # Initiator flag / Response flag (RFC 7296 sec 3.1)
    pkts = [
        # IKE_SA_INIT request: initiator, msgid 0, responder SPI still zero
        pkt(a, b, 500, 500, ike_header(INIT, "0000000000000000", IKE_SA_INIT, F_INIT, 0, b"\x00" * 200)),
        # IKE_SA_INIT response: responder SPI now set
        pkt(b, a, 500, 500, ike_header(INIT, RESP, IKE_SA_INIT, F_RESP, 0, b"\x00" * 200)),
        # CREATE_CHILD_SA request at msgid 1 — and crucially NO IKE_AUTH ever.
        pkt(a, b, 500, 500, ike_header(INIT, RESP, CREATE_CHILD_SA, F_INIT, 1, b"\x00" * 120)),
        pkt(b, a, 500, 500, ike_header(INIT, RESP, CREATE_CHILD_SA, F_RESP, 1, b"\x00" * 120)),
    ]
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), "..", "captures", "synthetic",
        "cve-2026-78135-plaintext-positive.pcap")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    wrpcap(out, pkts)
    print(f"wrote {out} ({len(pkts)} packets)")


if __name__ == "__main__":
    main()
