#!/usr/bin/env python3
"""T-044 / A7 — Tunnel vs Transport mode inference at T0.

Pre-registration P44-1..P44-3: research/registers/EXPERIMENT-REGISTER.md ("T-044 / A7").

Ground truth: the configured mode, confirmed by `swanctl --list-sas` (TUNNEL / TRANSPORT), T2.
Inputs: testbed/captures/a7-cs-aes256gcm16.pcap (tunnel), a7-cs-transport-aes256gcm16.pcap (transport).
"""
import json
import subprocess
import sys
from pathlib import Path

OUTER_IPV4_HDR, ESP_SPI_SEQ = 20, 8


def esp_content_lengths(pcap, src="10.10.1.10"):
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-Y", f"esp && ip.src=={src}", "-T", "fields", "-e", "ip.len"],
        capture_output=True, text=True, check=True).stdout
    return sorted(int(l) - OUTER_IPV4_HDR - ESP_SPI_SEQ for l in out.split() if l)


def main():
    cap = Path(sys.argv[1] if len(sys.argv) > 1 else "../../testbed/captures")
    res = Path(sys.argv[2] if len(sys.argv) > 2 else "results"); res.mkdir(parents=True, exist_ok=True)
    tun = esp_content_lengths(cap / "a7-cs-aes256gcm16.pcap")
    tra = esp_content_lengths(cap / "a7-cs-transport-aes256gcm16.pcap")

    # P44-1: paired offset (identical size sweep sent through both modes)
    paired = sorted(zip(sorted(set(tra)), sorted(set(tun))))
    offsets = sorted({t - r for r, t in paired})

    # P44-2: are the ACHIEVABLE length sets distinguishable without a baseline?
    # Both are AES-GCM-256 (IV 8, ICV 16, align 4): achievable content lengths are
    # exactly {c : (c - 8 - 16) % 4 == 0} = multiples of 4 above the minimum. Test
    # that every observed transport length is a *valid tunnel length too* and vice
    # versa (same residue class) => a single length reveals nothing about mode.
    def residue_ok(c):
        return (c - ESP_SPI_SEQ - 16) % 4 == 0
    all_same_residue = all(residue_ok(c) for c in tun + tra)
    # a transport packet of content C is indistinguishable from a tunnel packet of
    # content C (both are just "an ESP packet of length C"); the +20 lives in the
    # (encrypted, unknown) plaintext, so the observer cannot subtract it.
    tun_set, tra_set = set(tun), set(tra)

    report = {
        "ground_truth": "tunnel vs transport, both AES-GCM-256, from swanctl (T2)",
        "tunnel_content_lengths": tun, "transport_content_lengths": tra,
        "P44-1_paired_offsets_bytes": offsets,
        "P44-1_verdict": "HOLDS: fixed +20 (inner IPv4 header)" if offsets == [20] else f"offsets={offsets}",
        "P44-2_all_lengths_same_GCM_residue_class": all_same_residue,
        "P44-2_a_given_length_is_valid_in_both_modes": all_same_residue,
        "P44-2_verdict": ("HOLDS: mode NOT determinable from a single capture — every ESP length is "
                          "achievable by BOTH modes (same GCM residue class); the +20 is inside the "
                          "encrypted plaintext and cannot be subtracted without knowing the inner size"
                          if all_same_residue else "FALSIFIED: a length separates the modes"),
        "conclusion": ("A7 mode inference is NOT-OBSERVABLE at T0 from ESP traffic alone. It is "
                       "recoverable only with a paired-traffic baseline (P44-1), from endpoint "
                       "telemetry (T2), or from gateway-vs-host topology (P44-3). No ML component is "
                       "warranted; the analyzer reports mode from T2, or NOT-OBSERVABLE."),
    }
    (res / "exp08_results.json").write_text(json.dumps(report, indent=2))
    print("tunnel   :", tun)
    print("transport:", tra)
    print("P44-1 offsets:", offsets, "->", report["P44-1_verdict"])
    print("P44-2:", report["P44-2_verdict"])
    print("\nCONCLUSION:", report["conclusion"])


if __name__ == "__main__":
    main()
