"""Metadata-leakage measurement (T-034, CS-01) — the project's ONE ML-adjacent
component, and even here the output is bits of exposure, never a traffic label
(DEC-021, EXP-05).

Two modes:
  - per_capture(): single-SA forensic use. Measures the observable channels a
    passive adversary has — ESP size entropy, timing entropy, and whether TFC
    padding is masking sizes — in bits. This is honest for one capture: it says
    how much *structure* is exposed, not what the traffic is.
  - adversary_capability(): the EXP-05 estimator (RandomForest F1 + 1-NN Bayes
    bound + per-channel mutual information) over a LABELLED multi-session set.
    Requires reference traffic; lives in experiments/exp05 as the validated
    method and is imported here for completeness, not run on a single capture.

Key EXP-05 finding this encodes: TFC padding drives the SIZE channel to ~0 bits
but leaves the TIMING channel intact — so a "padding on" tunnel can still be
profiled. The module reports both channels separately and never claims the
size channel alone is the whole exposure.
"""
from __future__ import annotations

import math
from collections import Counter

from ..evidence.record import EvidenceRecord, Finding, Status, Vantage, EvidencePtr


def _entropy_bits(values, binner=lambda x: x) -> float:
    c = Counter(binner(v) for v in values)
    n = sum(c.values())
    if n == 0:
        return 0.0
    return max(0.0, -sum((k / n) * math.log2(k / n) for k in c.values()))


def per_capture(rec: EvidenceRecord) -> dict:
    esp = getattr(rec, "_esp", [])
    lens = [p["esp_content"] for p in esp if p["esp_content"] > 0]
    times = sorted(p["t"] for p in esp)
    iats = [round(b - a, 4) for a, b in zip(times, times[1:])] if len(times) > 1 else []

    distinct = len(set(lens))
    size_bits = _entropy_bits(lens)                                   # entropy of ESP sizes
    # timing entropy over log-spaced inter-arrival bins (matches EXP-05)
    iat_bits = _entropy_bits(iats, lambda x: int(math.floor(math.log2(x))) if x > 1e-6 else -20)
    # TFC padding pads to path MTU (RFC 4303 sec 2.7) - EXP-05's own tfc-sample
    # capture confirms this lands at 1472 B ESP content (1500 B MTU minus
    # IP/UDP/ESP overhead). "All one size" alone is NOT sufficient: naturally
    # uniform small traffic (e.g. identical-size ICMP probes, 112 B in a real
    # capture - EXP-10 addendum) triggered a false positive under the old
    # rule, because nothing distinguished "uniform because padded to MTU" from
    # "uniform because the traffic itself is uniform". MIN_PADDED_SIZE gives
    # real headroom below 1472 B for other common MTUs (1400/1420 with
    # tunnelling overhead) while safely excluding small uniform traffic.
    MIN_PADDED_SIZE = 1200
    padding_active = distinct <= 1 and len(lens) >= 5 and lens[0] >= MIN_PADDED_SIZE

    return {
        "n_esp": len(lens), "distinct_esp_lengths": distinct,
        "size_channel_bits": round(size_bits, 3),
        "timing_channel_bits": round(iat_bits, 3),
        "tfc_padding_active": padding_active,
        "interpretation": _interpret(size_bits, iat_bits, padding_active, len(lens)),
    }


def _interpret(size_bits, iat_bits, padding, n):
    if n < 5:
        return "too few ESP packets to measure leakage"
    if padding:
        return ("TFC padding masks the SIZE channel (size ≈ 0 bits), but per EXP-05 the TIMING "
                f"channel remains (~{iat_bits:.1f} bits/packet) — a timing-aware observer can still "
                "profile this tunnel. Padding alone is not sufficient; consider constant-rate IP-TFS.")
    return (f"passive size channel ~{size_bits:.1f} bits/packet and timing ~{iat_bits:.1f} bits/packet "
            "are exposed. Enabling ESP TFC padding would mask sizes (at a bandwidth cost); it would "
            "NOT hide the traffic class from a timing-aware observer (EXP-05).")


def extract_leakage(rec: EvidenceRecord) -> None:
    """Add a MEASURED metadata_exposure Finding. Bits, not a label (DEC-021)."""
    esp = getattr(rec, "_esp", [])
    if len([p for p in esp if p["esp_content"] > 0]) < 5:
        rec.add(Finding("metadata_exposure", Status.UNKNOWN, Vantage.T0, "leakage (EXP-05)",
                        note="too few ESP packets to measure")); return
    m = per_capture(rec)
    ev = [EvidencePtr(rec.source_pcap, esp[0]["frame"], "esp content lengths + timing",
                      f"size={m['size_channel_bits']}b timing={m['timing_channel_bits']}b")]
    rec.add(Finding("metadata_exposure", Status.MEASURED, Vantage.T0, "leakage (EXP-05)",
                    value={"size_bits": m["size_channel_bits"], "timing_bits": m["timing_channel_bits"],
                           "tfc_padding_active": m["tfc_padding_active"]},
                    confidence=1.0, evidence=ev, note=m["interpretation"]))
