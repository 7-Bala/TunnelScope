"""Exploratory tunnel/transport model (EXP-14 addendum A).

Basis, true for any TCP traffic, not just our generator: a pure TCP ACK is a
20-byte TCP header (32 with the timestamp option), and in tunnel mode it also
carries a 20-byte inner IPv4 header. With an AEAD/stream cipher (IV 8, ICV 16,
4-byte alignment: every candidate family has the same overhead) the ESP content
minus 24 is the inner length + trailer, padded to 4: pure ACKs land at 24 or 36
in transport mode, 44 or 56 in tunnel mode. The feature vector is the share of
ESP packets in each of those buckets; a Random Forest trained on EXP-15's tunnel
and transport sessions turns it into a probability.

Ships only if EXP-14's held-out evaluation met the bar declared in advance
(accuracy >= 0.95, zero tunnel sessions called transport); the model and its
threshold are loaded from tunnelscope/models/mode_windows.npz, which is written
only when that bar is met. Otherwise infer_mode() always abstains.
"""
from __future__ import annotations

import os
from functools import lru_cache

import numpy as np

BUCKETS = {"transport_ack": [24, 36], "tunnel_ack": [44, 56]}
AEAD = {"AES-CTR+HMAC-SHA256-128", "AES-GCM-16", "AES-CCM-16", "ChaCha20-Poly1305"}
DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "mode_windows.npz")


MIN_PURITY = 0.8   # share of ACK-bucket packets on ONE mode's side (added after the false positive below)


def purity(f: list[float]) -> float:
    """TCP traffic puts its pure ACKs on one side (24/36 transport, 44/56 tunnel).
    A ping size sweep spreads over both (0.56 on our sweep captures), which is
    how the first version called a tunnel capture "transport"."""
    t, u = f[0] + f[1], f[2] + f[3]
    return max(t, u) / (t + u) if t + u else 0.0


def features(content: list[int]) -> list[float]:
    n = max(len(content), 1)
    inner = [c - 24 for c in content]
    c = {b: sum(1 for x in inner if x == b) / n for b in (24, 36, 44, 56)}
    return [c[24], c[36], c[44], c[56], c[24] + c[36] + c[44] + c[56]]


@lru_cache(maxsize=1)
def _model():
    if not os.path.exists(DATA):
        return None
    from sklearn.ensemble import RandomForestClassifier
    d = np.load(DATA, allow_pickle=False)
    m = RandomForestClassifier(n_estimators=200, random_state=0, min_samples_leaf=2).fit(d["X"], d["y"])
    return m, float(d["tau"])


def infer_mode(record, families):
    """INFERRED mode Finding, or None (abstain)."""
    from ..evidence.record import EvidencePtr, Finding, Status, Vantage
    if not families or not set(families) <= AEAD:
        return None                       # overhead not uniquely known: the buckets would be wrong
    mm = _model()
    if mm is None:
        return None
    m, tau = mm
    esp = [p for p in getattr(record, "_esp", []) if p.get("esp_content_known", True) and p["esp_content"] > 0]
    if len(esp) < 20:
        return None
    f = features([p["esp_content"] for p in esp])
    if f[-1] < 0.05 or purity(f) < MIN_PURITY:
        return None                       # too few ACK-sized packets, or not a one-sided TCP pattern
    p = m.predict_proba([f])[0]
    j = int(np.argmax(p))
    if p[j] < tau:
        return None
    mode = str(m.classes_[j])
    return Finding("mode", Status.INFERRED, Vantage.T0, "ack_size_model (EXP-14 exploratory)", value=mode,
                   confidence=round(float(p[j]), 3),
                   evidence=[EvidencePtr(record.source_pcap, esp[0]["frame"], "esp content lengths",
                                         f"ACK-bucket shares {[round(x, 3) for x in f[:4]]}")],
                   note=f"model: TCP ACK-sized packets sit at the {mode}-mode size ({round(100 * p[j])}% model "
                        "confidence). Exploratory (EXP-14 addendum A); assumes an AEAD cipher and TCP traffic.")
