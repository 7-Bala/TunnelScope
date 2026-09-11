"""CBOM (Cryptographic Bill of Materials) export — CycloneDX 1.6 (PS §E, DST/NQM).

Catalogues, per observed Security Association, the cryptographic assets seen on
the wire: the IKE protocol, the IKE SA algorithms (ENCR/INTEG/DH), and the key
exchange (classical or post-quantum), each flagged for quantum vulnerability.
Only OBSERVED/INFERRED findings become assets; UNKNOWN/NOT_OBSERVABLE ones are
recorded as gaps, so the CBOM never overstates what was seen (DEC-008).

The DST/NQM task force defines a CBOM as "a detailed inventory of cryptographic
components and configurations ... algorithms, modes of operation, key sizes,
protocols ... covering both classical and quantum-safe cryptography."
"""
from __future__ import annotations

from ..evidence.record import EvidenceRecord, Status

# algorithm -> (primitive, quantum-vulnerable?, note)
_ALGO = {
    "MODP-2048": ("dh", True, "classical Diffie-Hellman; Shor-breakable"),
    "MODP-3072": ("dh", True, "classical Diffie-Hellman; Shor-breakable"),
    "MODP-4096": ("dh", True, "classical Diffie-Hellman; Shor-breakable"),
    "ECP-256": ("ecdh", True, "classical ECDH; Shor-breakable"),
    "ECP-384": ("ecdh", True, "classical ECDH; Shor-breakable"),
    "ML-KEM-512": ("kem", False, "NIST FIPS 203, quantum-safe (security level 1)"),
    "ML-KEM-768": ("kem", False, "NIST FIPS 203, quantum-safe (security level 3)"),
    "ML-KEM-1024": ("kem", False, "NIST FIPS 203, quantum-safe (security level 5)"),
    "AES-GCM-16": ("ae", False, "AEAD; Grover-reduced, adequate at >=256-bit"),
    "AES-CBC": ("block-cipher", False, "needs separate MAC; adequate at >=256-bit"),
    "ChaCha20-Poly1305": ("ae", False, "AEAD stream cipher"),
    "HMAC-SHA2-256-128": ("mac", False, "SHA-2 family MAC"),
}


def _asset(name, primitive, extra=None):
    c = {"type": "cryptographic-asset", "name": name,
         "cryptoProperties": {"assetType": "algorithm",
                              "algorithmProperties": {"primitive": primitive}}}
    if extra:
        c["cryptoProperties"]["algorithmProperties"].update(extra)
    return c


def record_to_components(rec: EvidenceRecord) -> tuple[list, list, str]:
    """Return (components, gaps, quantum_posture) for one SA."""
    comps, gaps = [], []
    qs_posture = "classical"

    ver = rec.findings.get("ike_version")
    if ver and ver.value:
        comps.append({"type": "cryptographic-asset",
                      "name": f"IKE{ver.value[-2:]}",
                      "cryptoProperties": {"assetType": "protocol",
                                           "protocolProperties": {"type": "ike"}}})

    for attr in ("ike_encr", "ike_integ", "ike_dh_group"):
        f = rec.findings.get(attr)
        if not f:
            continue
        if f.status in (Status.UNKNOWN, Status.NOT_OBSERVABLE):
            gaps.append({"attribute": attr, "status": f.status.value, "note": f.note}); continue
        base = f.value.rsplit("-", 1)[0] if attr == "ike_encr" and f.value[-3:].isdigit() else f.value
        prim, qvuln, note = _ALGO.get(base, ("unknown", None, ""))
        extra = {}
        if attr == "ike_encr" and f.value[-3:].isdigit():
            extra["parameterSetIdentifier"] = f.value.rsplit("-", 1)[1] + "-bit"
        if qvuln is not None:
            extra["nistQuantumSecurityLevel"] = 0 if qvuln else 3
        comps.append(_asset(f.value, prim, extra) | {"_quantum_vulnerable": qvuln, "_note": note})

    pq = rec.findings.get("pq_key_exchange")
    if pq and isinstance(pq.value, list):
        for kem in pq.value:
            prim, qvuln, note = _ALGO.get(kem, ("kem", False, ""))
            comps.append(_asset(kem, prim, {"nistQuantumSecurityLevel": 3}) |
                         {"_quantum_vulnerable": False, "_note": note})
        qs_posture = "post-quantum (hybrid)"
    elif pq and pq.value == "offered-but-not-used":
        qs_posture = "DOWNGRADED (PQ offered, classical used)"
        gaps.append({"attribute": "pq_key_exchange", "status": "downgrade",
                     "note": "post-quantum key exchange offered but not used"})
    elif pq and pq.value == "classical-only":
        qs_posture = "classical (quantum-vulnerable key exchange)"

    return comps, gaps, qs_posture


def build_cbom(records: list[EvidenceRecord], source: str = "") -> dict:
    sas = []
    all_comps = []
    for rec in records:
        if not getattr(rec, "_ike", []) and not getattr(rec, "_esp", []):
            continue
        comps, gaps, posture = record_to_components(rec)
        if getattr(rec, "_esp_only", False):
            posture = "unknown (ESP-only capture; IKE not observed - SA predates capture)"
        all_comps += comps
        sas.append({"sa": rec.key(), "src": rec.src, "dst": rec.dst,
                    "quantum_posture": posture,
                    "n_components": len(comps), "gaps": gaps})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "application", "name": "TunnelScope CBOM"},
                     "properties": [{"name": "tunnelscope:source", "value": source},
                                    {"name": "tunnelscope:note",
                                     "value": "Cryptographic assets OBSERVED on the wire; gaps list "
                                              "attributes not recoverable at this vantage (never overstated)."}]},
        "components": [{k: v for k, v in c.items() if not k.startswith("_")} for c in all_comps],
        "tunnelscope_sa_summary": sas,
    }
