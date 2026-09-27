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

# algorithm -> (primitive, quantum-vulnerable?, note). Primitives are CycloneDX 1.6's own enum values
# (Diffie-Hellman and ECDH are "key-agree"); the official schema rejects anything else (T-124).
_ALGO = {
    "MODP-2048": ("key-agree", True, "classical Diffie-Hellman; Shor-breakable"),
    "MODP-3072": ("key-agree", True, "classical Diffie-Hellman; Shor-breakable"),
    "MODP-4096": ("key-agree", True, "classical Diffie-Hellman; Shor-breakable"),
    "ECP-256": ("key-agree", True, "classical ECDH; Shor-breakable"),
    "ECP-384": ("key-agree", True, "classical ECDH; Shor-breakable"),
    "ML-KEM-512": ("kem", False, "NIST FIPS 203, quantum-safe (security level 1)"),
    "ML-KEM-768": ("kem", False, "NIST FIPS 203, quantum-safe (security level 3)"),
    "ML-KEM-1024": ("kem", False, "NIST FIPS 203, quantum-safe (security level 5)"),
    "AES-GCM-16": ("ae", False, "AEAD; Grover-reduced, adequate at >=256-bit"),
    "AES-CBC": ("block-cipher", False, "needs separate MAC; adequate at >=256-bit"),
    "ChaCha20-Poly1305": ("ae", False, "AEAD stream cipher"),
    "HMAC-SHA2-256-128": ("mac", False, "SHA-2 family MAC"),
}

# NIST PQC security categories (CycloneDX `nistQuantumSecurityLevel`) where they are DEFINED: FIPS 203 gives
# ML-KEM-512/768/1024 categories 1/3/5, and the categories themselves are defined by AES-128/192/256 key
# search. Anything else (ChaCha20, HMAC) has no NIST category, so the field is left out, never guessed.
_ML_KEM_LEVEL = {"ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}
_AES_LEVEL = {"128": 1, "192": 3, "256": 5}


def _quantum_level(name: str, quantum_vulnerable) -> int | None:
    if quantum_vulnerable:
        return 0                                   # 0 = none of the categories is met (schema text)
    if name in _ML_KEM_LEVEL:
        return _ML_KEM_LEVEL[name]
    if name.startswith("AES-") and name[-3:] in _AES_LEVEL:
        return _AES_LEVEL[name[-3:]]
    return None


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
    # Nothing seen yet means nothing is known (DEC-008): the posture is only "classical" when the
    # handshake showed a classical-only key exchange, or when the protocol itself has no PQ option.
    qs_posture = "unknown (key exchange not observed)"

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
        level = _quantum_level(f.value, qvuln)
        if level is not None:
            extra["nistQuantumSecurityLevel"] = level
        comps.append(_asset(f.value, prim, extra) | {"_quantum_vulnerable": qvuln, "_note": note, "_attr": attr})

    pq = rec.findings.get("pq_key_exchange")
    if pq and isinstance(pq.value, list):
        for kem in pq.value:
            prim, qvuln, note = _ALGO.get(kem, ("kem", False, ""))
            level = _quantum_level(kem, False)
            comps.append(_asset(kem, prim, {} if level is None else {"nistQuantumSecurityLevel": level}) |
                         {"_quantum_vulnerable": False, "_note": note, "_attr": "pq_key_exchange"})
        qs_posture = "post-quantum (hybrid)"
    elif pq and pq.value == "offered-but-not-used":
        qs_posture = "DOWNGRADED (PQ offered, classical used)"
        gaps.append({"attribute": "pq_key_exchange", "status": "downgrade",
                     "note": "post-quantum key exchange offered but not used"})
    elif pq and pq.value == "classical-only":
        qs_posture = "classical (quantum-vulnerable key exchange)"
    elif ver and ver.status.value == "OBSERVED" and ver.value == "IKEv1":
        # IKEv1 has no post-quantum key exchange at all (RFC 9370 extends IKEv2 only), so classical
        # is certain from the version alone even when the key-exchange payload was not seen.
        qs_posture = "classical (IKEv1: no post-quantum key exchange exists)"

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


# IKEv2 transform types (RFC 7296 section 3.3.2; KE per RFC 9370) -> CycloneDX `ikev2TransformTypes` slot
_SLOT = {"ike_encr": "encr", "ike_integ": "integ", "ike_dh_group": "ke", "pq_key_exchange": "ke"}


def to_cyclonedx(records: list[EvidenceRecord], source: str = "") -> dict:
    """The exported CBOM: strictly valid CycloneDX 1.6 (checked against the official schema, T-124).

    Each algorithm seen is one `cryptographic-asset` with a `bom-ref`, listed once however many tunnels use
    it. Each tunnel is one protocol asset whose `ikev2TransformTypes` point at the algorithms it was SEEN
    to use; its posture and its gaps (what could not be seen) are `tunnelscope:` properties on it, so the
    gaps travel with the file and nothing unseen is listed as an asset (DEC-008). `build_cbom` keeps the
    internal shape the dashboard and reports read."""
    algos: dict[str, dict] = {}
    protocols = []
    for rec in records:
        if not getattr(rec, "_ike", []) and not getattr(rec, "_esp", []):
            continue
        comps, gaps, posture = record_to_components(rec)
        esp_only = getattr(rec, "_esp_only", False)
        if esp_only:
            posture = "unknown (ESP-only capture; IKE not observed - SA predates capture)"
        slots: dict[str, list] = {}
        version = None
        for c in comps:
            if c["cryptoProperties"]["assetType"] == "protocol":
                version = c["name"][-1]                        # "IKEv2" -> "2"
                continue
            ref = f"crypto/algorithm/{c['name']}"
            algos.setdefault(ref, {"bom-ref": ref} | {k: v for k, v in c.items() if not k.startswith("_")})
            slot = _SLOT.get(c.get("_attr"))
            if slot and ref not in slots.setdefault(slot, []):
                slots[slot].append(ref)
        proto: dict = {"type": "ipsec" if esp_only or version is None else "ike"}
        if version:
            proto["version"] = version
        if slots and version == "2":
            proto["ikev2TransformTypes"] = slots
        elif slots:
            proto["cryptoRefArray"] = [r for refs in slots.values() for r in refs]
        props = [{"name": "tunnelscope:quantum_posture", "value": posture},
                 {"name": "tunnelscope:src", "value": str(rec.src)},
                 {"name": "tunnelscope:dst", "value": str(rec.dst)}]
        props += [{"name": "tunnelscope:gap", "value": f"{g['attribute']}: {g['status']}" + (f" - {g['note']}" if g.get("note") else "")}
                  for g in gaps]
        protocols.append({"type": "cryptographic-asset", "bom-ref": f"crypto/protocol/sa/{rec.key()}",
                          "name": f"{'IKEv' + version if version else 'IPsec'} SA {rec.src} -> {rec.dst}",
                          "cryptoProperties": {"assetType": "protocol", "protocolProperties": proto},
                          "properties": props})
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "TunnelScope"}]},
                     "component": {"type": "file", "name": source.rsplit("/", 1)[-1] or "capture"},
                     "properties": [{"name": "tunnelscope:note",
                                     "value": "Cryptographic assets OBSERVED on the wire; each tunnel's tunnelscope:gap "
                                              "properties list what was not recoverable at this vantage (never overstated)."}]},
        "components": list(algos.values()) + protocols,
    }
