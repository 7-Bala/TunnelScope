"""Plain names for evidence attributes (T-083, W10). One place, used by the
reports and sent to the dashboard, so "which cipher is this?" has one answer:
the IKE SA (handshake) suite is read exactly; the ESP (data) cipher is only
narrowed to a candidate set, because it is negotiated inside the encrypted
IKE_AUTH."""
LABELS = {
    "ike_version": "IKE version",
    "ike_exchanges": "IKE exchanges seen",
    "ike_spi": "IKE SA SPIs",
    "ike_prf": "Handshake (IKE SA) PRF",
    "ike_encr": "Handshake (IKE SA) encryption",
    "ike_integ": "Handshake (IKE SA) integrity",
    "ike_dh_group": "Handshake key-exchange group",
    "ike_offered_dh": "Key-exchange groups offered",
    "pq_key_exchange": "Post-quantum key exchange",
    "ipsec_protocols": "IPsec protocol(s)",
    "esp_cipher_family": "Data (ESP) cipher: candidates",
    "ah_integrity": "Data (AH) integrity",
    "mode": "Tunnel / transport mode",
    "sequence_integrity": "Sequence numbers (replay)",
    "pfs": "Perfect forward secrecy",
    "rekey_cadence": "Rekey interval (key lifetime)",
    "peer_auth_method": "Peer authentication method",
    "responder_cert_capability": "Responder certificate capability",
    "negotiation_outcome": "Negotiation outcome",
    "early_childsa_cve": "CVE-2026-78135 pattern",
    "metadata_exposure": "Metadata exposure (bits)",
    "attacker_exposure": "Attacker exposure (Random Forest)",
    "traffic_type": "Traffic type inside the tunnel",
}


def label(attr: str) -> str:
    return LABELS.get(attr, attr.replace("_", " "))
