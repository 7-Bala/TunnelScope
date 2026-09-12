"""Stage-3 C5 — cross-tier consistency. Verifies the three reconciliation
outcomes against synthetic records, plus the two directions of trust:
T2 escalates / confirms passive findings, and flags CONTRADICTORY when the
endpoint's own report diverges from the wire (the NOTES #13 IP-TFS case).
"""
from tunnelscope.crosstier.crosstier import apply_telemetry
from tunnelscope.evidence.record import EvidenceRecord, Finding, Status, Vantage


def _rec(findings):
    r = EvidenceRecord(ike_spi_i="aa", src="10.0.0.1", dst="10.0.0.2", source_pcap="unit")
    r._ike = [{"exchange": 34, "message_id": 0}]
    for f in findings:
        r.findings[f.attribute] = f
    return r


def test_mode_escalation_resolves_not_observable():
    r = _rec([Finding("mode", Status.NOT_OBSERVABLE, Vantage.T0, "EXP-08")])
    checks = apply_telemetry(r, {"mode": "tunnel"})
    assert r.findings["mode"].status == Status.OBSERVED
    assert r.findings["mode"].value == "tunnel"
    assert r.findings["mode"].vantage == Vantage.T2
    assert checks[0].outcome == "escalation"


def test_dh_confirmation_keeps_passive_finding():
    r = _rec([Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "reuse", value="MODP-2048")])
    checks = apply_telemetry(r, {"ike_dh_group": "MODP-2048"})
    assert r.findings["ike_dh_group"].value == "MODP-2048"
    assert "confirmed by T2" in r.findings["ike_dh_group"].note
    assert checks[0].outcome == "confirmation"


def test_dh_contradiction():
    r = _rec([Finding("ike_dh_group", Status.OBSERVED, Vantage.T1, "reuse", value="MODP-2048")])
    apply_telemetry(r, {"ike_dh_group": "ECP-256"})
    assert r.findings["ike_dh_group"].status == Status.CONTRADICTORY
    assert r.findings["ike_dh_group"].value is None


def test_downgrade_terms_are_consistent_not_conflicting():
    r = _rec([Finding("pq_key_exchange", Status.INFERRED, Vantage.T1, "EXP-04",
                      value="offered-but-not-used", confidence=0.9)])
    checks = apply_telemetry(r, {"pq_key_exchange": "classical-only"})
    assert checks[0].outcome == "confirmation"  # both mean "no PQ installed"
    assert r.findings["pq_key_exchange"].status == Status.INFERRED


def test_pq_true_contradiction_when_endpoint_installed_pq():
    r = _rec([Finding("pq_key_exchange", Status.INFERRED, Vantage.T1, "EXP-04",
                      value="offered-but-not-used", confidence=0.9)])
    apply_telemetry(r, {"pq_key_exchange": "ML-KEM-768"})
    assert r.findings["pq_key_exchange"].status == Status.CONTRADICTORY


def test_esp_cipher_family_refinement():
    r = _rec([Finding("esp_cipher_family", Status.INFERRED, Vantage.T0, "EXP-01",
                      value=["AES-CBC+HMAC-SHA256-128", "AES-CTR+HMAC-SHA256-128"], confidence=0.8)])
    checks = apply_telemetry(r, {"esp_cipher": "AES-CBC-256"})
    assert r.findings["esp_cipher"].status == Status.OBSERVED  # CBC family matches
    assert checks[0].outcome == "confirmation"


def test_esp_cipher_conflict_when_family_excluded():
    r = _rec([Finding("esp_cipher_family", Status.INFERRED, Vantage.T0, "EXP-01",
                      value=["AES-GCM-16", "ChaCha20-Poly1305"], confidence=0.8)])  # AEAD only, CBC excluded
    apply_telemetry(r, {"esp_cipher": "AES-CBC-256"})
    assert r.findings["esp_cipher"].status == Status.CONTRADICTORY


def test_tfc_notes13_contradiction():
    r = _rec([Finding("metadata_exposure", Status.MEASURED, Vantage.T0, "EXP-05",
                      value={"size_bits": 3.1, "timing_bits": 1.5, "tfc_padding_active": False})])
    checks = apply_telemetry(r, {"tfc_padding_active": True})  # configured but not applied
    assert r.findings["tfc_padding_active"].status == Status.CONTRADICTORY
    assert checks[0].outcome == "contradiction"
