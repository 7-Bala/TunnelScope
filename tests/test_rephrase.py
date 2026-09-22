"""Tests for local on-device MLX rephrase layer (DEC-031, T-093)."""
import json
import os
import threading
import time
import pytest

from tunnelscope.rephrase.rephrase import (
    MODEL_ID,
    FALLBACK_MODEL_ID,
    available,
    guardrail_facts_match,
    rephrase,
    _facts,
    _fact_tokens,
    _clean_candidate,
    _GEN_LOCK,
)
from tunnelscope.explain.explain import explain_sa, as_text
from tunnelscope.report.report import analyze
from tunnelscope.api.server import analysis_json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures")


def test_available_returns_bool_without_raising():
    """6.a: available() returns a bool without raising on any platform."""
    res = available()
    assert isinstance(res, bool)


def test_rephrase_returns_none_when_unavailable(monkeypatch):
    """6.b: rephrase() returns None when available() is False (fail-closed proof for Linux CI)."""
    monkeypatch.setattr("tunnelscope.rephrase.rephrase.available", lambda: False)
    assert rephrase("Some test explanation text") is None


def test_fact_extractor_identifies_rule_number_and_cipher():
    """6.c: Fact extractor finds rule ID, number, and cipher token."""
    text = "V-207193 (high): Diffie-Hellman group 16 using AES-GCM cipher."
    facts = _facts(text)
    assert "V-207193" in facts
    assert "16" in facts
    assert "AES-GCM" in facts
    assert "Diffie-Hellman" in facts


def test_fact_extractor_exact_token_count():
    """6.c: Fact extractor finds exactly three facts on a 3-fact input, with no spurious digit splits."""
    text = "Rule V-207193 failed: group 16 is below requirements. Seen MODP-1024."
    facts = _facts(text)
    assert facts == {"V-207193", "16", "MODP-1024"}
    assert len(facts) == 3


def test_guardrail_discard_on_fact_mismatch():
    """6.d: Guardrail 2 directly discards candidates with fact-set mismatches."""
    original = "V-207193 (high): group 16 with AES-GCM. Why it matters: weak. What to do: configure ECP-384."

    # 1. Mismatch: modified number (16 -> 14)
    cand_num = "V-207193 (high): group 14 with AES-GCM. Why it matters: weak. What to do: configure ECP-384."
    assert not guardrail_facts_match(original, cand_num)

    # 2. Mismatch: omitted rule ID
    cand_no_rule = "Group 16 with AES-GCM. Why it matters: weak. What to do: configure ECP-384."
    assert not guardrail_facts_match(original, cand_no_rule)

    # 3. Mismatch: invented/added algorithm token (3DES added)
    cand_add_algo = "V-207193 (high): group 16 with AES-GCM and 3DES. Why it matters: weak. What to do: configure ECP-384."
    assert not guardrail_facts_match(original, cand_add_algo)

    # 4. Mismatch: removed algorithm token (ECP-384 omitted)
    cand_drop_algo = "V-207193 (high): group 16 with AES-GCM. Why it matters: weak. What to do: configure."
    assert not guardrail_facts_match(original, cand_drop_algo)

    # 5. Matching facts with reworded phrasing returns True
    cand_ok = "Under rule V-207193 (high), group 16 was negotiated using AES-GCM; recommend moving to ECP-384."
    assert guardrail_facts_match(original, cand_ok)


def test_guardrail_rejects_hallucinated_digits():
    """Guardrail 2: rejects hallucinated digits matching internal substrings of identifiers."""
    orig = "Confidence: 99.5% with ChaCha20."
    cand = "Confidence: 99.5% with ChaCha20 and 20 dropped packets."
    assert not guardrail_facts_match(orig, cand)

    orig_cipher = "V-207193 (high): key exchange uses MODP-1024"
    cand_cipher = "Under rule V-207193 (high), key exchange uses MODP-1024 across 1024 dropped packets"
    assert not guardrail_facts_match(orig_cipher, cand_cipher)


def test_guardrail_rejects_ip_truncation():
    """Guardrail 2: rejects candidates that truncate or corrupt IP addresses."""
    orig_ip = "This tunnel between 192.168.1.1 and 192.168.1.2 was checked"
    cand_ip = "This tunnel between 192.168.1.1 and 1.2 was checked"
    assert not guardrail_facts_match(orig_ip, cand_ip)


def test_guardrail_rejects_count_shift():
    """Guardrail 2: rejects candidates that alter token frequencies (multiset mismatch)."""
    orig_cnt = "This tunnel was checked against 12 rules: 6 passed, 6 failed."
    cand_cnt = "This tunnel was checked against 12 rules: 6 passed, 12 failed."
    assert not guardrail_facts_match(orig_cnt, cand_cnt)


def test_clean_candidate_preambles_and_quotes():
    """Verify cleaning of conversational preambles, fences, thinking tags, and quotes."""
    c1 = _clean_candidate('Reworded: "The tunnel between 10.20.1.10 and 10.20.2.10 was checked."')
    assert c1 == "The tunnel between 10.20.1.10 and 10.20.2.10 was checked."

    c2 = _clean_candidate('Here is the revised text: Sure! "The tunnel was checked."')
    assert c2 == "The tunnel was checked."

    c3 = _clean_candidate('```markdown\nThe tunnel was checked.\n```')
    assert c3 == "The tunnel was checked."

    c4 = _clean_candidate('<think>reasoning...</think> The tunnel was checked.')
    assert c4 == "The tunnel was checked."


def test_baseline_byte_identical_with_flag_off(monkeypatch):
    """6.e: With flag off, explain_sa() JSON output is byte-identical to pre-task baseline."""
    monkeypatch.delenv("TUNNELSCOPE_LOCAL_LLM", raising=False)
    pcap = os.path.join(CAP, "cloud", "c-w.pcap")
    a = analyze(pcap)
    sa = analysis_json(a, "c-w.pcap")["sas"][0]
    out = explain_sa(sa, local_llm=False)
    out_json = json.dumps(out, indent=2)

    expected = {
        "summary": "This tunnel between 10.20.1.10 and 10.20.2.10 was checked against 12 rules: 6 passed, 5 failed, 2 of them high severity, and the rest could not be judged from this capture. Post-quantum posture: classical (quantum-vulnerable key exchange).",
        "points": [
            {
                "kind": "fail",
                "rule_id": "RFC8247-DH-MUST",
                "severity": "high",
                "text": "RFC8247-DH-MUST (high): the tunnel agreed on a key-exchange group that the IPsec standard (RFC 8247) says must not or should not be used (seen: MODP-1024). Why it matters: these groups are too weak today. What to do: remove that group from both ends and use MODP-2048 or stronger, or an elliptic-curve group."
            },
            {
                "kind": "fail",
                "rule_id": "V-207193",
                "severity": "high",
                "text": "V-207193 (high): the key exchange uses a Diffie-Hellman group below what the US DoD requires (group 16 or higher) (seen: MODP-1024). Why it matters: a weaker key exchange is easier for a well-funded attacker to break later. What to do: configure a stronger group, such as ECP-384 or MODP-4096."
            },
            {
                "kind": "fail",
                "rule_id": "RFC8247-DH-OFFER",
                "severity": "medium",
                "text": "RFC8247-DH-OFFER (medium): one side still OFFERS key-exchange groups that RFC 8247 forbids, even if this tunnel did not pick one (seen: MODP-1024). Why it matters: any peer (or an attacker in the middle) that asks for the weak group can get it. What to do: delete the weak groups from that endpoint's proposal list."
            },
            {
                "kind": "fail",
                "rule_id": "V-207223",
                "severity": "medium",
                "text": "V-207223 (medium): the handshake's integrity check is weaker than SHA-384 (seen: HMAC-SHA1-96). Why it matters: the integrity check is what stops tampering with the handshake. What to do: use a SHA-384 or SHA-512 based integrity setting."
            },
            {
                "kind": "fail",
                "rule_id": "DST-PQ-KE",
                "severity": "informational",
                "text": "DST-PQ-KE (informational): the key exchange is classical only, with no post-quantum part (seen: classical-only). Why it matters: traffic recorded today could be decrypted later by a large quantum computer. What to do: plan a move to a hybrid post-quantum key exchange (ML-KEM added to the classical one)."
            }
        ],
        "unseen": [
            "pfs cannot be seen from a passive capture at all (it needs endpoint data)",
            "rekey cadence cannot be seen from a passive capture at all (it needs endpoint data)",
            "mode could not be determined from this capture",
            "peer auth method cannot be seen from a passive capture at all (it needs endpoint data)",
            "attacker exposure could not be determined from this capture",
            "traffic type could not be determined from this capture"
        ],
        "source": "template"
    }

    expected_json = json.dumps(expected, indent=2)
    assert out_json == expected_json
    assert "summary_rephrased" not in out
    for pt in out["points"]:
        assert "text_rephrased" not in pt


def test_model_constants():
    """Verify published official model ID and fallback model ID."""
    assert MODEL_ID == "openbmb/MiniCPM5-2B-MLX"
    assert FALLBACK_MODEL_ID == "unsloth/gemma-4-E4B-it-UD-MLX-4bit"


def test_guardrail_rejects_empty_and_none():
    """Guardrail 2: must reject empty strings or None candidates even if original has no facts."""
    assert not guardrail_facts_match("No rule failed.", "")
    assert not guardrail_facts_match("No rule failed.", None)
    assert not guardrail_facts_match("", "No rule failed.")
    assert not guardrail_facts_match(None, "No rule failed.")
    assert not guardrail_facts_match("", "")
    assert not guardrail_facts_match(None, None)


def test_rephrase_empty_or_invalid_input_returns_none():
    """Rephrase fail-closed on empty, whitespace, or invalid types."""
    assert rephrase("") is None
    assert rephrase("   \n\t  ") is None
    assert rephrase(None) is None
    assert rephrase(123) is None


def test_rephrase_timeout_fails_closed(monkeypatch):
    """Rephrase fail-closed on timeout (returns None without raising)."""
    def _slow_generate(*args, **kwargs):
        time.sleep(0.5)
        return "reworded"

    monkeypatch.setattr("tunnelscope.rephrase.rephrase._get_model", lambda: ("model", "tok"))
    monkeypatch.setattr("mlx_lm.generate", _slow_generate)
    assert rephrase("Some text to rephrase", timeout_s=0.05) is None


def test_rephrase_exception_fails_closed(monkeypatch):
    """Rephrase fail-closed on model load or generation exceptions (never raises)."""
    monkeypatch.setattr("tunnelscope.rephrase.rephrase._get_model", lambda: (_ for _ in ()).throw(RuntimeError("OOM")))
    assert rephrase("Some text to rephrase") is None


def test_rephrase_lock_serializes_concurrent_requests(monkeypatch):
    """Rephrase fail-closed when generation lock is held by another worker."""
    monkeypatch.setattr("tunnelscope.rephrase.rephrase._get_model", lambda: ("model", "tok"))
    monkeypatch.setattr("mlx_lm.generate", lambda *args, **kwargs: "reworded")

    # Manually hold lock to simulate busy generation queue
    _GEN_LOCK.acquire()
    try:
        assert rephrase("Some text to rephrase", timeout_s=0.01) is None
    finally:
        _GEN_LOCK.release()


def test_env_var_strict_boolean_parsing(monkeypatch):
    """TUNNELSCOPE_LOCAL_LLM must strictly parse 1/true/yes, rejecting 0/false/empty."""
    pcap = os.path.join(CAP, "cloud", "c-w.pcap")
    a = analyze(pcap)
    sa = analysis_json(a, "c-w.pcap")["sas"][0]

    # Explicit False must override ambient env var
    monkeypatch.setenv("TUNNELSCOPE_LOCAL_LLM", "1")
    out_disabled = explain_sa(sa, local_llm=False)
    assert "summary_rephrased" not in out_disabled

    # '0' and 'false' must NOT enable local LLM
    monkeypatch.setenv("TUNNELSCOPE_LOCAL_LLM", "0")
    out_zero = explain_sa(sa)
    assert "summary_rephrased" not in out_zero

    monkeypatch.setenv("TUNNELSCOPE_LOCAL_LLM", "false")
    out_false = explain_sa(sa)
    assert "summary_rephrased" not in out_false


def test_fact_extractor_handles_cve_dst_and_decimals():
    """Fact extractor captures CVE IDs, DST-PQ IDs, decimals, and various ciphers."""
    text = (
        "CVE-2026-78135 (high): early child SA. Also DST-PQ-DOWNGRADE fallback. "
        "Confidence: 99.5% with ChaCha20 and Curve25519."
    )
    facts = _facts(text)
    assert "CVE-2026-78135" in facts
    assert "DST-PQ-DOWNGRADE" in facts
    assert "99.5" in facts
    assert "ChaCha20" in facts
    assert "Curve25519" in facts


def test_rephrase_module_exports():
    """Verify tunnelscope.rephrase.rephrase exports expected public interface."""
    import tunnelscope.rephrase.rephrase as rp
    assert rp.MODEL_ID == MODEL_ID
    assert rp.FALLBACK_MODEL_ID == FALLBACK_MODEL_ID
    assert callable(rp.available)
    assert callable(rp.rephrase)
    assert callable(rp.guardrail_facts_match)
    assert callable(rp._facts)
