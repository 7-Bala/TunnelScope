"""Local on-device AI rephrase layer using Apple Silicon MLX (DEC-031).

A model may reword an already-computed fact, never originate one.
Off by default, runs 100% locally on-device, fail-closed.
"""
from __future__ import annotations

import logging
import platform
import re
import sys
import threading
from typing import Any

logger = logging.getLogger("tunnelscope.rephrase")

MODEL_ID = "openbmb/MiniCPM5-2B-MLX"
FALLBACK_MODEL_ID = "unsloth/gemma-4-E4B-it-UD-MLX-4bit"

# Closed list of cipher/algorithm/protocol tokens collected from tunnelscope/rules/*.yaml
CIPHER_ALGORITHM_TOKENS = {
    # Protocols and versions
    "IKEv1",
    "IKEv2",
    "ESP",
    "AH",
    # Encryption ciphers
    "AES",
    "AES-GCM",
    "AES-CBC",
    "AES-CBC-256",
    "ChaCha20",
    "3DES",
    "3DES-CBC",
    "3DES-CBC+HMAC-SHA1-96",
    # Integrity / hash algorithms
    "HMAC-MD5-96",
    "HMAC-SHA1-96",
    "HMAC-SHA2-256",
    "HMAC-SHA2-256-128",
    "HMAC-SHA2-384-192",
    "HMAC-SHA2-512-256",
    "AES-XCBC-96",
    "SHA-1",
    "SHA-2",
    "SHA-384",
    "SHA-512",
    "SHA2-384",
    "MD5",
    "XCBC",
    # Key exchange & DH groups
    "Diffie-Hellman",
    "MODP-768",
    "MODP-1024",
    "MODP-1536",
    "MODP-2048",
    "MODP-3072",
    "MODP-4096",
    "MODP-6144",
    "MODP-8192",
    "MODP-1024-S160",
    "MODP-2048-S224",
    "MODP-2048-S256",
    "ECP-256",
    "ECP-384",
    "ECP-521",
    "Curve25519",
    "Curve448",
    # Post-quantum
    "ML-KEM",
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
}

_RULE_ID_REGEX = re.compile(
    r"(?<![\w-])(?:V-\d+|RFC\d+(?:-[A-Z0-9]+)+|CVE-\d+-\d+|DST-PQ(?:-[A-Z0-9]+)+)(?![\w-])"
)
_ALGO_REGEX = re.compile(
    r"(?<![\w-])(?:"
    + "|".join(re.escape(t) for t in sorted(CIPHER_ALGORITHM_TOKENS, key=len, reverse=True))
    + r")(?![\w-])"
)
_NUMBER_REGEX = re.compile(r"\d+(?:\.\d+)?")

_MODEL_CACHE: dict[str, Any] = {}


def available() -> bool:
    """True only if Apple Silicon macOS and mlx_lm imports cleanly."""
    if sys.platform != "darwin" or platform.machine() != "arm64":
        return False
    try:
        import mlx_lm  # noqa: F401
        return True
    except Exception:
        return False


def _facts(text: str) -> set[str]:
    """Extract rule IDs, numbers, and known cipher/algorithm tokens."""
    facts: set[str] = set()
    if not text:
        return facts
    for m in _RULE_ID_REGEX.finditer(text):
        facts.add(m.group(0))
    for m in _ALGO_REGEX.finditer(text):
        facts.add(m.group(0))
    for m in _NUMBER_REGEX.finditer(text):
        facts.add(m.group(0))
    return facts


def guardrail_facts_match(original: str, candidate: str) -> bool:
    """Guardrail 2: returns True iff candidate has the EXACT same facts as original."""
    return _facts(original) == _facts(candidate)


def _get_model(model_id: str = MODEL_ID) -> tuple[Any, Any]:
    """Lazy model loader cached at module level."""
    if model_id not in _MODEL_CACHE:
        import mlx_lm
        _MODEL_CACHE[model_id] = mlx_lm.load(model_id)
    return _MODEL_CACHE[model_id]


def rephrase(text: str, timeout_s: float = 3.0) -> str | None:
    """Rephrase text using local MLX model under strict Guardrail 2 fact check.

    Fail closed: returns None on any error, timeout, platform absence, or fact mismatch.
    Never raises.
    """
    if not available() or not text or not text.strip():
        return None

    try:
        model, tokenizer = _get_model(MODEL_ID)
    except Exception as e:
        logger.debug("Failed to load MLX model: %s", e)
        return None

    content = (
        "Reword the following text into clear, natural prose. "
        "Preserve all rule IDs, numbers, and algorithm names exactly as written. "
        "Do not add any facts. Return ONLY the reworded text with no preamble and no markdown formatting:\n\n"
        f"{text}"
    )

    if hasattr(tokenizer, "apply_chat_template") and getattr(tokenizer, "chat_template", None):
        messages = [{"role": "user", "content": content}]
        try:
            prompt = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True, enable_thinking=False
            )
        except TypeError:
            prompt = tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
    else:
        prompt = (
            "Reword the following text into clear, natural prose. "
            "Preserve all rule IDs, numbers, and algorithm names exactly as written. "
            "Do not add any facts. Return ONLY the reworded text with no preamble and no markdown formatting:\n\n"
            f"Original: {text}\n\nReworded:"
        )

    res_box: list[str] = []

    def _worker():
        try:
            import mlx_lm
            gen = mlx_lm.generate(
                model,
                tokenizer,
                prompt=prompt,
                max_tokens=160,
                verbose=False,
            )
            res_box.append(gen)
        except Exception as e:
            logger.debug("Generation failed: %s", e)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout_s)

    if not res_box or t.is_alive():
        logger.debug("Generation timed out or produced no output")
        return None

    candidate = res_box[0].strip()
    if "</think>" in candidate:
        candidate = candidate.split("</think>")[-1].strip()
    elif "<think>" in candidate:
        candidate = candidate.split("<think>")[0].strip()

    if candidate.startswith("```") and candidate.endswith("```"):
        candidate = candidate.strip("`").strip()
    if candidate.startswith('"') and candidate.endswith('"'):
        candidate = candidate[1:-1].strip()
    if candidate.lower().startswith("reworded:"):
        candidate = candidate[9:].strip()

    # Guardrail 2: discard if facts do not match exactly
    if not guardrail_facts_match(text, candidate):
        logger.debug("Rephrase discarded: fact-set mismatch")
        return None

    return candidate
