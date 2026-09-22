"""Local on-device AI rephrase layer using Apple Silicon MLX (DEC-031).

A model may reword an already-computed fact, never originate one.
Off by default, runs 100% locally on-device, fail-closed.
"""
from __future__ import annotations

from collections import Counter
import contextlib
import logging
import os
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
    "ENCR_3DES",
    # Integrity / hash algorithms
    "HMAC-MD5-96",
    "HMAC-SHA1-96",
    "HMAC-SHA2",
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
    r"(?<![\w-])(?:V-\d+|RFC\d+(?:-[A-Z0-9]+)+|CVE-\d+-\d+|DST-PQ(?:-[A-Z0-9]+)+|DPDP-R\d+-\d+[a-z]?|CERTIN-GE-\d+(?:\.\d+)*)(?![\w-])"
)
_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ALGO_REGEX = re.compile(
    r"(?<![\w-])(?:"
    + "|".join(re.escape(t) for t in sorted(CIPHER_ALGORITHM_TOKENS, key=len, reverse=True))
    + r")(?![\w-])"
)
_NUMBER_REGEX = re.compile(r"(?<![\w.-])\d+(?:\.\d+)?(?![\w.-])")

_MODEL_CACHE: dict[str, Any] = {}
_MODEL_LOCK = threading.Lock()
_GEN_LOCK = threading.Lock()


def available() -> bool:
    """True only if Apple Silicon macOS and mlx_lm imports cleanly."""
    if sys.platform != "darwin" or platform.machine() != "arm64":
        return False
    try:
        import mlx_lm  # noqa: F401
        return True
    except (ImportError, Exception):
        return False


def _fact_tokens(text: str) -> list[str]:
    """Extract ordered fact tokens: rule IDs, IP addresses, cipher/algo tokens, numbers."""
    if not text or not isinstance(text, str):
        return []
    tokens: list[str] = []
    occupied_spans: list[tuple[int, int]] = []

    # 1. Rule IDs
    for m in _RULE_ID_REGEX.finditer(text):
        tokens.append(m.group(0))
        occupied_spans.append((m.start(), m.end()))

    # 2. IP addresses (atomic entity extraction, per build/10-LOCAL-AI-RUNTIME.md)
    for m in _IP_REGEX.finditer(text):
        tokens.append(m.group(0))
        occupied_spans.append((m.start(), m.end()))

    # 3. Cipher / algorithm tokens from rules
    for m in _ALGO_REGEX.finditer(text):
        start, end = m.start(), m.end()
        if not any(s <= start and end <= e for s, e in occupied_spans):
            tokens.append(m.group(0))
            occupied_spans.append((start, end))

    # 4. Standalone numbers (outside rule IDs, IPs, and cipher spans)
    for m in _NUMBER_REGEX.finditer(text):
        start, end = m.start(), m.end()
        if not any(s <= start and end <= e for s, e in occupied_spans):
            tokens.append(m.group(0))

    return tokens


def _facts(text: str) -> set[str]:
    """Extract rule IDs, IP addresses, numbers, and cipher tokens as a set."""
    return set(_fact_tokens(text))


def guardrail_facts_match(original: str, candidate: str) -> bool:
    """Guardrail 2: returns True iff candidate has the EXACT same facts as original.

    Enforces both set equality and token occurrence frequency (multiset) equality.
    Rejects empty strings or non-string inputs.
    """
    if not original or not candidate or not isinstance(original, str) or not isinstance(candidate, str):
        return False
    orig_tokens = _fact_tokens(original)
    cand_tokens = _fact_tokens(candidate)
    return set(orig_tokens) == set(cand_tokens) and Counter(orig_tokens) == Counter(cand_tokens)


@contextlib.contextmanager
def _silence_io():
    """Suppress progress bars, download messages, and C-level writes during model loading."""
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    null_fd = None
    save_out = None
    save_err = None
    try:
        null_fd = os.open(os.devnull, os.O_WRONLY)
        save_out = os.dup(1)
        save_err = os.dup(2)
        sys.stdout.flush()
        sys.stderr.flush()
        os.dup2(null_fd, 1)
        os.dup2(null_fd, 2)
    except Exception:
        pass

    try:
        yield
    finally:
        if save_out is not None and save_err is not None:
            try:
                sys.stdout.flush()
                sys.stderr.flush()
                os.dup2(save_out, 1)
                os.dup2(save_err, 2)
            except Exception:
                pass
        for fd in (null_fd, save_out, save_err):
            if fd is not None:
                try:
                    os.close(fd)
                except Exception:
                    pass


def _clean_candidate(raw: str) -> str:
    """Clean raw generation output: strip think tags, markdown blocks, preambles, and quotes."""
    if not raw or not isinstance(raw, str):
        return ""
    candidate = raw.strip()

    if "</think>" in candidate:
        candidate = candidate.split("</think>")[-1].strip()
    elif "<think>" in candidate:
        candidate = candidate.split("<think>")[0].strip()

    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if len(lines) > 1 and lines[0].startswith("```"):
            candidate = "\n".join(lines[1:])
        else:
            candidate = candidate.lstrip("`").strip()
    if candidate.endswith("```"):
        lines = candidate.splitlines()
        if lines and lines[-1].strip() == "```":
            candidate = "\n".join(lines[:-1])
        else:
            candidate = candidate.rstrip("`").strip()

    preamble_re = re.compile(
        r"^(?:(?:here is (?:the|a) (?:revised|reworded|rephrased|rewritten) (?:text|version|sentence):?)"
        r"|(?:(?:sure|certainly|okay)[!,.]?\s*)"
        r"|(?:(?:reworded|rephrased|revised|rewritten|original|text|paraphrase):\s*)"
        r")",
        flags=re.IGNORECASE,
    )
    for _ in range(3):
        candidate = candidate.strip()
        candidate = preamble_re.sub("", candidate).strip()
        if (candidate.startswith('"') and candidate.endswith('"')) or (
            candidate.startswith("'") and candidate.endswith("'")
        ):
            candidate = candidate[1:-1].strip()

    return candidate


def _get_model(model_id: str = MODEL_ID) -> tuple[Any, Any]:
    """Lazy model loader cached at module level (thread-safe, silenced)."""
    with _MODEL_LOCK:
        if model_id not in _MODEL_CACHE:
            with _silence_io():
                import mlx_lm
                _MODEL_CACHE[model_id] = mlx_lm.load(model_id)
        return _MODEL_CACHE[model_id]


def rephrase(text: str, timeout_s: float = 3.0) -> str | None:
    """Rephrase text using local MLX model under strict Guardrail 2 fact check.

    Fail closed: returns None on any error, timeout, platform absence, or fact mismatch.
    Never raises.
    """
    if not available() or not text or not isinstance(text, str) or not text.strip():
        return None

    if not _GEN_LOCK.acquire(blocking=True, timeout=timeout_s):
        logger.debug("Rephrase discarded: generation lock busy / timed out")
        return None

    try:
        try:
            model, tokenizer = _get_model(MODEL_ID)
        except Exception as e:
            logger.debug("Failed to load MLX model: %s", e)
            return None

        content = (
            "Rewrite the following security text to improve flow and readability for a non-technical reader. "
            "Use different words and sentence phrasing. Keep all numbers as digits. "
            "Do not alter, omit, or add any numbers, rule IDs, or cipher/group names. "
            "Return ONLY the revised text with no introduction and no markdown formatting:\n\n"
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
                "Rewrite the following security text to improve flow and readability for a non-technical reader. "
                "Use different words and sentence phrasing. Keep all numbers as digits. "
                "Do not alter, omit, or add any numbers, rule IDs, or cipher/group names. "
                "Return ONLY the revised text with no introduction and no markdown formatting:\n\n"
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

        candidate = _clean_candidate(res_box[0])

        # Guardrail 2: discard if facts do not match exactly
        if not guardrail_facts_match(text, candidate):
            logger.debug("Rephrase discarded: fact-set mismatch")
            return None

        # If the candidate was repeated verbatim without any rewording, return None
        if candidate.strip() == text.strip():
            logger.debug("Rephrase discarded: verbatim repetition (unchanged)")
            return None

        return candidate
    except Exception as e:
        logger.debug("Unexpected error in rephrase: %s", e)
        return None
    finally:
        _GEN_LOCK.release()
