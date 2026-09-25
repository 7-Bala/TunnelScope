"""Optional cloud drafting backend: Google Gemini (DEC-038, owner override of DEC-031/DEC-035's
offline-only rule, 2026-09-25).

This file exists ONLY to draft a candidate remediation edit for tunnelscope/remediate/generate.py.
It decides nothing: every draft this returns is re-validated from scratch by the same V1-V8 checks,
sandboxed dry run, clone-load check, baseline capture, snapshot+watchdog and rollback that already
gate the local model (DEC-033/034) — a Gemini draft that fails any of those is refused exactly like
a local-model draft that fails them. This module is never imported by anything that produces a
finding, verdict, score or applied command; `tests/test_ai_layer.py` enforces both of those with a
scoped exception (this one file may mention a cloud provider; nothing else may, and no
finding/verdict/risk/anomaly module may import this one).

Off by default, and off unless BOTH:
  - TUNNELSCOPE_GEMINI_API_KEY is set (never hold this key in a committed file; see .env.example);
  - the operator has set TUNNELSCOPE_GENERATOR_BACKEND=gemini (generate.py's `backend` argument
    is never set from an untrusted client request; only from this server-side setting).

What a call sends to Google's servers: the failing rule's id/title/assertion (public text, from
tunnelscope/rules/*.yaml), the CURRENT value of the fixed lab connection's (`t-tun`) proposal/
version lines, and the vocabulary of strongSwan keywords the lab image accepts. The pre-shared key
and any traffic content are never part of the prompt. This backend is reachable only through the
generator's existing scope (DEC-034 D-D: the lab-only `t-tun` connection, never a real capture or a
real gateway) — nothing about a real analysed capture is ever sent here.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any

MODEL_ID = os.environ.get("TUNNELSCOPE_GEMINI_MODEL", "gemini-3.1-pro-preview")
API_KEY_ENV = "TUNNELSCOPE_GEMINI_API_KEY"
DEFAULT_TIMEOUT_S = 30.0

_CLIENT_LOCK = threading.Lock()
_client_cache: list[Any] = []


def available() -> bool:
    """Whether a call can be attempted: the API key is set and the SDK is importable. Never
    downloads or imports anything on its own initiative — both checks are read-only."""
    if not os.environ.get(API_KEY_ENV):
        return False
    try:
        import google.genai  # noqa: F401
    except ImportError:
        return False
    return True


def _client():
    with _CLIENT_LOCK:
        if not _client_cache:
            from google import genai
            _client_cache.append(genai.Client(api_key=os.environ[API_KEY_ENV]))
        return _client_cache[0]


def reset_client_cache() -> None:
    """Test-only: drop the cached client so a new API key or a fake SDK takes effect."""
    with _CLIENT_LOCK:
        _client_cache.clear()


def generate_json(system: str, data_blocks: dict[str, str], max_tokens: int = 256,
                  timeout_s: float = DEFAULT_TIMEOUT_S, temperature: float = 0.0,
                  seed: int | None = None) -> tuple[str | None, dict[str, Any]]:
    """Same contract as tunnelscope.rephrase.runtime.generate_json: (raw text or None, metadata).
    Never raises. `timeout_s` bounds only this call (the SDK's own per-request timeout); the
    caller's overall time budget (generate.py) is enforced by not calling again once it is spent."""
    from ..rephrase.runtime import build_prompt
    content = build_prompt(system, data_blocks)
    meta: dict[str, Any] = {"model_id": MODEL_ID, "model_revision": None, "backend": "gemini",
                            "prompt_sha256": hashlib.sha256(content.encode()).hexdigest(),
                            "temperature": temperature, "seed": seed, "latency_s": None, "reason": None}
    if not os.environ.get(API_KEY_ENV):
        meta["reason"] = f"no Gemini API key set ({API_KEY_ENV})"
        return None, meta
    try:
        import google.genai  # noqa: F401
    except ImportError:
        meta["reason"] = "the google-genai package is not installed (pip install google-genai)"
        return None, meta

    t0 = time.monotonic()
    try:
        from google.genai import errors, types
    except Exception as e:
        meta["reason"] = f"the google-genai package could not be loaded: {type(e).__name__}"
        return None, meta
    try:
        client = _client()
        cfg_kwargs: dict[str, Any] = {"response_mime_type": "application/json",
                                      "max_output_tokens": max_tokens, "temperature": temperature,
                                      "http_options": types.HttpOptions(timeout=int(timeout_s * 1000))}
        if seed is not None:
            cfg_kwargs["seed"] = seed
        response = client.models.generate_content(model=MODEL_ID, contents=content,
                                                   config=types.GenerateContentConfig(**cfg_kwargs))
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        text = getattr(response, "text", None)
        if not text:
            meta["reason"] = "the model produced no output"
            return None, meta
        return text, meta
    except errors.APIError as e:
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        code = getattr(e, "code", None)
        if code == 429:
            meta["reason"] = "rate limit or quota exceeded"
        elif code in (401, 403):
            meta["reason"] = f"authentication failed (check {API_KEY_ENV})"
        else:
            meta["reason"] = f"API error (HTTP {code}): {getattr(e, 'message', None) or type(e).__name__}"
        return None, meta
    except Exception as e:
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        meta["reason"] = f"unexpected error: {type(e).__name__}"
        return None, meta
