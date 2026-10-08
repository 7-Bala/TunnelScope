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

Off by default, and off unless ALL of:
  - the network is not switched off (TUNNELSCOPE_NETWORK, DEC-040's single switch for everything that leaves the
    machine; on by default since DEC-045, an air-gapped install sets it off);
  - a Gemini API key is set (never in a committed file; see .env.example). TUNNELSCOPE_KEY_PURPOSE
    (e.g. `dev`, `demo`, `experiment`) picks TUNNELSCOPE_GEMINI_API_KEY_<PURPOSE> if set, else
    TUNNELSCOPE_GEMINI_API_KEY. Keys are separated by job, never rotated to get round a quota
    (Google APIs Terms 2(d); rate limits are per project);
  - the operator has chosen the cloud or chain backend (TUNNELSCOPE_GENERATOR_BACKEND; never set
    from an untrusted client request).

What a call sends to Google's servers: the failing rule's id/title/assertion (public text, from
tunnelscope/rules/*.yaml), the CURRENT value of the fixed lab connection's (`t-tun`) proposal/
version lines, and the vocabulary of strongSwan keywords the lab image accepts. The pre-shared key
and any traffic content are never part of the prompt. This backend is reachable only through the
generator's existing scope (DEC-034 D-D: the lab-only `t-tun` connection, never a real capture or a
real gateway) — nothing about a real analysed capture is ever sent here.

DEC-055 (owner, 2026-10-04) adds one more caller: tunnelscope/rephrase/api.py may ask this client to REWORD
explanation sentences. Those do describe a real analysed capture (rule ids, algorithm names, counts), with every IP
address replaced by a placeholder before sending; each reworded sentence is kept only if the fact check in
rephrase.py passes. Off unless the operator sets TUNNELSCOPE_REPHRASE_BACKEND=api.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any

from .. import net

# Measured 2026-09-25 against the project's own key: gemini-3.1-pro-preview (the top reasoning
# model) returned 429 "quota exceeded" on every call (this key's tier has none for it);
# gemini-3.8-flash answered normally and is Google's own description for this kind of task
# ("engineered for long-horizon software engineering, autonomous agents"). Override with
# TUNNELSCOPE_GEMINI_MODEL if a key with Pro-tier quota is used later.
# DEC-041 (EXP-18b, 2026-09-27): gemini-3.1-flash-lite confirmed 13/16 test fixes live (gemini-3.8-flash could not
# finish: its free daily quota ran out after 3/5 dev items). "Good, not the top model" (owner).
MODEL_ID = os.environ.get("TUNNELSCOPE_GEMINI_MODEL", "gemini-3.1-flash-lite")
PROVIDER = "gemini"
# The fallback chain (chain.py) tries these in order on a rate limit or overload; each model has its own limits.
# Measured 2026-09-27 on the owner's three keys: gemini-3.7-flash and gemini-3.1-flash-lite answered on all three
# (flash-lite in ~1.5 s); gemini-2.5-flash returns 404 "no longer available to new users" on two of them;
# gemini-3.5-flash works but took ~17 s. 503 "high demand" was common on 3.8/3.7-flash that day.
FALLBACK_MODELS = tuple(dict.fromkeys((MODEL_ID, "gemini-3.7-flash")))
# Gemini 3 models spend output tokens on internal reasoning first: with the generator's small budgets (~320
# tokens) and default reasoning, gemini-3.8-flash returned an EMPTY answer; with thinking_level "low" it answered
# in ~2 s (measured 2026-09-27). Override with TUNNELSCOPE_GEMINI_THINKING (e.g. "high"), or "" to leave default.
THINKING_LEVEL = os.environ.get("TUNNELSCOPE_GEMINI_THINKING", "low")
API_KEY_ENV = "TUNNELSCOPE_GEMINI_API_KEY"
DEFAULT_TIMEOUT_S = 30.0

_CLIENT_LOCK = threading.Lock()
_client_cache: list[Any] = []


def _api_key() -> tuple[str | None, str]:
    """(key, the env var it came from). TUNNELSCOPE_KEY_PURPOSE selects a per-job key."""
    purpose = os.environ.get("TUNNELSCOPE_KEY_PURPOSE", "").strip().upper()
    if purpose:
        name = f"{API_KEY_ENV}_{purpose}"
        if os.environ.get(name):
            return os.environ[name], name
    return os.environ.get(API_KEY_ENV), API_KEY_ENV


def available() -> bool:
    """Whether a call can be attempted: network on, an API key set and the SDK importable. Never
    downloads or imports anything on its own initiative — all checks are read-only."""
    if not net.network_enabled() or not _api_key()[0]:
        return False
    try:
        import google.genai  # noqa: F401
    except ImportError:
        return False
    return True


def _client():
    key = _api_key()[0]
    with _CLIENT_LOCK:
        if not _client_cache or _client_cache[0][0] != key:
            from google import genai
            _client_cache[:] = [(key, genai.Client(api_key=key))]
        return _client_cache[0][1]


def reset_client_cache() -> None:
    """Test-only: drop the cached client so a new API key or a fake SDK takes effect."""
    with _CLIENT_LOCK:
        _client_cache.clear()


def generate_json(system: str, data_blocks: dict[str, str], max_tokens: int = 256,
                  timeout_s: float = DEFAULT_TIMEOUT_S, temperature: float = 0.0,
                  seed: int | None = None, model: str | None = None) -> tuple[str | None, dict[str, Any]]:
    """Same contract as tunnelscope.rephrase.runtime.generate_json: (raw text or None, metadata).
    `model` overrides MODEL_ID (the fallback chain uses it). meta["retryable"] is True for a rate limit
    or a server-side error, so the chain may back off or move to its next model.
    Never raises. `timeout_s` bounds only this call (the SDK's own per-request timeout); the
    caller's overall time budget (generate.py) is enforced by not calling again once it is spent."""
    from ..rephrase.runtime import build_prompt
    content = build_prompt(system, data_blocks)
    model = model or MODEL_ID
    meta: dict[str, Any] = {"model_id": model, "model_revision": None, "backend": "gemini",
                            "prompt_sha256": hashlib.sha256(content.encode()).hexdigest(),
                            "temperature": temperature, "seed": seed, "latency_s": None, "reason": None,
                            "retryable": False}
    if not net.network_enabled():
        meta["reason"] = f"network is off ({net.ENV}=on allows the cloud model)"
        return None, meta
    key, key_env = _api_key()
    if not key:
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
        thinking = getattr(types, "ThinkingConfig", None)
        if THINKING_LEVEL and model.startswith("gemini-3") and thinking is not None:
            cfg_kwargs["thinking_config"] = thinking(thinking_level=THINKING_LEVEL)
            meta["thinking_level"] = THINKING_LEVEL
        response = client.models.generate_content(model=model, contents=content,
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
            meta["reason"], meta["retryable"] = "rate limit or quota exceeded", True
        elif code in (401, 403):
            meta["reason"] = f"authentication failed (check {key_env})"
        else:
            meta["reason"] = f"API error (HTTP {code}): {getattr(e, 'message', None) or type(e).__name__}"
            meta["retryable"] = isinstance(code, int) and code >= 500
        return None, meta
    except Exception as e:
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        meta["reason"] = f"unexpected error: {type(e).__name__}"
        return None, meta
