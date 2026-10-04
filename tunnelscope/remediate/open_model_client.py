"""Optional cloud drafting backend: Groq (DEC-040, owner, 2026-09-27). Same role and the same limits as
cloud_client.py (DEC-038): it only DRAFTS a candidate remediation edit; generate.py re-verifies every draft with
its V1-V8 checks, dry run and clone-load check before anything can run. Never imported by anything that produces
a finding, verdict, score or anomaly (tests/test_ai_layer.py).

Why Groq: its free tier contractually does not train on inputs or outputs and retains none by default (Groq
"Your Data" docs, 2026-09-27), and it serves open-weight models (GPT-OSS 120B, Llama 3.3 70B) that a client can
also run air-gapped on its own hardware. Plain HTTPS through tunnelscope.net (its chat-completions endpoint follows
the widely used chat-completions request format); no provider SDK.

Off unless TUNNELSCOPE_GROQ_API_KEY is set and the network is not switched off (TUNNELSCOPE_NETWORK, on by default since DEC-045).

DEC-055 (owner, 2026-10-04): tunnelscope/rephrase/api.py may also ask this client to REWORD explanation sentences,
with every IP address replaced by a placeholder before sending and the rephrase fact check applied to each reply;
only when the operator sets TUNNELSCOPE_REPHRASE_BACKEND=api."""
from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from .. import net

PROVIDER = "groq"
MODEL_ID = os.environ.get("TUNNELSCOPE_GROQ_MODEL", "openai/gpt-oss-120b")
API_KEY_ENV = "TUNNELSCOPE_GROQ_API_KEY"
URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_TIMEOUT_S = 30.0
FALLBACK_MODELS = (MODEL_ID,)
# GPT-OSS is a reasoning model: at the generator's ~320-token budget and default effort it spent ~480 tokens
# reasoning, left no answer, and Groq rejected the empty output (HTTP 400 json_validate_failed); with "low" it
# answered 3/3 using 63-132 reasoning tokens (measured 2026-09-27). Override with TUNNELSCOPE_GROQ_REASONING.
REASONING_EFFORT = os.environ.get("TUNNELSCOPE_GROQ_REASONING", "low")


def available() -> bool:
    return net.network_enabled() and bool(os.environ.get(API_KEY_ENV))


def generate_json(system: str, data_blocks: dict[str, str], max_tokens: int = 256,
                  timeout_s: float = DEFAULT_TIMEOUT_S, temperature: float = 0.0,
                  seed: int | None = None, model: str | None = None) -> tuple[str | None, dict[str, Any]]:
    """Same contract as cloud_client.generate_json. Never raises."""
    from ..rephrase.runtime import build_prompt
    content = build_prompt(system, data_blocks)
    model = model or MODEL_ID
    meta: dict[str, Any] = {"model_id": model, "model_revision": None, "backend": PROVIDER,
                            "prompt_sha256": hashlib.sha256(content.encode()).hexdigest(),
                            "temperature": temperature, "seed": seed, "latency_s": None, "reason": None,
                            "retryable": False}
    if not net.network_enabled():
        meta["reason"] = f"network is off ({net.ENV}=on allows the cloud model)"
        return None, meta
    key = os.environ.get(API_KEY_ENV)
    if not key:
        meta["reason"] = f"no Groq API key set ({API_KEY_ENV})"
        return None, meta
    body: dict[str, Any] = {"model": model, "temperature": temperature, "max_completion_tokens": max_tokens,
                            "response_format": {"type": "json_object"},
                            "messages": [{"role": "user", "content": content}]}
    if seed is not None:
        body["seed"] = seed
    if REASONING_EFFORT and "gpt-oss" in model:
        body["reasoning_effort"] = REASONING_EFFORT
        meta["reasoning_effort"] = REASONING_EFFORT
    t0 = time.monotonic()
    try:
        d = net.http_json(URL, method="POST", headers={"Authorization": f"Bearer {key}"}, body=body, timeout=timeout_s)
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        text = ((d.get("choices") or [{}])[0].get("message") or {}).get("content")
        if not text:
            meta["reason"] = "the model produced no output"
            return None, meta
        return text, meta
    except net.HttpError as e:
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        if e.status == 429:
            meta["reason"], meta["retryable"] = "rate limit or quota exceeded", True
        elif e.status in (401, 403):
            meta["reason"] = f"authentication failed (check {API_KEY_ENV})"
        elif e.status == 400 and "json_validate_failed" in str(e):
            meta["reason"] = "the model produced no valid JSON (json_validate_failed)"
        else:
            meta["reason"], meta["retryable"] = f"API error (HTTP {e.status})", e.status >= 500
        return None, meta
    except Exception as e:
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        meta["reason"], meta["retryable"] = f"unexpected error: {type(e).__name__}", isinstance(e, OSError)
        return None, meta
