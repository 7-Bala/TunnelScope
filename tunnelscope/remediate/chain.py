"""DEC-040: the drafting fallback chain. Tries each model in order and moves on when one is unavailable (network
off, no key) or rate limited (after one short backoff on the same model), ending with the on-device model, so
drafting degrades instead of stopping. It never switches API keys to get round a quota: rate limits are per project
and the Google APIs Terms 2(d) forbid circumventing them; different MODELS have their own limits.

Order (DEC-041): every cloud client's FALLBACK_MODELS in CLIENTS order, then the local model. TUNNELSCOPE_GENERATOR_CHAIN
overrides it, e.g. "<provider>:<model>,<provider>:<model>,local", provider names being each client's PROVIDER.
Same generate_json contract as every backend; meta["attempts"] lists every try, meta["backend"] the one used."""
from __future__ import annotations

import os
import time
from typing import Any

from ..rephrase import runtime
from . import cloud_client, open_model_client

# DEC-041 (EXP-18b): the hosted open-weight model first (12/16 test fixes, median 3.3 s per draft, free tier does not
# train on inputs), then cloud_client's model (13/16, 13.3 s); fix rates are within each other's 95% intervals.
CLIENTS = (open_model_client, cloud_client)
BACKOFF_S = 2.0


def order() -> list[tuple[Any, str | None]]:
    spec = os.environ.get("TUNNELSCOPE_GENERATOR_CHAIN", "").strip()
    by_name = {c.PROVIDER: c for c in CLIENTS}
    if not spec:
        return [(c, m) for c in CLIENTS for m in c.FALLBACK_MODELS] + [(runtime, None)]
    out = []
    for item in (x.strip() for x in spec.split(",") if x.strip()):
        if item == "local":
            out.append((runtime, None))
        else:
            name, _, model = item.partition(":")
            if name in by_name:
                out.append((by_name[name], model or None))
    return out or [(runtime, None)]


def _call(mod, model, system, blocks, max_tokens, timeout_s, temperature, seed):
    if mod is runtime:
        raw, meta = runtime.generate_json(system, blocks, max_tokens=max_tokens, timeout_s=timeout_s,
                                          temperature=temperature, seed=seed)
        return raw, {**meta, "backend": "local"}
    return mod.generate_json(system, blocks, max_tokens=max_tokens, timeout_s=timeout_s, temperature=temperature,
                             seed=seed, model=model)


def generate_json(system: str, data_blocks: dict[str, str], max_tokens: int = 256, timeout_s: float = 30.0,
                  temperature: float = 0.0, seed: int | None = None) -> tuple[str | None, dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    attempts: list[dict] = []
    meta: dict[str, Any] = {"reason": "no model configured"}
    for mod, model in order():
        for retry in (False, True):
            left = deadline - time.monotonic()
            if left <= 1:
                break
            raw, meta = _call(mod, model, system, data_blocks, max_tokens, left, temperature, seed)
            attempts.append({"backend": meta.get("backend"), "model_id": meta.get("model_id"),
                             "ok": raw is not None, "reason": meta.get("reason"), "latency_s": meta.get("latency_s")})
            if raw is not None:
                return raw, {**meta, "attempts": attempts}
            if not meta.get("retryable") or retry:
                break
            time.sleep(min(BACKOFF_S, max(0.0, deadline - time.monotonic() - 1)))
    reasons = "; ".join(f"{a['backend']}:{a['model_id']}: {a['reason']}" for a in attempts) or "time budget spent"
    return None, {**meta, "backend": "chain", "attempts": attempts, "reason": f"every model failed ({reasons})"}
