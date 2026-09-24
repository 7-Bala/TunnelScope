"""Local model runtime for structured generation (DEC-034, T-101).

The only place a remediation draft is asked of the local model. It shares the loaded model and
the generation lock with `rephrase.py` (one model in memory, one generation at a time), loads the
pinned revision from the local cache only (never downloads, never touches the network), and
never raises: every failure is `(None, {"reason": ...})`.

What comes back is the model's raw text. Nothing here parses, trusts or runs it; the caller
(tunnelscope/remediate/generate.py) checks every part of it with code.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from typing import Any

from . import rephrase as _r

logger = logging.getLogger("tunnelscope.rephrase.runtime")

MODEL_ID = _r.MODEL_ID
MODEL_REVISION = _r.MODEL_REVISION
DEFAULT_TIMEOUT_S = 20.0


def model_available() -> bool:
    """Apple Silicon with mlx_lm installed AND the pinned model revision already downloaded."""
    return _r.available() and _r.local_model_path() is not None


def build_prompt(system: str, data_blocks: dict[str, str]) -> str:
    """The instruction, then each data block between named markers. Data is labelled as data."""
    parts = [system.strip(), ""]
    for name, text in data_blocks.items():
        tag = "".join(c for c in name.upper() if c.isalnum() or c == "_")
        parts += [f"<<<{tag}_START>>>", str(text), f"<<<{tag}_END>>>", ""]
    return "\n".join(parts).rstrip() + "\n"


def generate_json(system: str, data_blocks: dict[str, str], max_tokens: int = 256,
                  timeout_s: float = DEFAULT_TIMEOUT_S, temperature: float = 0.0,
                  seed: int | None = None) -> tuple[str | None, dict[str, Any]]:
    """Ask the local model for a JSON answer. Returns (raw text or None, metadata).

    Greedy decoding by default (deterministic: the same input gives the same output). A
    temperature above 0 is for the EXP-18 robustness arm only."""
    content = build_prompt(system, data_blocks)
    meta: dict[str, Any] = {"model_id": MODEL_ID, "model_revision": MODEL_REVISION,
                            "prompt_sha256": hashlib.sha256(content.encode()).hexdigest(),
                            "temperature": temperature, "seed": seed, "latency_s": None, "reason": None}
    if not _r.available():
        meta["reason"] = "the local model runtime is not available on this machine"
        return None, meta
    if _r.local_model_path() is None:
        meta["reason"] = "model not downloaded (the pinned revision is not in the local cache)"
        return None, meta

    t0 = time.monotonic()
    deadline = t0 + timeout_s
    if not _r._GEN_LOCK.acquire(blocking=True, timeout=max(0.001, timeout_s)):
        meta["reason"] = "the local model is busy"
        return None, meta
    lock_held = True
    worker: threading.Thread | None = None
    try:
        try:
            model, tokenizer = _r._get_model(MODEL_ID)
        except Exception as e:
            meta["reason"] = f"model could not be loaded: {type(e).__name__}"
            return None, meta
        if time.monotonic() >= deadline:
            meta["reason"] = "time budget used up before generation"
            return None, meta
        messages = [{"role": "user", "content": content}]
        prompt: Any
        if hasattr(tokenizer, "apply_chat_template") and getattr(tokenizer, "chat_template", None):
            try:
                prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True,
                                                       enable_thinking=False)
            except TypeError:
                prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        else:
            prompt = content
        box: list[str] = []

        def _work() -> None:
            try:
                import mlx_lm
                kwargs: dict[str, Any] = {"max_tokens": max_tokens, "verbose": False}
                if temperature > 0:
                    import mlx.core as mx
                    from mlx_lm.sample_utils import make_sampler
                    if seed is not None:
                        mx.random.seed(seed)
                    kwargs["sampler"] = make_sampler(temp=temperature)
                box.append(mlx_lm.generate(model, tokenizer, prompt=prompt, **kwargs))
            except Exception as e:  # recorded, never raised
                logger.debug("generation failed: %s", e)

        worker = threading.Thread(target=_work, daemon=True)
        worker.start()
        worker.join(timeout=max(0.001, deadline - time.monotonic()))
        if worker.is_alive():
            lock_held = False
            threading.Thread(target=_r._reap_and_release, args=(worker,), daemon=True).start()
            meta["reason"] = f"timed out after {timeout_s:g} s"
            return None, meta
        if not box:
            meta["reason"] = "the model produced no output"
            return None, meta
        meta["latency_s"] = round(time.monotonic() - t0, 3)
        return box[0], meta
    except Exception as e:
        meta["reason"] = f"unexpected error: {type(e).__name__}"
        return None, meta
    finally:
        if lock_held:
            if worker is not None and worker.is_alive():
                threading.Thread(target=_r._reap_and_release, args=(worker,), daemon=True).start()
            else:
                _r._GEN_LOCK.release()
