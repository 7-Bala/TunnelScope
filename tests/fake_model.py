"""A scripted stand-in for the local model (tunnelscope.rephrase.runtime.generate_json).

Tests give it the answers to return (strings, or a function of the prompt blocks) and read back
exactly what the model was shown. Never imported by the tunnelscope package."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable

from tunnelscope.rephrase import runtime


class FakeModel:
    def __init__(self, outputs: list[str | None] | Callable[[dict[str, str]], str | None]):
        self.outputs = outputs
        self.calls: list[dict[str, Any]] = []

    def __call__(self, system: str, data_blocks: dict[str, str], **kw: Any):
        self.calls.append({"system": system, "blocks": dict(data_blocks), **kw})
        if callable(self.outputs):
            out = self.outputs(dict(data_blocks))
        else:
            out = self.outputs.pop(0) if self.outputs else None
        meta = {"model_id": "fake", "model_revision": "fake-rev",
                "prompt_sha256": hashlib.sha256((system + json.dumps(data_blocks, sort_keys=True)).encode()).hexdigest(),
                "temperature": kw.get("temperature", 0.0), "seed": kw.get("seed"),
                "latency_s": 0.01 if out is not None else None,
                "reason": None if out is not None else "fake: no output"}
        return out, meta

    def install(self, monkeypatch) -> "FakeModel":
        monkeypatch.setattr(runtime, "generate_json", self)
        return self


def answer(line_key: str, edits: list[dict[str, Any]], expected: str, problem: str = "p", why: str = "w") -> str:
    return json.dumps({"line_key": line_key, "edits": edits, "problem": problem, "why": why,
                       "expected_line_after": expected})
