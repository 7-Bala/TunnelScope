"""T-101: the model runtime for remediation drafts. These tests never load a real model: mlx_lm
is replaced through sys.modules (as tests/test_rephrase.py does), so they run the same on Linux
CI and on the Mac. The real-model check is `build/check_live.sh model` (build/live_checks.py)."""
import os
import sys
import threading
import time
import types

import pytest

from tunnelscope.rephrase import rephrase as rp
from tunnelscope.rephrase import runtime


class _Tok:
    chat_template = "x"

    def __init__(self):
        self.calls = []

    def apply_chat_template(self, messages, tokenize, add_generation_prompt, enable_thinking=None):
        self.calls.append((messages, enable_thinking))
        return "PROMPT:" + messages[0]["content"]


def _fake_mlx(monkeypatch, generate):
    loads = []
    mod = types.SimpleNamespace(load=lambda path: loads.append(path) or ("MODEL", _Tok()), generate=generate)
    monkeypatch.setitem(sys.modules, "mlx_lm", mod)
    monkeypatch.setattr(rp, "available", lambda: True)
    monkeypatch.setattr(rp, "local_model_path", lambda: "/cache/pinned-snapshot")
    monkeypatch.setattr(rp, "_MODEL_CACHE", {})
    return loads


def test_unavailable_platform_returns_none_with_a_reason(monkeypatch):
    monkeypatch.setattr(rp, "available", lambda: False)
    out, meta = runtime.generate_json("sys", {"config": "x"})
    assert out is None and "not available" in meta["reason"]
    assert meta["model_revision"] == runtime.MODEL_REVISION and len(meta["prompt_sha256"]) == 64


def test_model_not_downloaded_is_a_refusal_never_a_download(monkeypatch):
    monkeypatch.setattr(rp, "available", lambda: True)
    monkeypatch.setattr(rp, "local_model_path", lambda: None)
    called = []
    monkeypatch.setitem(sys.modules, "mlx_lm", types.SimpleNamespace(load=lambda p: called.append(p), generate=None))
    out, meta = runtime.generate_json("sys", {"config": "x"})
    assert out is None and "not downloaded" in meta["reason"] and called == []


def _hub_cache(monkeypatch, tmp_path, files):
    snap = tmp_path / ("models--" + rp.MODEL_ID.replace("/", "--")) / "snapshots" / rp.MODEL_REVISION
    snap.mkdir(parents=True)
    for f in files:
        (snap / f).write_text("x")
    monkeypatch.setitem(sys.modules, "huggingface_hub", types.SimpleNamespace(constants=types.SimpleNamespace(HF_HUB_CACHE=str(tmp_path))))
    return snap


def test_local_model_path_is_the_pinned_revision_and_sets_offline_mode(monkeypatch, tmp_path):
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    monkeypatch.delenv("TRANSFORMERS_OFFLINE", raising=False)
    snap = _hub_cache(monkeypatch, tmp_path, ["config.json", "model.safetensors"])
    assert rp.local_model_path() == str(snap)
    assert os.environ["HF_HUB_OFFLINE"] == "1" and os.environ["TRANSFORMERS_OFFLINE"] == "1"


def test_a_different_or_partial_revision_is_not_used(monkeypatch, tmp_path):
    _hub_cache(monkeypatch, tmp_path, ["config.json"])            # no weights
    assert rp.local_model_path() is None
    other = tmp_path / ("models--" + rp.MODEL_ID.replace("/", "--")) / "snapshots" / ("f" * 40)
    other.mkdir(parents=True)
    (other / "config.json").write_text("x")
    (other / "model.safetensors").write_text("x")
    assert rp.local_model_path() is None, "only the pinned revision counts"


def test_an_explicit_offline_setting_is_not_overwritten(monkeypatch, tmp_path):
    monkeypatch.setenv("HF_HUB_OFFLINE", "0")
    _hub_cache(monkeypatch, tmp_path, [])
    assert rp.local_model_path() is None
    assert os.environ["HF_HUB_OFFLINE"] == "0"


def test_generates_from_the_pinned_local_path_with_data_blocks_marked(monkeypatch):
    prompts = []
    loads = _fake_mlx(monkeypatch, lambda m, t, prompt, **k: prompts.append((prompt, k)) or '{"a": 1}')
    out, meta = runtime.generate_json("Return JSON.", {"config": "proposals = aes256-sha256-modp2048", "rule": "V-1"})
    assert out == '{"a": 1}' and meta["reason"] is None and meta["latency_s"] is not None
    assert loads == ["/cache/pinned-snapshot"]
    p, kw = prompts[0]
    assert "<<<CONFIG_START>>>\nproposals = aes256-sha256-modp2048\n<<<CONFIG_END>>>" in p
    assert "<<<RULE_START>>>\nV-1\n<<<RULE_END>>>" in p
    assert "sampler" not in kw, "greedy by default"


def test_prompt_hash_follows_the_data(monkeypatch):
    _fake_mlx(monkeypatch, lambda *a, **k: "{}")
    a = runtime.generate_json("s", {"config": "x"})[1]["prompt_sha256"]
    b = runtime.generate_json("s", {"config": "y"})[1]["prompt_sha256"]
    assert a != b and a == runtime.generate_json("s", {"config": "x"})[1]["prompt_sha256"]


def test_one_model_in_memory_shared_with_rephrase(monkeypatch):
    loads = _fake_mlx(monkeypatch, lambda *a, **k: "{}")
    runtime.generate_json("s", {"c": "x"})
    runtime.generate_json("s", {"c": "y"})
    rp._get_model(rp.MODEL_ID)
    assert len(loads) == 1


def test_timeout_returns_none_and_releases_the_lock_later(monkeypatch):
    release = threading.Event()
    _fake_mlx(monkeypatch, lambda *a, **k: release.wait(5) and "{}")
    out, meta = runtime.generate_json("s", {"c": "x"}, timeout_s=0.2)
    assert out is None and "timed out" in meta["reason"]
    assert rp._GEN_LOCK.locked(), "still held while the abandoned generation runs"
    release.set()
    deadline = time.monotonic() + 3
    while rp._GEN_LOCK.locked() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not rp._GEN_LOCK.locked()


def test_busy_lock_shared_with_rephrase_times_out(monkeypatch):
    _fake_mlx(monkeypatch, lambda *a, **k: "{}")
    rp._GEN_LOCK.acquire()
    try:
        out, meta = runtime.generate_json("s", {"c": "x"}, timeout_s=0.1)
    finally:
        rp._GEN_LOCK.release()
    assert out is None and "busy" in meta["reason"]


def test_errors_never_escape(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("metal")
    _fake_mlx(monkeypatch, boom)
    out, meta = runtime.generate_json("s", {"c": "x"})
    assert out is None and meta["reason"] == "the model produced no output"
    monkeypatch.setitem(sys.modules, "mlx_lm", types.SimpleNamespace(load=boom, generate=boom))
    monkeypatch.setattr(rp, "_MODEL_CACHE", {})
    out, meta = runtime.generate_json("s", {"c": "x"})
    assert out is None and "could not be loaded" in meta["reason"]
    assert not rp._GEN_LOCK.locked()


def test_temperature_uses_a_sampler_and_seed(monkeypatch):
    seen = {}
    _fake_mlx(monkeypatch, lambda m, t, prompt, **k: seen.update(k) or "{}")
    seeds = []
    core = types.SimpleNamespace(random=types.SimpleNamespace(seed=seeds.append))
    monkeypatch.setitem(sys.modules, "mlx.core", core)
    monkeypatch.setitem(sys.modules, "mlx", types.SimpleNamespace(core=core))
    monkeypatch.setitem(sys.modules, "mlx_lm.sample_utils", types.SimpleNamespace(make_sampler=lambda temp: ("S", temp)))
    out, meta = runtime.generate_json("s", {"c": "x"}, temperature=0.7, seed=3)
    assert seen["sampler"] == ("S", 0.7) and seeds == [3] and meta["temperature"] == 0.7 and meta["seed"] == 3


def test_runtime_is_the_only_new_model_entry_point():
    """No remediate module imports mlx or huggingface itself; they go through the runtime."""
    import pathlib
    import tunnelscope
    rem = pathlib.Path(tunnelscope.__file__).parent / "remediate"
    for p in rem.rglob("*.py"):
        src = p.read_text().lower()
        assert "mlx" not in src and "huggingface" not in src, p.name
