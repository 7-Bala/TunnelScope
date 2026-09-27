"""DEC-040: the hosted open-model client and the drafting fallback chain. No network: net.http_json and the
clients are replaced. The chain moves to the next MODEL on a rate limit (after one backoff), never to another key."""
import pytest

from tunnelscope import net
from tunnelscope.remediate import chain, cloud_client, open_model_client as om
from tunnelscope.rephrase import runtime


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv(net.ENV, "on")
    monkeypatch.setenv(om.API_KEY_ENV, "test-key")
    monkeypatch.delenv("TUNNELSCOPE_GENERATOR_CHAIN", raising=False)
    monkeypatch.setattr(chain, "BACKOFF_S", 0.0)


def test_open_model_client_sends_json_mode_and_reads_the_answer(monkeypatch):
    seen = {}

    def fake(url, **kw):
        seen.update(url=url, **kw)
        return {"choices": [{"message": {"content": '{"ok": true}'}}]}
    monkeypatch.setattr(net, "http_json", fake)
    raw, meta = om.generate_json("SYS", {"rule": "R"}, max_tokens=50, seed=3)
    assert raw == '{"ok": true}' and meta["backend"] == "groq" and meta["model_id"] == om.MODEL_ID
    assert seen["body"]["response_format"] == {"type": "json_object"} and seen["body"]["seed"] == 3
    assert seen["headers"]["Authorization"] == "Bearer test-key" and "test-key" not in str(meta)


@pytest.mark.parametrize("status,retryable", [(429, True), (503, True), (401, False), (400, False)])
def test_open_model_client_errors(monkeypatch, status, retryable):
    def fake(url, **kw):
        raise net.HttpError(status, "x")
    monkeypatch.setattr(net, "http_json", fake)
    raw, meta = om.generate_json("s", {"a": "b"})
    assert raw is None and meta["retryable"] is retryable


def test_open_model_client_refuses_with_the_network_off(monkeypatch):
    monkeypatch.setenv(net.ENV, "off")
    monkeypatch.setattr(net, "http_json", lambda *a, **k: pytest.fail("called"))
    raw, meta = om.generate_json("s", {"a": "b"})
    assert raw is None and "network is off" in meta["reason"]


def _stub(name, script):
    """A fake client whose answers follow `script` (list of (raw, retryable))."""
    calls = []

    def gen(system, blocks, max_tokens=256, timeout_s=30, temperature=0.0, seed=None, model=None):
        raw, retry = script[min(len(calls), len(script) - 1)]
        calls.append(model)
        return raw, {"backend": name, "model_id": model, "reason": None if raw else "rate limit", "retryable": retry}
    return gen, calls


def test_rate_limit_backs_off_once_then_moves_to_the_next_model(monkeypatch):
    g1, c1 = _stub("gemini", [(None, True)])
    g2, c2 = _stub("groq", [('{"x":1}', False)])
    monkeypatch.setattr(cloud_client, "generate_json", g1)
    monkeypatch.setattr(om, "generate_json", g2)
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR_CHAIN", "gemini:m1,groq:m2,local")
    raw, meta = chain.generate_json("s", {"a": "b"}, timeout_s=30)
    assert raw == '{"x":1}' and c1 == ["m1", "m1"] and c2 == ["m2"]
    assert [a["backend"] for a in meta["attempts"]] == ["gemini", "gemini", "groq"] and meta["backend"] == "groq"


def test_a_non_retryable_failure_is_not_retried(monkeypatch):
    g1, c1 = _stub("gemini", [(None, False)])
    monkeypatch.setattr(cloud_client, "generate_json", g1)
    monkeypatch.setattr(runtime, "generate_json", lambda *a, **k: ('{"l":1}', {"model_id": "local-model"}))
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR_CHAIN", "gemini:m1,local")
    raw, meta = chain.generate_json("s", {"a": "b"})
    assert c1 == ["m1"] and raw == '{"l":1}' and meta["backend"] == "local"


def test_everything_failing_reports_every_attempt(monkeypatch):
    g1, _ = _stub("gemini", [(None, False)])
    monkeypatch.setattr(cloud_client, "generate_json", g1)
    monkeypatch.setattr(runtime, "generate_json", lambda *a, **k: (None, {"reason": "no local runtime"}))
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR_CHAIN", "gemini:m1,local")
    raw, meta = chain.generate_json("s", {"a": "b"})
    assert raw is None and "every model failed" in meta["reason"] and len(meta["attempts"]) == 2


def test_default_order_is_every_cloud_model_then_local():
    o = chain.order()
    assert o[-1][0] is runtime and [m for c, m in o[:-1] if c is cloud_client] == list(cloud_client.FALLBACK_MODELS)


def test_generator_accepts_the_chain_backend():
    from tunnelscope.remediate import generate
    assert "chain" in generate.BACKENDS and generate._backend_module("chain") is chain


def test_reasoning_models_get_low_effort_so_small_budgets_still_answer(monkeypatch):
    """Measured 2026-09-27: default effort spent ~480 reasoning tokens and left no answer at 320 tokens."""
    seen = {}
    monkeypatch.setattr(net, "http_json", lambda url, **kw: seen.update(kw) or {"choices": [{"message": {"content": "{}"}}]})
    _, meta = om.generate_json("s", {"a": "b"}, model="openai/gpt-oss-120b")
    assert seen["body"]["reasoning_effort"] == "low" and meta["reasoning_effort"] == "low"
    seen.clear()
    om.generate_json("s", {"a": "b"}, model="llama-3.3-70b-versatile")
    assert "reasoning_effort" not in seen["body"]


def test_empty_json_rejection_is_a_model_failure_not_retryable(monkeypatch):
    def fake(url, **kw):
        raise net.HttpError(400, '{"error":{"code":"json_validate_failed"}}')
    monkeypatch.setattr(net, "http_json", fake)
    raw, meta = om.generate_json("s", {"a": "b"})
    assert raw is None and "no valid JSON" in meta["reason"] and meta["retryable"] is False

