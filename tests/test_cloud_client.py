"""DEC-038: the optional Gemini drafting backend. These tests never call the real API: google.genai
is replaced through sys.modules (tests/test_runtime.py does the same for mlx_lm), so they run the
same in CI (no key, no package) as on a machine with both. The real-API check is a pre-registered
experiment (experiments/exp18b-gemini-remediation/), never a unit test."""
import sys
import types

import pytest

from tunnelscope.remediate import cloud_client as cc


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(cc.API_KEY_ENV, raising=False)
    cc.reset_client_cache()
    yield
    cc.reset_client_cache()


class _APIError(Exception):
    """Module-level so every _fake_sdk() install exposes the SAME class as google.genai.errors
    .APIError; two locally-defined classes of the same name would not match each other's instances
    in `except errors.APIError`, which is exactly the check being tested here."""
    def __init__(self, code, message="boom"):
        super().__init__(message)
        self.code, self.message = code, message


def _fake_sdk(monkeypatch, *, text="{}", raise_error=None, capture=None):
    """Install a minimal fake google.genai package. `capture`, if given, is filled with the kwargs
    passed to generate_content and to GenerateContentConfig."""
    class HttpOptions:
        def __init__(self, **kw):
            self.kw = kw

    class GenerateContentConfig:
        def __init__(self, **kw):
            self.kw = kw
            if capture is not None:
                capture["config"] = kw

    class _Response:
        def __init__(self, t):
            self.text = t

    class _Models:
        def generate_content(self, model, contents, config):
            if capture is not None:
                capture["model"] = model
                capture["contents"] = contents
            if raise_error is not None:
                raise raise_error
            return _Response(text)

    class Client:
        def __init__(self, api_key):
            self.api_key = api_key
            self.models = _Models()

    genai_mod = types.SimpleNamespace(Client=Client)
    errors_mod = types.SimpleNamespace(APIError=_APIError)
    types_mod = types.SimpleNamespace(HttpOptions=HttpOptions, GenerateContentConfig=GenerateContentConfig)
    google_mod = types.SimpleNamespace(genai=genai_mod)
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.genai", genai_mod)
    monkeypatch.setitem(sys.modules, "google.genai.errors", errors_mod)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_mod)
    genai_mod.errors, genai_mod.types = errors_mod, types_mod
    return _APIError


def test_unavailable_with_no_key_returns_none_with_a_reason(monkeypatch):
    _fake_sdk(monkeypatch)
    assert cc.available() is False
    out, meta = cc.generate_json("sys", {"a": "b"})
    assert out is None and cc.API_KEY_ENV in meta["reason"] and meta["backend"] == "gemini"
    assert len(meta["prompt_sha256"]) == 64


def test_unavailable_with_key_but_no_package(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "fake-key")
    monkeypatch.delitem(sys.modules, "google.genai", raising=False)
    monkeypatch.delitem(sys.modules, "google", raising=False)
    real_import = __import__

    def blocked(name, *a, **k):
        if name.startswith("google"):
            raise ImportError("no such package")
        return real_import(name, *a, **k)
    monkeypatch.setattr("builtins.__import__", blocked)
    assert cc.available() is False
    out, meta = cc.generate_json("sys", {"a": "b"})
    assert out is None and "not installed" in meta["reason"]


def test_key_and_package_present_is_available(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "fake-key")
    _fake_sdk(monkeypatch)
    assert cc.available() is True


def test_successful_call_returns_text_and_never_leaks_the_key_in_meta(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "super-secret-key")
    cap: dict = {}
    _fake_sdk(monkeypatch, text='{"line_key": "proposals"}', capture=cap)
    out, meta = cc.generate_json("SYSTEM", {"rule": "V-207193 text"}, max_tokens=99, temperature=0.3, seed=7)
    assert out == '{"line_key": "proposals"}'
    assert meta["reason"] is None and meta["backend"] == "gemini" and meta["latency_s"] is not None
    assert "super-secret-key" not in str(meta)
    assert cap["config"]["max_output_tokens"] == 99 and cap["config"]["temperature"] == 0.3 and cap["config"]["seed"] == 7
    assert cap["config"]["response_mime_type"] == "application/json"
    assert "SYSTEM" in cap["contents"] and "V-207193 text" in cap["contents"]


def test_seed_omitted_when_none(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    cap: dict = {}
    _fake_sdk(monkeypatch, text="{}", capture=cap)
    cc.generate_json("s", {"a": "b"}, seed=None)
    assert "seed" not in cap["config"]


def test_empty_output_is_a_refusal(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    _fake_sdk(monkeypatch, text="")
    out, meta = cc.generate_json("s", {"a": "b"})
    assert out is None and "no output" in meta["reason"]


def test_rate_limit_error_is_reported_as_such(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    _fake_sdk(monkeypatch, raise_error=_APIError(429))
    out, meta = cc.generate_json("s", {"a": "b"})
    assert out is None and "rate limit" in meta["reason"]


def test_auth_error_names_the_env_var(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    _fake_sdk(monkeypatch, raise_error=_APIError(401))
    out, meta = cc.generate_json("s", {"a": "b"})
    assert out is None and cc.API_KEY_ENV in meta["reason"] and "authentication" in meta["reason"]


def test_other_api_error_is_reported_with_its_code(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    _fake_sdk(monkeypatch, raise_error=_APIError(500, "server exploded"))
    out, meta = cc.generate_json("s", {"a": "b"})
    assert out is None and "500" in meta["reason"]


def test_unexpected_exception_is_caught_never_raised(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    _fake_sdk(monkeypatch, raise_error=RuntimeError("kaboom"))
    out, meta = cc.generate_json("s", {"a": "b"})
    assert out is None and "unexpected error" in meta["reason"] and "RuntimeError" in meta["reason"]


def _counting_sdk(monkeypatch):
    made: list[str] = []

    class Client:
        def __init__(self, api_key):
            made.append(api_key)
            self.models = types.SimpleNamespace(generate_content=lambda **kw: types.SimpleNamespace(text="{}"))
    genai_mod = types.SimpleNamespace(Client=Client)
    errors_mod = types.SimpleNamespace(APIError=type("APIError", (Exception,), {}))
    types_mod = types.SimpleNamespace(HttpOptions=lambda **kw: None, GenerateContentConfig=lambda **kw: None)
    genai_mod.errors, genai_mod.types = errors_mod, types_mod
    monkeypatch.setitem(sys.modules, "google", types.SimpleNamespace(genai=genai_mod))
    monkeypatch.setitem(sys.modules, "google.genai", genai_mod)
    monkeypatch.setitem(sys.modules, "google.genai.errors", errors_mod)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_mod)
    return made


def test_client_is_cached_across_calls(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    made = _counting_sdk(monkeypatch)
    cc.generate_json("s", {"a": "b"})
    cc.generate_json("s", {"a": "b"})
    assert made == ["k"]


def test_reset_client_cache_forces_a_new_client(monkeypatch):
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    made = _counting_sdk(monkeypatch)
    cc.generate_json("s", {"a": "b"})
    cc.reset_client_cache()
    cc.generate_json("s", {"a": "b"})
    assert made == ["k", "k"]


def test_prompt_reuses_the_same_data_is_data_framing_as_the_local_model(monkeypatch):
    """The <<<TAG_START>>>...<<<TAG_END>>> markers are what EXP-18's prompt-injection safety items
    (S11a/S11b) rely on; the cloud backend must build the prompt the same way, not its own format."""
    from tunnelscope.rephrase.runtime import build_prompt
    monkeypatch.setenv(cc.API_KEY_ENV, "k")
    cap: dict = {}
    _fake_sdk(monkeypatch, text="{}", capture=cap)
    cc.generate_json("SYS", {"rule": "R", "current_lines": "L"})
    assert cap["contents"] == build_prompt("SYS", {"rule": "R", "current_lines": "L"})
