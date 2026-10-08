"""DEC-064: AI drafting through a cloud API is the default drafter whenever it can be used, on every target.

It stays off in the public demo, off without a key, and the operator can turn it off (TUNNELSCOPE_GENERATOR=0)."""
import pytest

from tunnelscope.api import server
from tunnelscope.remediate import execute, gateways


@pytest.fixture
def cloud(monkeypatch):
    """A switch for 'a cloud model can be called here', without a key, the network or an SDK."""
    state = {"on": True}
    monkeypatch.setattr(server, "cloud_model_available", lambda: state["on"])
    return state


def test_drafting_is_on_by_default_when_a_cloud_model_is_available(cloud, monkeypatch):
    assert server.generator_enabled() is True
    assert server.generator_backend() == "chain"


def test_drafting_stays_off_and_local_without_a_cloud_model(cloud, monkeypatch):
    cloud["on"] = False
    assert server.generator_enabled() is False
    assert server.generator_backend() == "local"


def test_the_operator_can_turn_drafting_off_or_force_it_on(cloud, monkeypatch):
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR", "0")
    assert server.generator_enabled() is False
    cloud["on"] = False
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR", "1")
    assert server.generator_enabled() is True          # the on-device model, forced on


def test_the_public_demo_never_drafts(cloud, monkeypatch):
    monkeypatch.setenv("TUNNELSCOPE_PUBLIC_DEMO", "1")
    assert server.generator_enabled() is False
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR", "1")
    assert server.generator_enabled() is False          # not even when forced on


def test_an_explicit_backend_setting_is_still_honoured(cloud, monkeypatch):
    for value, want in (("cloud", "cloud"), ("chain", "chain"), ("local", "local"), ("nonsense", "local")):
        monkeypatch.setenv("TUNNELSCOPE_GENERATOR_BACKEND", value)
        assert server.generator_backend() == want


def test_a_new_gateway_allows_ai_drafts_unless_it_opts_out(tmp_path):
    base = {"host": "192.168.77.10", "connection": "office-link"}
    assert execute.save_gateway("a", dict(base), tmp_path)["allow_ai_drafts"] is True
    assert execute.save_gateway("b", {**base, "allow_ai_drafts": False}, tmp_path)["allow_ai_drafts"] is False
    assert gateways.DEFAULT_ALLOW_AI_DRAFTS is True


def test_the_cli_flag_defaults_on_and_has_an_opt_out(monkeypatch, tmp_path):
    import argparse
    from tunnelscope import cli
    seen = {}
    monkeypatch.setattr(cli, "cmd_gateway", lambda a: seen.update(allow=a.allow_ai_drafts) or 0)
    # the parser binds the handler at build time, so call main() and read what the handler saw
    assert cli.main(["gateway", "list", "--history", str(tmp_path)]) == 0
    assert seen["allow"] is True
    assert cli.main(["gateway", "list", "--history", str(tmp_path), "--no-allow-ai-drafts"]) == 0
    assert seen["allow"] is False
