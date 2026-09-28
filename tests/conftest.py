"""Keep the unit tests hermetic against the operator's shell environment.

An operator who loads the git-ignored .env (`set -a; . ./.env; set +a`) exports TUNNELSCOPE_GENERATOR,
TUNNELSCOPE_GENERATOR_BACKEND=chain, TUNNELSCOPE_NETWORK=on and real API keys. The API server reads the drafting
backend from the environment, so a test's FakeModel on the local runtime was bypassed and the result depended on
whose shell ran pytest. Every test now starts with none of these set; a test that needs one sets it itself with
monkeypatch.setenv. Values are only deleted, never read or printed (they include real keys)."""
from __future__ import annotations

import os

import pytest

PREFIX = "TUNNELSCOPE_"
# provider key variables an SDK may pick up on its own even when the package does not read them
PROVIDER_KEYS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                 "NVD_API_KEY", "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")


def _operator_vars() -> list[str]:
    return [k for k in os.environ if k.startswith(PREFIX) or k in PROVIDER_KEYS]


# Some modules read the environment at import time (e.g. assess.engine.RULES_DIR, api.server.HISTORY_DIR, the cloud
# clients' MODEL_ID), before any fixture runs. conftest.py is imported before the test modules, so clear them here too.
for _k in _operator_vars():
    del os.environ[_k]


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch, tmp_path_factory):
    """Per test: remove anything the package or an earlier test left in os.environ outside monkeypatch."""
    for k in _operator_vars():
        monkeypatch.delenv(k, raising=False)
    # DEC-045 turned the network on by default. Unit tests never touch the network or this machine's intel cache:
    # a test that needs either sets it itself (monkeypatch.setenv overrides these).
    monkeypatch.setenv("TUNNELSCOPE_NETWORK", "off")
    monkeypatch.setenv("TUNNELSCOPE_INTEL_DIR", str(tmp_path_factory.mktemp("intel-cache")))
