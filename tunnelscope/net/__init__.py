"""DEC-040: the ONE place in TunnelScope that opens a network connection, and only when the operator turns the
network is on. Everything that reads captures and produces findings, verdicts and scores never imports this module
(tests/test_ai_layer.py checks that); only the extras do: threat intelligence lookups (tunnelscope.intel) and
remediation drafting by an outside model (tunnelscope.remediate.*_client, which also needs TUNNELSCOPE_GENERATOR=1).
DEC-045 (owner, 2026-09-28): ON by default, so known-vulnerability data is looked up on every analysis and stays
current; only the software name is ever sent. An air-gapped install sets TUNNELSCOPE_NETWORK=off and uses the
offline intel bundle (tunnelscope intel-bundle)."""
from __future__ import annotations

import functools
import json
import os
import ssl
import urllib.error
import urllib.request

ENV = "TUNNELSCOPE_NETWORK"
USER_AGENT = "TunnelScope (IPsec posture analyzer; https://github.com/7-Bala/TunnelScope)"


class NetworkDisabled(RuntimeError):
    """The operator has not turned the network on."""


class HttpError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


@functools.lru_cache(maxsize=1)
def _ssl_context() -> ssl.SSLContext:
    """Certificate verification is always on. Some Python builds (e.g. python.org's macOS installer before
    'Install Certificates') ship with no CA store at all; then certifi's bundle is used if it is installed."""
    ctx = ssl.create_default_context()
    if not ctx.get_ca_certs() and not ssl.get_default_verify_paths().cafile:
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except ImportError:
            pass
    return ctx


def network_enabled() -> bool:
    # DEC-045 (owner, 2026-09-28): on by default so vulnerability data stays current; air-gapped installs set
    # TUNNELSCOPE_NETWORK=off and use the offline intel bundle.
    return os.environ.get(ENV, "on").strip().lower() in ("on", "1", "true", "yes")


def http_json(url: str, *, method: str = "GET", headers: dict | None = None, body: dict | None = None,
              timeout: float = 30.0):
    """GET/POST and parse JSON. Raises NetworkDisabled, HttpError (status kept, e.g. 429), or OSError."""
    if not network_enabled():
        raise NetworkDisabled(f"network is off ({ENV}=on enables online extras)")
    h = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as r:
            return json.loads(r.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as e:
        raise HttpError(e.code, (e.read() or b"").decode(errors="replace")[:300]) from None
