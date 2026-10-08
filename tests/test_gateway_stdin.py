"""DEC-063: a gateway fix must not lose what the operator types or pipes in.

Found on 2026-10-05 against two real strongSwan gateways over real SSH: `ssh` inherited the CLI's
standard input and consumed the piped confirmation sentence, and the prompt then ended in a
traceback. Nothing was changed on the gateways, but a refusal has to be said plainly.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.fake_lab import sas
from tests.test_gateway_remediation import CONF, GW_CONF, FakeGateways, _accept, _fix, _register
from tunnelscope import cli
from tunnelscope.remediate import execute, gateways

REPO = Path(__file__).resolve().parents[1]
SENTENCE = "APPLY V-207193 ON office-a\n"


def _lab(monkeypatch, tmp_path) -> FakeGateways:
    lab = FakeGateways(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "PASS"}))
    lab.install(monkeypatch, tmp_path)
    monkeypatch.setenv("TUNNELSCOPE_SKIP_PREFLIGHT", "1")
    monkeypatch.delenv("TUNNELSCOPE_GATEWAYS", raising=False)
    return lab


def _no_input(*_a, **_k):
    raise EOFError


def test_ssh_does_not_consume_the_callers_stdin(tmp_path):
    """Real processes, no fake `subprocess.run`: a stand-in `ssh` that reads all of its input, as the
    real one does while a remote command runs. What was piped to the caller must still be there."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake_ssh = bindir / "ssh"
    fake_ssh.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n")
    fake_ssh.chmod(0o755)
    execute.save_gateway("office-a", {"host": "192.0.2.10", "connection": "office-link"}, tmp_path)
    code = ("import sys\n"
            "from tunnelscope.remediate import execute\n"
            f"execute._CTX.history_dir = {str(tmp_path)!r}\n"
            "r = execute._exec('gw:office-a', ['true'])\n"
            "assert r.returncode == 0, r\n"
            "sys.stdout.write(sys.stdin.readline())\n")
    env = {k: v for k, v in os.environ.items() if k != "TUNNELSCOPE_GATEWAYS"}
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    r = subprocess.run([sys.executable, "-c", code], input=SENTENCE, capture_output=True, text=True,
                       env=env, cwd=REPO, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout == SENTENCE


def test_every_ssh_call_in_a_whole_fix_feeds_or_closes_stdin(monkeypatch, tmp_path):
    lab = _lab(monkeypatch, tmp_path)
    seen: list[dict] = []

    def spy(cmd, *args, **kwargs):
        if cmd[0] == "ssh":
            seen.append(kwargs)
        return lab.run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    _register(tmp_path, peer="office-b")
    _accept(tmp_path, "office-a", "office-b")
    _, res = _fix(tmp_path)
    assert res["confirmed_fixed"] is True and len(seen) > 10
    for kwargs in seen:
        assert kwargs.get("input") is not None or kwargs.get("stdin") is subprocess.DEVNULL, kwargs


def test_fix_with_nothing_typed_refuses_plainly_and_changes_nothing(monkeypatch, tmp_path, capsys):
    lab = _lab(monkeypatch, tmp_path)
    _register(tmp_path, peer="office-b")
    _accept(tmp_path, "office-a", "office-b")
    before = {g: lab.fs[g][CONF] for g in ("gw:office-a", "gw:office-b")}
    monkeypatch.setattr("builtins.input", _no_input)
    rc = cli.main(["fix", "V-207193", "--target", "gw:office-a", "--history", str(tmp_path)])
    err = capsys.readouterr().err
    assert rc != 0 and "nothing was typed" in err and "--ack" in err and "Traceback" not in err
    assert {g: lab.fs[g][CONF] for g in before} == before and before["gw:office-a"] == GW_CONF
    log = (tmp_path / "remediate.jsonl").read_text().splitlines()
    decisions = [json.loads(line).get("decision") for line in log]
    assert "applied" not in decisions and "started" not in decisions


def test_fix_with_the_sentence_given_by_flag_applies(monkeypatch, tmp_path, capsys):
    lab = _lab(monkeypatch, tmp_path)
    _register(tmp_path, peer="office-b")
    _accept(tmp_path, "office-a", "office-b")
    monkeypatch.setattr("builtins.input", _no_input)
    rc = cli.main(["fix", "V-207193", "--target", "gw:office-a", "--history", str(tmp_path),
                   "--ack", SENTENCE.strip()])
    assert rc == 0 and '"confirmed_fixed": true' in capsys.readouterr().out
    assert "modp4096" in lab.fs["gw:office-a"][CONF] and "modp4096" in lab.fs["gw:office-b"][CONF]


def test_accept_with_nothing_typed_refuses_plainly_and_records_nothing(monkeypatch, tmp_path, capsys):
    _lab(monkeypatch, tmp_path)
    _register(tmp_path)
    monkeypatch.setattr("builtins.input", _no_input)
    rc = cli.main(["gateway", "accept", "office-a", "--history", str(tmp_path), "--by", "tester"])
    err = capsys.readouterr().err
    assert rc != 0 and "nothing was typed" in err and "--typed" in err
    assert gateways.consent_status(gateways.get("gw:office-a", tmp_path), tmp_path)["accepted"] is False
