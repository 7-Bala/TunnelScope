"""DEC-063: fixes on real strongSwan gateways over SSH, with terms-and-risks consent.

A fake SSH gateway (built on the fake lab) answers the `ssh` calls execute.py makes: it parses the
remote command line back into arguments (so quoting is exercised) and plays the gateway's files,
its isolated load check and its capture. The same steps were also run against two real strongSwan
gateways over real SSH: testbed/live-gateway/e2e.py (22 checks).
"""
from __future__ import annotations

import base64
import json
import shlex
import threading
import urllib.error
import urllib.request

import pytest

from tests.fake_lab import FakeLab, _Res, fake_clone_output, sas
from tunnelscope.remediate import execute, gateways

GW_CONF = """connections {
    office-link {
        local_addrs  = 192.168.77.10
        remote_addrs = 192.168.77.11
        version = 2
        proposals = aes256-sha256-modp2048
        local {
            auth = psk
            id = gwa
        }
        remote {
            auth = psk
            id = gwb
        }
        children {
            office-link {
                esp_proposals = aes256-sha256
            }
        }
    }
    backup-link {
        remote_addrs = 192.168.77.99
        version = 2
        proposals = aes128-sha256-modp2048
    }
}
"""
CONF = "/etc/swanctl/swanctl.conf"
HOSTS = {"192.168.77.10": "gw:office-a", "192.168.77.11": "gw:office-b"}


class FakeGateways(FakeLab):
    """The fake lab, reached as two gateways over `ssh` instead of `docker exec`."""

    def __init__(self, conf=GW_CONF, **kw):
        super().__init__(files={"gw:office-a": {CONF: conf}, "gw:office-b": {CONF: conf.replace("192.168.77.10", "X")
                                                                             .replace("192.168.77.11", "192.168.77.10")
                                                                             .replace("X", "192.168.77.11")}},
                         running=["gw:office-a", "gw:office-b"], **kw)
        self.ssh_calls: list[list[str]] = []
        self.load_checks = 0

    def run(self, cmd, *args, **kwargs):
        if cmd[0] != "ssh":
            return super().run(cmd, *args, **kwargs)
        self.ssh_calls.append(list(cmd))
        i = cmd.index("--")
        dest, remote = cmd[i + 1], cmd[i + 2]
        key = HOSTS[dest.split("@", 1)[1]]
        words = shlex.split(remote)
        detach = words[0] == "nohup"
        if detach:
            assert words[-4:] == [">/dev/null", "2>&1", "</dev/null", "&"], words
            words = words[1:-4]
        fs = self.fs[key]
        if words[:2] == ["unshare", "-n"]:
            assert words == execute.GW_LOAD_ARGV, "only the fixed load-check script may run on a gateway"
            self.load_checks += 1
            return _Res(0, fake_clone_output(kwargs["input"]).encode(), b"")
        if words[:2] == ["sh", "-c"] and words[2] == execute._LIST_GLOBS_SCRIPT:
            return _Res(0, "".join(p + "\n" for p in sorted(fs) if p.endswith(".conf") and p.startswith("/etc/swanctl/")))
        if words[0] == "tcpdump":
            fs[execute.GW_CAPTURE] = "fake-pcap"
            return _Res()
        if words[0] == "base64":
            data = fs.get(words[1])
            return _Res(0, base64.b64encode(data.encode()).decode()) if data else _Res(1, "", "no file")
        if words[0] == "swanctl" and "--stats" in words:
            return _Res(0, "uptime: 1 minute")
        if words[0] == "swanctl" and "--list-sas" in words:
            if self.rekeys and self.rekey_outcome == "down":
                return _Res(0, "list-sas reply {}\n")
            return _Res(0, "list-sa event {office-link {uniqueid=1 " + self.sa_fields +
                        f" initiator-spi={self.ike_spi:016x} responder-spi={self.ike_spi + 7:016x}"
                        " child-sas {office-link-1 {name=office-link state=INSTALLED mode=TUNNEL protocol=ESP}}}}\n")
        return super().run(["docker", "exec", *(["-d"] if detach else []), key, *words], *args, **kwargs)


def _register(h, peer=None, **extra):
    execute.save_gateway("office-a", {"host": "192.168.77.10", "connection": "office-link",
                                      "config_globs": [CONF], "peer": peer, **extra}, h)
    execute.save_gateway("office-b", {"host": "192.168.77.11", "connection": "office-link", "config_globs": [CONF]}, h)


def _accept(h, *names):
    for n in names:
        assert execute.accept_terms(gateways.PREFIX + n, gateways.accept_phrase(n), "tester", h)["ok"]


def _fix(h, ack="auto", **kw):
    pv = execute.preview_remediation("V-207193", "gw:office-a", history_dir=h)
    if not pv.get("ok"):
        return pv, None
    if ack == "auto":
        ack = pv["live"]["ack_phrase"]
    return pv, execute.apply_remediation("V-207193", "gw:office-a", confirm=True, history_dir=h,
                                         digest=pv["digest"], require_digest=True, risk_ack=ack, **kw)


@pytest.fixture
def gw(monkeypatch, tmp_path):
    lab = FakeGateways(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "PASS"}))
    lab.install(monkeypatch, tmp_path)
    return lab


# ------------------------------------------------------------------ registry and consent

def test_registry_validation_refuses_unsafe_values():
    for bad in ({"host": "a b", "connection": "c"}, {"host": "h", "connection": "c; rm"},
                {"host": "h", "connection": "c", "user": "root;x"}, {"host": "h", "connection": "c", "config_globs": ["etc/x.conf"]},
                {"host": "h", "connection": "c", "config_globs": ["/etc/$(x).conf"]}, {"host": "h", "connection": "c", "port": 0}):
        with pytest.raises(ValueError):
            gateways.validate_entry("g", bad)
    with pytest.raises(ValueError):
        gateways.validate_entry("-bad", {"host": "h", "connection": "c"})


def test_nothing_is_touched_without_accepted_terms(gw, tmp_path):
    _register(tmp_path)
    pv, _ = _fix(tmp_path)
    assert pv["stage"] == "consent" and "not been accepted" in pv["error"]
    assert gw.ssh_calls == [] and gw.fs["gw:office-a"][CONF] == GW_CONF


def test_acceptance_needs_the_exact_sentence_and_a_name(gw, tmp_path):
    _register(tmp_path)
    assert not execute.accept_terms("gw:office-a", "I accept", "tester", tmp_path)["ok"]
    assert not execute.accept_terms("gw:office-a", gateways.accept_phrase("office-a"), " ", tmp_path)["ok"]
    assert not execute.accept_terms("gw:office-a", gateways.accept_phrase("office-a"), "t", tmp_path, terms_sha256="0" * 64)["ok"]
    assert execute.accept_terms("gw:office-a", gateways.accept_phrase("office-a"), "tester", tmp_path)["ok"]


def test_changed_definition_or_terms_or_withdrawal_needs_new_acceptance(gw, tmp_path, monkeypatch):
    _register(tmp_path)
    _accept(tmp_path, "office-a")
    g = gateways.get("gw:office-a", tmp_path)
    assert gateways.consent_status(g, tmp_path)["accepted"]
    execute.save_gateway("office-a", {"host": "192.168.77.12", "connection": "office-link", "config_globs": [CONF]}, tmp_path)
    assert "definition changed" in gateways.consent_status(gateways.get("gw:office-a", tmp_path), tmp_path)["reason"]
    _register(tmp_path)
    _accept(tmp_path, "office-a")
    monkeypatch.setattr(gateways, "TERMS_SHA256", "f" * 64)
    assert "terms have changed" in gateways.consent_status(gateways.get("gw:office-a", tmp_path), tmp_path)["reason"]
    monkeypatch.undo()
    execute.withdraw_terms("gw:office-a", "tester", tmp_path)
    assert "withdrawn" in gateways.consent_status(gateways.get("gw:office-a", tmp_path), tmp_path)["reason"]


def test_apply_needs_the_per_change_sentence_and_the_preview_digest(gw, tmp_path):
    _register(tmp_path)
    _accept(tmp_path, "office-a", "office-b")
    pv, res = _fix(tmp_path, ack="APPLY IT")
    assert res["stage"] == "consent" and "APPLY V-207193 ON office-a" in res["error"]
    res = execute.apply_remediation("V-207193", "gw:office-a", confirm=True, history_dir=tmp_path,
                                    risk_ack="APPLY V-207193 ON office-a")
    assert res["decision"] == "refused" and "digest" in res["error"]
    assert gw.fs["gw:office-a"][CONF] == GW_CONF


# ------------------------------------------------------------------ the SSH path

def test_every_gateway_command_is_ssh_with_strict_options_and_quoted_words(gw, tmp_path):
    _register(tmp_path, peer="office-b")
    _accept(tmp_path, "office-a", "office-b")
    _fix(tmp_path)
    assert gw.ssh_calls
    for c in gw.ssh_calls:
        assert c[0] == "ssh" and "BatchMode=yes" in c and "StrictHostKeyChecking=yes" in c and "--" in c
    g = gateways.get("gw:office-a", tmp_path)
    cmd = execute.remote_command(g, ["sed", "-i", "-E", "s/a b;rm -rf //", "/etc/x.conf"])
    assert shlex.split(cmd) == ["sed", "-i", "-E", "s/a b;rm -rf //", "/etc/x.conf"]


def test_confirmed_fix_changes_only_the_registered_connection_on_both_ends(gw, tmp_path):
    _register(tmp_path, peer="office-b")
    _accept(tmp_path, "office-a", "office-b")
    pv, res = _fix(tmp_path)
    assert pv["live"]["peer"] == "office-b" and pv["clone_check"]["ok"] and gw.load_checks >= 2
    assert res["confirmed_fixed"] is True and res["verdict_after"] == "PASS", res
    # what is recorded is what really ran on the gateway, not the lab form of the plan
    assert res["commands_run"] and all("t-tun" not in c and "/tmp/exp15" not in c for c in res["commands_run"])
    assert "office-link" in res["commands_run"][0] and CONF in res["commands_run"][0]
    for key in ("gw:office-a", "gw:office-b"):
        text = gw.fs[key][CONF]
        assert "proposals = aes256-sha256-modp4096" in text
        assert "proposals = aes128-sha256-modp2048" in text        # backup-link untouched
        assert not any(k.endswith(execute.SNAP_SUFFIX) for k in gw.fs[key]) and execute.MANIFEST not in gw.fs[key]


def test_failed_verification_rolls_back_byte_for_byte(monkeypatch, tmp_path):
    lab = FakeGateways(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "UNKNOWN"}))
    lab.install(monkeypatch, tmp_path)
    _register(tmp_path)
    _accept(tmp_path, "office-a")
    _, res = _fix(tmp_path)
    assert res["confirmed_fixed"] is False and res["rolled_back"] is True and res["rollback_verified"] is True
    assert lab.fs["gw:office-a"][CONF] == GW_CONF


def test_watchdog_restore_on_a_gateway_is_detected(monkeypatch, tmp_path):
    lab = FakeGateways(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "PASS"}))
    lab.install(monkeypatch, tmp_path)
    lab.before_verify = lambda l: l.fire_watchdog("gw:office-a")
    _register(tmp_path)
    _accept(tmp_path, "office-a")
    _, res = _fix(tmp_path)
    assert res["verdict_after"] == "REVERTED_BY_WATCHDOG" and res["confirmed_fixed"] is False
    assert lab.fs["gw:office-a"][CONF] == GW_CONF
    assert lab.watchdogs and lab.watchdogs[0][0] == "gw:office-a"


def test_tab_indented_connection_is_found_and_a_missing_one_is_refused(monkeypatch, tmp_path):
    """The range is built from how the connection is really written (here: tabs). The fake loader
    only reads 4-space configs, so this checks the rewritten sed script itself on the text."""
    from tests.fake_lab import run_sed
    from tunnelscope.remediate import plan
    lines = GW_CONF.replace("    office-link {", "\toffice-link {", 1).splitlines()
    close = next(i for i, l in enumerate(lines) if l == "    }" and i > 1)
    lines[close] = "\t}"
    tabbed = "\n".join(lines) + "\n"
    lab = FakeGateways(conf=tabbed)
    lab.install(monkeypatch, tmp_path)
    _register(tmp_path)
    execute._CTX.history_dir = tmp_path
    script = execute._script_for("gw:office-a", plan.sed_script_of(plan.plan_for("V-207193", include_exec=True)["exec_commands"][0]))
    assert script.startswith("/^\toffice-link[[:space:]]*\\{/,/^\t\\}/")
    after = run_sed(script, tabbed)
    assert "proposals = aes256-sha256-modp4096" in after and "proposals = aes128-sha256-modp2048" in after
    execute.save_gateway("office-a", {"host": "192.168.77.10", "connection": "no-such-link", "config_globs": [CONF]}, tmp_path)
    _accept(tmp_path, "office-a", "office-b")
    pv, _ = _fix(tmp_path)
    assert pv["ok"] is False and pv["stage"] == "dry_run" and "not found" in pv["error"]


def test_ai_drafts_need_the_gateway_to_allow_them(gw, tmp_path):
    # DEC-064: AI drafts are allowed by default, so a gateway that must refuse them opts out explicitly.
    from tunnelscope.remediate import generate
    _register(tmp_path, allow_ai_drafts=False)
    _accept(tmp_path, "office-a")
    r = generate.generate_plan("RFC8247-ENCR", "gw:office-a", history_dir=tmp_path, force=True)
    assert r["ok"] is False and "allow_ai_drafts" in r["reason"]


# ------------------------------------------------------------------ server endpoints

def test_terms_endpoints(monkeypatch, tmp_path):
    from tunnelscope.api import server
    monkeypatch.setattr(server, "HISTORY_DIR", str(tmp_path))
    _register(tmp_path)
    srv = server.make_server(0)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        t = json.loads(urllib.request.urlopen(base + "/api/remediate/terms").read())
        assert t["sha256"] == gateways.TERMS_SHA256 and len(t["clauses"]) >= 5

        def post(path, body):
            req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            return json.loads(urllib.request.urlopen(req).read())
        with pytest.raises(urllib.error.HTTPError) as e:
            post("/api/remediate/terms/accept", {"target": "gw:office-a", "typed": "ok", "accepted_by": "t"})
        assert e.value.code == 400
        r = post("/api/remediate/terms/accept", {"target": "gw:office-a", "typed": gateways.accept_phrase("office-a"),
                                                 "accepted_by": "tester", "terms_sha256": t["sha256"]})
        assert r["ok"]
        tg = json.loads(urllib.request.urlopen(base + "/api/remediate/targets").read())
        a = next(g for g in tg["gateways"] if g["name"] == "gw:office-a")
        assert a["accepted"] is True
    finally:
        srv.shutdown()
        srv.server_close()
