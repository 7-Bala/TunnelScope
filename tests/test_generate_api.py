"""T-104: generated plans are stored write-once under their content address, re-checked from
their raw draft before any preview or apply, and reachable through the API only when the
generator is switched on. In-memory lab + scripted model."""
import json
import threading
import urllib.error
import urllib.request

import pytest
from fake_lab import FakeLab, sas
from fake_model import FakeModel, answer

from tunnelscope.api import server
from tunnelscope.remediate import execute
from tunnelscope.remediate import generate as gen

A, FA = "sih26-alice-pq", "/tmp/exp15-alice.conf"
GOOD = answer("proposals", [{"op": "replace", "from": "modp2048", "to": "ecp384"}], "proposals = aes256-sha256-ecp384")


@pytest.fixture
def lab(monkeypatch, tmp_path):
    return FakeLab(baseline=sas(**{"V-207193": "FAIL"}), verify=sas(**{"V-207193": "PASS"})).install(monkeypatch, tmp_path)


def _draft(monkeypatch):
    FakeModel([GOOD]).install(monkeypatch)
    r = gen.generate_plan("V-207193", A, compare_with_handwritten=True)
    assert r["ok"], r
    return r["plan"]


def test_store_is_write_once_and_content_addressed(lab, monkeypatch, tmp_path):
    plan = _draft(monkeypatch)
    pid = execute.store_generated_plan(plan, A, tmp_path)
    assert len(pid) == 64 and execute.store_generated_plan(plan, A, tmp_path) == pid
    rec = execute.load_generated_plan(pid, tmp_path)
    assert rec["exec_commands"] == plan["exec_commands"] and rec["target"] == A
    other = execute.store_generated_plan({**plan, "exec_commands": plan["exec_commands"][:1]}, A, tmp_path)
    assert other != pid


def test_a_tampered_plan_file_is_refused(lab, monkeypatch, tmp_path):
    pid = execute.store_generated_plan(_draft(monkeypatch), A, tmp_path)
    path = tmp_path / execute.PLAN_STORE / f"{pid}.json"
    rec = json.loads(path.read_text())
    rec["exec_commands"][0] = rec["exec_commands"][0].replace("ecp384", "modp1024")
    path.write_text(json.dumps(rec))
    with pytest.raises(execute._Refusal) as e:
        execute.load_generated_plan(pid, tmp_path)
    assert e.value.stage == "plan_integrity"
    r = execute.apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, plan_id=pid)
    assert r["stage"] == "plan_integrity"


@pytest.mark.parametrize("bad", ["../../etc/passwd", "x" * 64, "", 7, "A" * 64])
def test_bad_plan_ids_are_refused(lab, tmp_path, bad):
    r = execute.apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, plan_id=bad)
    assert r["decision"] == "refused" and r["stage"] == "validate"
    assert lab.fs[A][FA].count("modp2048") == 1, "nothing changed"


def test_generated_plan_previews_and_applies_through_the_same_gate(lab, monkeypatch, tmp_path):
    plan = _draft(monkeypatch)
    pid = execute.store_generated_plan(plan, A, tmp_path)
    p = execute.preview_remediation("V-207193", A, history_dir=tmp_path, plan_id=pid)
    assert p["ok"] and p["source"] == "generated" and p["plan_id"] == pid
    hand = execute.preview_remediation("V-207193", A, history_dir=tmp_path)
    assert hand["digest"] != p["digest"], "a digest names which plan was approved"
    r = execute.apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, plan_id=pid,
                                  digest=p["digest"], require_digest=True)
    assert r["ok"] is True and r["commands_run"] == plan["exec_commands"]
    assert "ecp384" in lab.fs[A][FA] and "modp4096" not in lab.fs[A][FA]
    audit = [json.loads(l) for l in (tmp_path / "remediate.jsonl").read_text().splitlines()]
    applied = [x for x in audit if x.get("decision") == "applied"][-1]
    assert applied["source"] == "generated" and applied["plan_id"] == pid and applied["model_revision"] == "fake-rev"


def test_the_stored_draft_is_rechecked_not_trusted(lab, monkeypatch, tmp_path):
    pid = execute.store_generated_plan(_draft(monkeypatch), A, tmp_path)
    from tunnelscope.remediate import vocab
    real = vocab.kind
    monkeypatch.setattr(vocab, "kind", lambda t, c, v=None: None if t == "ecp384" else real(t, c, v))
    r = execute.apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, plan_id=pid)
    assert r["stage"] == "recheck" and "V4" in r["error"]


def test_a_plan_for_another_rule_or_container_is_refused(lab, monkeypatch, tmp_path):
    pid = execute.store_generated_plan(_draft(monkeypatch), A, tmp_path)
    assert execute.apply_remediation("V-207223", A, confirm=True, history_dir=tmp_path, plan_id=pid)["stage"] == "validate"
    assert execute.apply_remediation("V-207193", "sih26-bob-pq", confirm=True, history_dir=tmp_path, plan_id=pid)["stage"] == "validate"


# ------------------------------------------------------------------ the API

def _serve(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "HISTORY_DIR", str(tmp_path))
    srv = server.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def test_health_reports_the_model_and_the_switch(lab, monkeypatch, tmp_path):
    monkeypatch.delenv("TUNNELSCOPE_GENERATOR", raising=False)
    srv, base = _serve(monkeypatch, tmp_path)
    try:
        h = json.load(urllib.request.urlopen(base + "/api/remediate/capabilities"))
        assert isinstance(h["local_model"], bool) and h["generator_enabled"] is False
        monkeypatch.setenv("TUNNELSCOPE_GENERATOR", "1")
        assert json.load(urllib.request.urlopen(base + "/api/remediate/capabilities"))["generator_enabled"] is True
    finally:
        srv.shutdown()


def test_generate_is_off_by_default(lab, monkeypatch, tmp_path):
    monkeypatch.delenv("TUNNELSCOPE_GENERATOR", raising=False)
    m = FakeModel([GOOD]).install(monkeypatch)
    srv, base = _serve(monkeypatch, tmp_path)
    try:
        code, body = _post(base, "/api/remediate/generate", {"rule_id": "V-207193", "target": A})
        assert code == 403 and body["stage"] == "disabled" and m.calls == []
    finally:
        srv.shutdown()


def test_generate_preview_apply_over_http(lab, monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR", "1")
    FakeModel([GOOD, json.dumps({"addresses_rule": True, "breaks_something": False, "reason": "ok"})]).install(monkeypatch)
    srv, base = _serve(monkeypatch, tmp_path)
    try:
        code, g = _post(base, "/api/remediate/generate", {"rule_id": "V-207193", "target": A})
        assert code == 200 and g["ok"] is True, g
        pid, plan = g["plan_id"], g["plan"]
        assert plan["agrees_with_handwritten"] is False and plan["self_review"]["verdict"] == "no concerns"
        code, p = _post(base, "/api/remediate/preview", {"rule_id": "V-207193", "target": A, "plan_id": pid})
        assert code == 200 and p["digest"]
        code, r = _post(base, "/api/remediate/apply", {"rule_id": "V-207193", "target": A, "confirm": True, "plan_id": pid})
        assert code == 400 and r["stage"] == "validate" and "preview" in r["error"]
        code, r = _post(base, "/api/remediate/apply", {"rule_id": "V-207193", "target": A, "confirm": True,
                                                        "plan_id": pid, "digest": p["digest"]})
        assert code == 200 and r["ok"] is True and r["source"] == "generated"
        audit = [json.loads(l) for l in (tmp_path / "remediate.jsonl").read_text().splitlines()]
        assert [x["decision"] for x in audit if x.get("decision") in ("generate", "preview", "applied")][:3] == ["generate", "preview", "applied"]
    finally:
        srv.shutdown()


def test_generate_bad_input(lab, monkeypatch, tmp_path):
    monkeypatch.setenv("TUNNELSCOPE_GENERATOR", "1")
    srv, base = _serve(monkeypatch, tmp_path)
    try:
        assert _post(base, "/api/remediate/generate", {"rule_id": 5, "target": A})[0] == 400
        assert _post(base, "/api/remediate/generate", ["x"])[0] == 400
    finally:
        srv.shutdown()


def test_a_digest_names_the_plan_even_when_the_change_is_identical(lab, monkeypatch, tmp_path):
    """A draft that agrees with the hand-written fix makes the same diff. Approving the one must
    still not authorise the other: the audit would say the wrong thing about what was approved."""
    FakeModel([answer("proposals", [{"op": "replace", "from": "modp2048", "to": "modp4096"}],
                      "proposals = aes256-sha256-modp4096")]).install(monkeypatch)
    plan = gen.generate_plan("V-207193", A, compare_with_handwritten=True)["plan"]
    assert plan["agrees_with_handwritten"] is True
    pid = execute.store_generated_plan(plan, A, tmp_path)
    gen_preview = execute.preview_remediation("V-207193", A, history_dir=tmp_path, plan_id=pid)
    hand_preview = execute.preview_remediation("V-207193", A, history_dir=tmp_path)
    assert gen_preview["diff"] == hand_preview["diff"] and gen_preview["digest"] != hand_preview["digest"]
    r = execute.apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path, plan_id=pid, digest=hand_preview["digest"])
    assert r["stage"] == "stale_preview"
