"""Tests for the owner decisions of 2026-10-04: TH-07 wording, the INFORMATIONAL detector without an IKE_AUTH,
ledger signing, and rephrasing through a hosted model with addresses masked (DEC-055)."""
import hashlib
import json

import pytest

from tunnelscope.evidence.extract import detect_informational_before_auth
from tunnelscope.evidence.record import EvidenceRecord, Finding, Status, Vantage

CLASSICAL = "testbed/captures/classical-baseline-6.1.0.pcap"


# ---------------------------------------------------------------- TH-07
def _threat(protocols, tid="TH-07"):
    from tunnelscope.assess.engine import assess_record
    from tunnelscope.risk import risk as rk
    r = EvidenceRecord(src="a", dst="b")
    r.add(Finding("ipsec_protocols", Status.OBSERVED, Vantage.T0, "protocol_id", value=protocols))
    return {t.id: t for t in rk.threats(r, assess_record(r))}[tid]


def test_esp_in_use_is_never_called_confidentiality_mitigated():
    t = _threat(["ESP"])
    assert t.status == "not_seen" and "NULL" in t.reason


def test_ah_only_is_still_a_present_confidentiality_threat():
    assert _threat(["AH"]).status == "present"


# ---------------------------------------------------------------- INFORMATIONAL before auth, no IKE_AUTH captured
def _m(exchange, frame, mid, response=False, initiator=True):
    return dict(exchange=exchange, frame=frame, message_id=mid, is_response=response, is_initiator=initiator)


def test_informational_directly_after_init_with_no_auth_is_detected():
    ike = [_m(34, 1, 0), _m(34, 2, 0, response=True, initiator=False), _m(37, 3, 1)]
    assert detect_informational_before_auth(ike)[0] == "informational-before-auth"


def test_informational_with_a_message_id_gap_and_no_auth_is_unknown():
    """msgid 2 after msgid 0: an IKE_AUTH (msgid 1) may have been sent and not captured."""
    ike = [_m(34, 1, 0), _m(34, 2, 0, response=True, initiator=False), _m(37, 3, 2)]
    v, note = detect_informational_before_auth(ike)
    assert v is None and "not proven" in note


def test_informational_from_the_responder_with_no_auth_is_unknown():
    ike = [_m(34, 1, 0), _m(34, 2, 0, response=True, initiator=False), _m(37, 3, 0, initiator=False)]
    assert detect_informational_before_auth(ike)[0] is None


# ---------------------------------------------------------------- ledger signing
def _forge(led):
    """Flip every FAIL to PASS and recompute the whole chain: needs no secret."""
    canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    led = json.loads(json.dumps(led)); prev = "0" * 64
    for e in led["entries"]:
        if e["kind"] == "verdict" and e["data"].get("verdict") == "FAIL":
            e["data"]["verdict"] = "PASS"
        e["prev"] = prev
        e["hash"] = hashlib.sha256(canon({k: e[k] for k in ("seq", "kind", "data", "prev")}).encode()).hexdigest()
        prev = e["hash"]
    led["head"] = prev
    return led


def test_signed_ledger_detects_a_rebuilt_chain():
    from tunnelscope.ledger import build_ledger, sign_ledger, verify_ledger
    key = b"k" * 64
    led = sign_ledger(build_ledger(CLASSICAL), key)
    assert verify_ledger(led, key=key)["ok"]
    forged = _forge(led)
    assert verify_ledger(forged)["ok"]                         # the chain alone cannot tell
    r = verify_ledger(forged, key=key)
    assert not r["ok"] and "signature" in r["reason"]
    assert not verify_ledger(led, key=b"x" * 64)["ok"]         # another key
    assert not verify_ledger(build_ledger(CLASSICAL), key=key)["ok"]   # a key was given, the ledger is unsigned


def test_ledger_key_on_the_command_line(tmp_path, capsys):
    from tunnelscope.cli import main
    led, key = tmp_path / "led.json", tmp_path / "ledger.key"
    assert main(["ledger", CLASSICAL, "-o", str(led), "--key", str(key)]) == 0
    assert key.exists() and (key.stat().st_mode & 0o077) == 0           # created, owner-only
    capsys.readouterr()
    assert main(["ledger-verify", str(led), "--key", str(key)]) == 0
    assert "signature matches" in capsys.readouterr().out
    assert main(["ledger-verify", str(led)]) == 0
    assert "pass --key" in capsys.readouterr().out
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(_forge(json.loads(led.read_text()))))
    assert main(["ledger-verify", str(forged), "--key", str(key)]) == 1


# ---------------------------------------------------------------- rephrase through a hosted model (DEC-055)
SENT = "This tunnel between 10.1.1.1 and 2001:db8::2 was checked against 12 rules: 3 passed, 2 failed."


class FakeClient:
    """Stands in for a hosted model: records what it was sent, answers with `reply(blocks)`."""
    PROVIDER = "fake"

    def __init__(self, reply):
        self.reply, self.seen = reply, []

    def available(self):
        return True

    def generate_json(self, system, blocks, **kw):
        self.seen.append((system, dict(blocks)))
        return json.dumps(self.reply(blocks)), {"backend": "fake", "model_id": "fake-1", "reason": None}


def _use(monkeypatch, reply):
    from tunnelscope.rephrase import api
    c = FakeClient(reply)
    monkeypatch.setattr(api, "_clients", lambda: [(c, None)])
    return api, c


def test_addresses_never_leave_the_machine_and_come_back(monkeypatch):
    api, c = _use(monkeypatch, lambda b: {k: "In short: " + v for k, v in b.items()})
    out, meta = api.rephrase_many([SENT, "Rule V-207193 failed: MODP-2048 is below group 16 for 10.1.1.1."])
    sent = json.dumps(c.seen)
    assert "10.1.1.1" not in sent and "2001:db8::2" not in sent and "ADDR_1" in sent
    assert out[0] == "In short: " + SENT                       # placeholders restored
    assert "10.1.1.1" in out[1] and meta["kept"] == 2 and meta["model_id"] == "fake-1"
    assert c.seen[0][1]["TEXT_2"].count("ADDR_1") == 1         # the same address keeps the same placeholder


@pytest.mark.parametrize("damage", [
    lambda v: v.replace("ADDR_1", "the first site"),            # a placeholder dropped
    lambda v: v + " ADDR_1",                                    # a placeholder repeated
    lambda v: v.replace("12 rules", "13 rules"),                # a number changed
    lambda v: v.replace("ADDR_2", "192.0.2.9"),                 # an address invented
    lambda v: v + " The tunnel is compliant.",                  # a compliance claim added
    lambda v: v,                                                # nothing reworded
])
def test_a_reply_that_changes_any_fact_is_discarded(monkeypatch, damage):
    api, _ = _use(monkeypatch, lambda b: {k: damage(v if damage(v) == v else "In short: " + v) for k, v in b.items()})
    out, _ = api.rephrase_many([SENT])
    assert out == [None]


def test_a_reply_that_is_not_json_or_fails_keeps_the_template(monkeypatch):
    from tunnelscope.rephrase import api

    class Broken(FakeClient):
        def generate_json(self, system, blocks, **kw):
            return "sorry, I cannot do that", {"backend": "fake", "model_id": "fake-1", "reason": None}
    monkeypatch.setattr(api, "_clients", lambda: [(Broken(None), None)])
    out, meta = api.rephrase_many([SENT])
    assert out == [None] and "JSON" in meta["reason"]


def test_typographic_hyphens_do_not_hide_or_fake_a_fact(monkeypatch):
    s = "V-207223 (medium): integrity is weaker than SHA-384 (seen: HMAC-SHA2-256-128)."
    api, _ = _use(monkeypatch, lambda b: {k: "Note: " + v.replace("-", "\u2011") for k, v in b.items()})
    out, _ = api.rephrase_many([s])
    assert out == ["Note: " + s]                                # same tokens once the hyphens are plain again
    api, _ = _use(monkeypatch, lambda b: {k: "Note: " + v.replace("SHA-384", "SHA\u2011512") for k, v in b.items()})
    assert api.rephrase_many([s])[0] == [None]                  # a changed algorithm is still caught


def test_a_sentence_one_model_gets_wrong_is_offered_to_the_next(monkeypatch):
    from tunnelscope.rephrase import api
    bad = FakeClient(lambda b: {k: v.replace("12 rules", "twelve rules") for k, v in b.items()})
    good = FakeClient(lambda b: {k: "In short: " + v for k, v in b.items()})
    monkeypatch.setattr(api, "_clients", lambda: [(bad, None), (good, None)])
    out, meta = api.rephrase_many([SENT])
    assert out == ["In short: " + SENT] and len(meta["attempts"]) == 2 and meta["attempts"][0]["kept"] == 0


def test_api_rephrase_sends_nothing_with_the_network_off_or_no_key(monkeypatch):
    from tunnelscope.rephrase import api
    for var in ("TUNNELSCOPE_GROQ_API_KEY", "TUNNELSCOPE_GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    out, meta = api.rephrase_many([SENT])                       # no key
    assert out == [None] and meta["sent"] == 0 and not api.available()
    monkeypatch.setenv("TUNNELSCOPE_GROQ_API_KEY", "k" * 40)
    monkeypatch.setenv("TUNNELSCOPE_NETWORK", "off")            # a key, but the operator switched the network off
    out, meta = api.rephrase_many([SENT])
    assert out == [None] and meta["sent"] == 0 and "network is off" in meta["reason"]
    assert api.backend() == "local"
    monkeypatch.setenv(api.BACKEND_ENV, "api")
    assert api.backend() == "api"


def test_explanation_uses_the_api_only_when_chosen_and_says_so(monkeypatch):
    from tunnelscope.api.server import analysis_json
    from tunnelscope.explain.explain import as_text, explain_sa
    from tunnelscope.report.report import analyze
    api, c = _use(monkeypatch, lambda b: {k: "In short: " + v for k, v in b.items()})
    sa = analysis_json(analyze(CLASSICAL), "c.pcap")["sas"][0]
    assert c.seen == [] and "summary_rephrased" not in sa["explanation"]      # default: nothing is sent
    e = explain_sa(sa, api_llm=True)
    assert e["rephrase_source"] == "api" and e["summary_rephrased"].startswith("In short: ")
    assert sa["src"] in e["summary_rephrased"] and sa["src"] not in json.dumps(c.seen)
    assert e["summary"] == sa["explanation"]["summary"]                        # the template text is untouched
    text = as_text(e)
    assert "(rephrased by an API model:" in text and "rephrased locally" not in text
