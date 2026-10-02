"""T-155 / DEC-053: the evidence ledger is deterministic and catches every kind of after-the-fact change."""
import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from tunnelscope import cli
from tunnelscope.ledger import build_ledger, verify_ledger
from tunnelscope.ledger.ledger import _canon

CAP = Path(__file__).resolve().parent.parent / "testbed" / "captures" / "classical-baseline-6.1.0.pcap"
OTHER = Path(__file__).resolve().parent.parent / "testbed" / "captures" / "exp40" / "e40-m-3des-sha1-g5.pcap"


@pytest.fixture(scope="module")
def led():
    return build_ledger(str(CAP))


def _first(led, kind):
    return next(i for i, e in enumerate(led["entries"]) if e["kind"] == kind)


def test_it_binds_the_capture_and_holds_findings_and_verdicts(led):
    e0 = led["entries"][0]
    assert e0["kind"] == "capture" and e0["data"]["pcap_sha256"] == hashlib.sha256(CAP.read_bytes()).hexdigest()
    kinds = {e["kind"] for e in led["entries"]}
    assert kinds == {"capture", "finding", "verdict"}
    assert verify_ledger(led)["ok"] and verify_ledger(led, pcap=str(CAP))["ok"]


def test_same_capture_same_ledger_wherever_it_lives(led, tmp_path):
    moved = tmp_path / "elsewhere" / CAP.name
    moved.parent.mkdir()
    shutil.copy(CAP, moved)
    assert build_ledger(str(moved))["head"] == led["head"]


@pytest.mark.parametrize("how", ["value", "note", "status", "verdict"])
def test_changing_any_entry_is_caught_at_that_entry(led, how):
    t = copy.deepcopy(led)
    i = _first(t, "verdict" if how == "verdict" else "finding")
    d = t["entries"][i]["data"]
    if how == "value":
        d["value"] = "tampered"
    elif how == "note":
        d["note"] = (d.get("note") or "") + " (edited)"
    elif how == "status":
        d["status"] = "OBSERVED" if d["status"] != "OBSERVED" else "UNKNOWN"
    else:
        d["verdict"] = "PASS" if d["verdict"] != "PASS" else "FAIL"
    r = verify_ledger(t)
    assert not r["ok"] and r["first_bad"] == i


def test_a_forger_who_rehashes_one_entry_breaks_the_next_link(led):
    t = copy.deepcopy(led)
    i = _first(t, "finding")
    e = t["entries"][i]
    e["data"]["value"] = "tampered"
    e["hash"] = hashlib.sha256(_canon({k: e[k] for k in ("seq", "kind", "data", "prev")}).encode()).hexdigest()
    r = verify_ledger(t)
    assert not r["ok"] and r["first_bad"] == i + 1


def test_a_forger_who_rehashes_everything_is_caught_by_reanalysis(led):
    t = copy.deepcopy(led)
    d = t["entries"][_first(t, "verdict")]["data"]
    d["verdict"] = "FAIL" if d["verdict"] == "PASS" else "PASS"     # a real change, whatever it was
    prev = "0" * 64
    for e in t["entries"]:
        e["prev"] = prev
        e["hash"] = hashlib.sha256(_canon({k: e[k] for k in ("seq", "kind", "data", "prev")}).encode()).hexdigest()
        prev = e["hash"]
    t["head"] = prev
    assert verify_ledger(t)["ok"]                                   # internally consistent ...
    r = verify_ledger(t, pcap=str(CAP), reanalyse=True)              # ... but not what this capture gives
    assert not r["ok"] and "re-analysing" in r["reason"]


def test_removing_inserting_reordering_and_trimming_are_caught(led):
    removed = copy.deepcopy(led); del removed["entries"][3]
    assert not verify_ledger(removed)["ok"]
    swapped = copy.deepcopy(led); swapped["entries"][2], swapped["entries"][3] = swapped["entries"][3], swapped["entries"][2]
    assert not verify_ledger(swapped)["ok"]
    trimmed = copy.deepcopy(led); trimmed["entries"] = trimmed["entries"][:-2]
    r = verify_ledger(trimmed)
    assert not r["ok"] and "head" in r["reason"]


def test_a_different_capture_does_not_match(led):
    r = verify_ledger(led, pcap=str(OTHER))
    assert not r["ok"] and "SHA-256" in r["reason"]


def test_cli_exit_codes(led, tmp_path, capsys):
    good = tmp_path / "l.json"
    good.write_text(json.dumps(led))
    assert cli.main(["ledger-verify", str(good), "--pcap", str(CAP)]) == 0
    t = copy.deepcopy(led); t["entries"][_first(t, "finding")]["data"]["value"] = "x"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(t))
    assert cli.main(["ledger-verify", str(bad)]) == 1
    assert "TAMPERED" in capsys.readouterr().out


def test_deleting_an_entry_and_rehashing_the_rest_is_caught_without_the_capture(led):
    """The forger removes one verdict and re-links everything after it; with no capture to re-analyse, the gap in the
    sequence numbers is what gives it away."""
    t = copy.deepcopy(led)
    del t["entries"][_first(t, "verdict")]
    prev = "0" * 64
    for e in t["entries"]:
        e["prev"] = prev
        e["hash"] = hashlib.sha256(_canon({k: e[k] for k in ("seq", "kind", "data", "prev")}).encode()).hexdigest()
        prev = e["hash"]
    t["head"] = prev
    r = verify_ledger(t)
    assert not r["ok"] and "sequence" in r["reason"]
