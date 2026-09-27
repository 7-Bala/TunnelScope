"""T-121 / EXP-28: config vs wire. No false alarm on the configs that produced the captures; drift in an
observable field is a mismatch; what the wire cannot see is never a match."""
import copy
from pathlib import Path

import pytest

from tunnelscope.config import parse_file
from tunnelscope.config.reconcile import (CONSISTENT, MATCH, MISMATCH, NOT_COMPARABLE, pick_tunnel, reconcile)
from tunnelscope.evidence.extract import build_records

ROOT = Path(__file__).resolve().parents[1]
CONFIGS, CAPS = ROOT / "testbed" / "configs", ROOT / "testbed" / "captures"


def _rec(path):
    return next(r for r in build_records(str(CAPS / path)) if getattr(r, "_ike", []))


def _tunnel(cfg, name):
    return next(t for t in parse_file(CONFIGS / cfg)["tunnels"] if t["name"] == name)


def _out(comps, field):
    return next(c for c in comps if c.field == field)


def test_no_false_alarm_on_the_configs_that_made_the_captures():
    caps = {p.stem: p for p in CAPS.rglob("*.pcap")}
    n = 0
    for cf in sorted(p for p in CONFIGS.rglob("*.conf") if p.name != "strongswan.conf"):
        for t in parse_file(cf)["tunnels"]:
            if t["name"] in caps:
                rec = next(r for r in build_records(str(caps[t["name"]])) if getattr(r, "_ike", []))
                comps = reconcile(t, rec)
                assert not [c for c in comps if c.outcome == MISMATCH], (cf, t["name"])
                assert not [c for c in comps if c.outcome in (MATCH, CONSISTENT) and c.wire is None], (cf, t["name"])
                n += 1
    assert n >= 90


@pytest.mark.parametrize("field,change", [
    ("ike_dh_group", lambda t: [p.update(ke=["ECP-384"]) for p in t["ike_proposals"]]),
    ("ike_encr", lambda t: [p.update(encr=["AES-CBC-128"]) for p in t["ike_proposals"]]),
    ("pq_key_exchange", lambda t: [p.update(addke={1: ["ML-KEM-768"]}) for p in t["ike_proposals"]]),
])
def test_one_changed_ike_field_is_a_mismatch(field, change):
    rec = _rec("cs-aes256gcm16.pcap")
    t = copy.deepcopy(_tunnel("alice/swanctl.conf", "cs-aes256gcm16"))
    change(t)
    assert _out(reconcile(t, rec), field).outcome == MISMATCH


def test_pfs_drift_is_caught_where_a_rekey_shows_it():
    rec = _rec("rekey-cs-pfs-on-aes256gcm16-run2.pcap")
    t = copy.deepcopy(_tunnel("alice/swanctl.conf", "cs-pfs-on-aes256gcm16"))
    assert _out(reconcile(t, rec), "pfs").outcome == CONSISTENT        # inferred from size: never "match"
    t["children"][0]["pfs"] = False
    assert _out(reconcile(t, rec), "pfs").outcome == MISMATCH


def test_ppk_drift_on_the_initiator_and_not_comparable_for_the_responder():
    rec = _rec("exp27/ppk-k0.pcap")
    t = copy.deepcopy(_tunnel("exp27/alice-k0.conf", "ppk-k0"))
    t["ppk"] = {"id": "x", "required": False}
    assert _out(reconcile(t, rec), "pq_ppk").outcome == MISMATCH
    b = copy.deepcopy(_tunnel("exp27/bob-k0.conf", "ppk-k0"))
    b["ppk"] = {"id": "x", "required": False}
    assert _out(reconcile(b, rec), "pq_ppk").outcome == NOT_COMPARABLE


def test_esp_key_length_is_never_compared():
    rec = _rec("cs-aes256gcm16.pcap")
    t = copy.deepcopy(_tunnel("alice/swanctl.conf", "cs-aes256gcm16"))
    t["children"][0]["esp_proposals"][0]["encr"] = ["AES-GCM-16-128"]
    comps = reconcile(t, rec)
    assert _out(comps, "esp_key_length").outcome == NOT_COMPARABLE
    assert not [c for c in comps if c.outcome == MISMATCH]


def test_esp_family_inside_the_sieve_set_is_consistent_never_match():
    """EXP-28: GCM configured on CBC+HMAC traffic cannot be ruled out by packet geometry."""
    rec = _rec("cs-aes256cbc-sha256.pcap")
    t = copy.deepcopy(_tunnel("alice/swanctl.conf", "cs-aes256cbc-sha256"))
    t["children"][0]["esp_proposals"] = [{**t["children"][0]["esp_proposals"][0], "encr": ["AES-GCM-16-256"], "integ": []}]
    assert _out(reconcile(t, rec), "esp_cipher_family").outcome == CONSISTENT


def test_ambiguous_addresses_need_a_connection_name():
    rec = _rec("cs-aes256gcm16.pcap")
    tunnels = parse_file(CONFIGS / "alice" / "swanctl.conf")["tunnels"]
    t, why = pick_tunnel(tunnels, rec)
    assert t is None and "--conn" in why
    assert pick_tunnel(tunnels, rec, "cs-aes256gcm16")[0]["name"] == "cs-aes256gcm16"


def test_cli_exit_codes():
    from tunnelscope.cli import main
    cap, conf = str(CAPS / "exp27" / "ppk-k0.pcap"), str(CONFIGS / "exp27")
    assert main(["reconcile", cap, f"{conf}/alice-k0.conf", "--conn", "ppk-k0"]) == 0
    assert main(["reconcile", cap, f"{conf}/alice-k1.conf", "--conn", "ppk-k1"]) == 3
    assert main(["reconcile", cap, f"{conf}/alice-k1.conf", "--conn", "nope"]) == 1
