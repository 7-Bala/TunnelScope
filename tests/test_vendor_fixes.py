"""T-123 / EXP-50: per-vendor fix templates (Libreswan, MikroTik RouterOS). Bars H1, H4, H5, H6 of experiments/exp50-vendor-fixes/PREREG.md.
The lab runs (H2, H3) are experiments/exp50-vendor-fixes/run_libreswan.py + analyze.py; the test at the end ties each template's `verification`
label to the committed lab result."""
import hashlib
import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from threading import Thread
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from tunnelscope.remediate import plan as P
from tunnelscope.remediate import vendors as V

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "vendor-docs"
ROS = json.loads((FIX / "routeros-ipsec.json").read_text())
LSW = json.loads((FIX / "libreswan-ipsec.conf.json").read_text())
GOLDEN = json.loads((FIX / "strongswan-plan-hashes.json").read_text())
LABELS = {"docs-only", "lab", "lab-device-state"}
CONFIG_RULES = ["V-207205", "V-207193", "V-207223", "RFC8247-DH-MUST", "RFC8247-DH-OFFER", "RFC8247-ENCR", "DST-PQ-KE", "DST-PQ-DOWNGRADE",
                "RFC4301-CONFIDENTIALITY", "RFC8221-AH-INTEG", "RFC8221-AH-LEGACY", "RFC8221-ESP-3DES"]


def _templates(vendor):
    return sorted(V.TEMPLATES[vendor].items())


# ---------------------------------------------------------------------------------------------- H1: every keyword is documented
ROS_CMD = re.compile(r"^(/ip ipsec (?:profile|peer|proposal|policy)) set \[ find ([^\]]+?) \] (.+)$")


@pytest.mark.parametrize("rule,t", _templates("mikrotik"))
def test_every_routeros_setting_and_value_is_in_the_vendors_documentation(rule, t):
    for cmd in t["commands"]:
        m = ROS_CMD.match(cmd)
        assert m, (rule, cmd)
        menu, finder, settings = m.groups()
        pairs = [tuple(x.split("=", 1)) for x in settings.split()]
        if "=" in finder and not finder.startswith("name="):            # a finder on a setting (policies have no name)
            pairs.append(tuple(finder.split("=", 1)))
        assert pairs, cmd
        for name, value in pairs:
            assert name in ROS["settings"], (rule, name)
            for v in value.split(","):
                assert v in ROS["settings"][name], (rule, name, v, ROS["settings"][name])


@pytest.mark.parametrize("rule,t", _templates("libreswan"))
def test_every_libreswan_keyword_is_in_the_manual_or_was_run_in_the_lab(rule, t):
    for state in ("example_before", "example_after"):
        for key, value in t[state].items():
            assert key in LSW["keywords"], (rule, key)
            assert value is None or re.fullmatch(r"[a-z0-9_.;,=+-]+", value), (rule, key, value)
    inline = " ".join(str(v) for k, v in t["example_after"].items() if v)
    for opt in re.findall(r";([a-z0-9]+)=", inline):                    # options inside ike=: addke1 etc.
        assert opt in LSW["keywords"] or opt in LSW["lab_only"], (rule, opt)
    text = " ".join(t["commands"])
    for k, v in t["example_after"].items():
        assert (f"{k}={v}" in text) if v is not None else (k in text), (rule, k)


def test_the_fixtures_are_the_pages_that_were_hashed():
    assert re.fullmatch(r"[0-9a-f]{64}", ROS["page_sha256"]) and re.fullmatch(r"[0-9a-f]{64}", LSW["page_sha256"])
    assert ROS["retrieved"] == LSW["retrieved"] == "2026-10-05"
    assert "keyexchange" in LSW["keywords"] and "hash-algorithm" in ROS["settings"]


def test_routeros_has_no_sha384_so_the_integrity_fix_is_sha512_not_a_copy_of_the_strongswan_fix():
    assert "sha384" not in ROS["settings"]["hash-algorithm"] and "sha384" not in ROS["settings"]["auth-algorithms"]
    t = V.TEMPLATES["mikrotik"]["V-207223"]
    assert t["edits"][0]["set"] == {"hash-algorithm": "sha512"}
    assert "sha384" not in " ".join(t["commands"]).lower()


# ---------------------------------------------------------------------------------------------- H5: nothing invented
@pytest.mark.parametrize("vendor", ["libreswan", "mikrotik"])
@pytest.mark.parametrize("rule", sorted(P.REMEDIATION))
def test_every_rule_has_a_template_with_provenance_or_a_reason_never_neither(vendor, rule):
    p = P.plan_for(rule, detailed=True, vendor=vendor)
    assert p["vendor"] == vendor and p["source"] and p["automated_fix_available"] is False and p["auto_applicable"] is False
    if p["template"]:
        assert p["verification"] in LABELS and p["commands"] and p["verify"] and p["config_diff"] and p["why"]
    else:
        assert p["commands"] == [] and p["verification"] is None and len(p["reason"]) > 20


def test_the_five_patch_rules_get_no_template_and_make_no_version_claim():
    for vendor in ("libreswan", "mikrotik"):
        for rule in V.PATCH_RULES:
            p = P.plan_for(rule, vendor=vendor)
            assert not p["template"] and "advisories" in p["reason"] and not re.search(r"\d+\.\d+", p["reason"])


def test_the_twelve_config_rules_are_all_decided_for_both_vendors():
    for vendor in ("libreswan", "mikrotik"):
        decided = set(V.TEMPLATES[vendor]) | set(V.NO_TEMPLATE[vendor])
        assert set(CONFIG_RULES) <= decided, sorted(set(CONFIG_RULES) - decided)
        assert not set(V.TEMPLATES[vendor]) & set(V.PATCH_RULES)


def test_routeros_has_no_post_quantum_template_because_its_documentation_lists_none():
    assert not any(re.search(r"ml-?kem|kyber|pqc|post-quantum", json.dumps(v)) for v in ROS["settings"].values())
    for rule in ("DST-PQ-KE", "DST-PQ-DOWNGRADE"):
        p = P.plan_for(rule, vendor="mikrotik")
        assert not p["template"] and "post-quantum" in p["reason"]


def test_libreswan_pq_template_adds_ml_kem_through_addke1_with_intermediate_and_fragmentation():
    a = V.TEMPLATES["libreswan"]["DST-PQ-KE"]["example_after"]
    assert "addke1=ml_kem_768" in a["ike"] and a["intermediate"] == "yes" and a["fragmentation"] == "yes"


def test_libreswan_ikev2_fix_uses_the_keyword_the_manual_says_replaced_ikev2_equals():
    assert V.TEMPLATES["libreswan"]["V-207205"]["example_after"] == {"keyexchange": "ikev2"}
    assert "ikev1-policy" in " ".join(V.TEMPLATES["libreswan"]["V-207205"]["commands"])
    assert "ikev1-policy" in LSW["keywords"]


def test_libreswan_reload_line_is_the_one_that_ran_on_the_lab_pair_not_the_deprecated_one():
    for rule, t in _templates("libreswan"):
        assert t["commands"][-1] == "ipsec replace <conn>" and "ipsec auto" not in " ".join(t["commands"])


# ---------------------------------------------------------------------------------------------- H4: strongSwan untouched
@pytest.mark.parametrize("vendor", [None, "strongswan"])
@pytest.mark.parametrize("rule", sorted(P.REMEDIATION))
def test_strongswan_plans_are_byte_identical_to_the_pinned_hashes_from_the_base_code(vendor, rule):
    for flags in ((False, False), (True, True)):
        j = json.dumps(P.plan_for(rule, observed="x", include_exec=flags[0], detailed=flags[1], vendor=vendor), sort_keys=True)
        assert hashlib.sha256(j.encode()).hexdigest() == GOLDEN[f"{rule}|{int(flags[0])}{int(flags[1])}"], (rule, flags)


def test_the_golden_file_covers_every_rule_and_both_call_shapes():
    assert set(GOLDEN) == {f"{r}|{a}" for r in P.REMEDIATION for a in ("00", "11")}


# ---------------------------------------------------------------------------------------------- H6: unknown vendor is an error
def test_unknown_vendor_is_an_error_naming_the_supported_ones_never_the_old_answer():
    for bad in ("cisco", "", "StrongSwan", "libreswan "):
        with pytest.raises(ValueError, match="supported: strongswan, libreswan, mikrotik"):
            P.plan_for("V-207205", vendor=bad)


def test_unknown_rule_is_none_for_every_vendor():
    for vendor in (None, "strongswan", "libreswan", "mikrotik"):
        assert P.plan_for("NOT-A-RULE", vendor=vendor) is None


def _serve():
    from tunnelscope.api.server import make_server
    srv = make_server(0)
    Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _post(srv, body):
    req = Request(f"http://127.0.0.1:{srv.server_port}/api/remediate/plan", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except HTTPError as e:
        return e.code, json.loads(e.read())


def test_the_api_takes_a_vendor_and_rejects_an_unknown_or_non_string_one():
    srv = _serve()
    try:
        code, j = _post(srv, {"rule_id": "V-207223", "vendor": "mikrotik"})
        assert code == 200 and j["vendor"] == "mikrotik" and "sha512" in " ".join(j["commands"])
        code, j = _post(srv, {"rule_id": "V-207223"})
        assert code == 200 and "vendor" not in j
        code, j = _post(srv, {"rule_id": "V-207223", "vendor": "cisco"})
        assert code == 400 and "supported" in j["error"]
        code, j = _post(srv, {"rule_id": "V-207223", "vendor": 7})
        assert code == 400
        code, j = _post(srv, {"rule_id": "NOT-A-RULE", "vendor": "libreswan"})
        assert code == 404
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------------------------- the labels match the committed lab result
def test_a_template_is_labelled_lab_only_if_the_committed_lab_run_passed_for_that_rule():
    f = ROOT / "experiments" / "exp50-vendor-fixes" / "results" / "summary-libreswan.json"
    if not f.exists():
        pytest.skip("lab result not committed yet")
    res = json.loads(f.read_text())["rules"]
    for rule, t in V.TEMPLATES["libreswan"].items():
        want = ("lab" if res[rule]["pass"] else "lab-device-state" if res[rule].get("pass_device_state") else "docs-only")
        assert t["verification"] == want, (rule, t["verification"], want)
    for rule, t in V.TEMPLATES["mikrotik"].items():
        assert t["verification"] == "docs-only", rule              # no RouterOS device run in this experiment (PREREG H3)
