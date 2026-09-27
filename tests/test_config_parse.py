"""T-120: IPsec configuration files -> normalised crypto model. The strongest check is independent: every lab
connection that has a capture of the same name must offer (in its config) exactly what the wire showed."""
import csv
from pathlib import Path

from tunnelscope.config import parse_config, parse_file
from tunnelscope.evidence.extract import build_records

ROOT = Path(__file__).resolve().parents[1]
CONFIGS, CAPS = ROOT / "testbed" / "configs", ROOT / "testbed" / "captures"


def _repo_configs():
    return [p for p in sorted(CONFIGS.rglob("*.conf")) if p.name != "strongswan.conf"]


def test_every_lab_config_parses_with_nothing_unknown():
    n = 0
    for p in _repo_configs():
        d = parse_file(p)
        assert d["format"] in ("strongswan-swanctl", "ipsec.conf"), p
        for t in d["tunnels"]:
            n += 1
            props = t["ike_proposals"] + [x for c in t["children"] for x in c["esp_proposals"] + c["ah_proposals"]]
            assert not t["unknown"] and not any(pr["unknown"] for pr in props), (p, t["name"])
    assert n >= 131


def test_config_matches_what_the_wire_showed():
    """Initiator configs vs TunnelScope's wire findings for the capture of the same name (50 connections)."""
    caps = {p.stem: p for p in CAPS.rglob("*.pcap")}
    seen, compared, bad = set(), 0, []
    for cf in _repo_configs():
        if "bob" in str(cf):
            continue
        for t in parse_file(cf)["tunnels"]:
            if t["name"] not in caps or t["name"] in seen:
                continue
            seen.add(t["name"])
            (r, *_) = [r for r in build_records(str(caps[t["name"]])) if getattr(r, "_ike", [])]
            offered = {k: {v for pr in t["ike_proposals"] for v in pr[k]} for k in ("encr", "integ", "prf", "ke")}
            for key, attr in (("encr", "ike_encr"), ("integ", "ike_integ"), ("prf", "ike_prf"), ("ke", "ike_dh_group")):
                v = r.findings[attr].value if attr in r.findings else None
                if v is not None:
                    compared += 1
                    if v not in offered[key]:
                        bad.append((t["name"], key, v, sorted(offered[key])))
    assert not bad, bad
    assert len(seen) >= 50 and compared >= 190


def test_esp_proposals_match_the_dataset_ground_truth():
    """dataset/MANIFEST.csv's causal ground truth for the classical arms vs the parsed esp_proposals."""
    tunnels = {t["name"]: t for t in parse_file(CONFIGS / "alice" / "swanctl.conf")["tunnels"]}
    fam = {"AES-GCM-16": "AES-GCM-16-{k}", "AES-CBC+HMAC-SHA256": "AES-CBC-{k}", "AES-CTR+HMAC-SHA256": "AES-CTR-{k}",
           "ChaCha20-Poly1305": "ChaCha20-Poly1305"}
    checked = 0
    for row in csv.DictReader(open(ROOT / "dataset" / "MANIFEST.csv")):
        name = Path(row["path"]).stem
        if name in tunnels and row["gt_cipher"] in fam and "/" not in row["path"]:
            (child,) = tunnels[name]["children"]
            assert child["esp_proposals"][0]["encr"] == [fam[row["gt_cipher"]].format(k=row["gt_keylen"])], name
            if "HMAC-SHA256" in row["gt_cipher"]:
                assert child["esp_proposals"][0]["integ"] == ["HMAC-SHA2-256-128"], name
            assert child["pfs"] == (row["gt_pfs"] == "True"), name
            checked += 1
    assert checked >= 9


def test_ml_kem_additional_key_exchange_in_both_syntaxes():
    ss = parse_config("connections {\n c {\n  proposals = aes256-sha256-x25519-ke1_mlkem768\n }\n}\n")
    ls = parse_config("conn c\n\tike=aes256-sha2_256-modp2048;addke1=ml_kem_768\n")
    assert ss["tunnels"][0]["ike_proposals"][0]["addke"] == {1: ["ML-KEM-768"]}
    assert ls["tunnels"][0]["ike_proposals"][0]["addke"] == {1: ["ML-KEM-768"]}
    assert ss["tunnels"][0]["ike_proposals"][0]["ke"] == ["Curve25519"]


def test_ppk_settings_are_read():
    (t,) = parse_file(CONFIGS / "exp27" / "alice-k2.conf")["tunnels"]
    assert t["ppk"] == {"id": "ppk27", "required": True}
    (t0,) = parse_file(CONFIGS / "exp27" / "alice-k0.conf")["tunnels"]
    assert t0["ppk"] is None


def test_unknown_syntax_is_reported_never_guessed():
    d = parse_config("connections {\n c {\n  proposals = aes256-rc4mystery-modp2048\n  frobnicate = 1\n"
                     "  children {\n   c {\n    esp_proposals = aes128gcm16-weird9\n   }\n  }\n }\n}\n")
    (t,) = d["tunnels"]
    assert t["ike_proposals"][0]["unknown"] == ["rc4mystery"]
    assert t["ike_proposals"][0]["encr"] == ["AES-CBC-256"]          # the rest is still read
    assert t["children"][0]["esp_proposals"][0]["unknown"] == ["weird9"]
    assert "frobnicate = 1" in t["unknown"]


def test_unrecognised_format_says_so():
    d = parse_config("hostname fw1\ncrypto ikev2 proposal P\n encryption aes-cbc-256\n")
    assert d["format"] is None and d["tunnels"] == [] and d["unknown"]


def test_defaults_are_flagged_not_invented():
    """No `proposals` line means the implementation's default list, which this tool does not claim to know."""
    (t,) = parse_config("connections {\n c {\n  children {\n   c {\n   }\n  }\n }\n}\n")["tunnels"]
    assert t["ike_proposals"] == [] and t["ike_proposals_default"] is True
    assert t["children"][0]["esp_proposals"] == [] and t["children"][0]["pfs"] is None


def test_prf_implied_by_integrity_is_marked():
    (t,) = parse_config("connections {\n c {\n  proposals = aes128-sha384-ecp384\n }\n}\n")["tunnels"]
    p = t["ike_proposals"][0]
    assert p["prf"] == ["PRF-HMAC-SHA2-384"] and p["prf_implied_by_integ"] is True


def test_cli_config_command_exit_codes(tmp_path, capsys):
    from tunnelscope.cli import main
    assert main(["config", str(CONFIGS / "exp27" / "alice-k2.conf")]) == 0
    assert "PPK: id ppk27, required" in capsys.readouterr().out
    other = tmp_path / "fw.cfg"
    other.write_text("hostname fw1\n")
    assert main(["config", str(other), "--json"]) == 1
