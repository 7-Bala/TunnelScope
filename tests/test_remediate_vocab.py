"""T-100: the strongSwan keyword vocabulary is derived from the lab, and it knows what it knows."""
import re

from tunnelscope.remediate import vocab
from tunnelscope.remediate.plan import REMEDIATION


def _replacement_tokens():
    """Every algorithm keyword a hand-written fix writes into a config (the replacement side of
    each s/// script, plus whole values set on AH/ESP lines)."""
    toks = set()
    for entry in REMEDIATION.values():
        for cmd in entry.get("exec_commands", []):
            for repl in re.findall(r"s/(?:[^/\\]|\\.)*/((?:[^/\\]|\\.)*)/", cmd):
                toks.update(t for t in re.findall(r"[a-z][a-z0-9_]*", repl) if t not in ("proposals", "esp_proposals", "ah_proposals"))
    return toks


def test_file_says_where_it_came_from():
    v = vocab.load_vocab()
    assert v["generated_by"] == "testbed/scripts/probe_keywords.py"
    assert re.fullmatch(r"strongSwan \d+\.\d+\.\d+", v["strongswan_version"])
    assert set(v["images"]) == {"testbed-alice-pq", "testbed-bob-pq"}
    assert all(i.startswith("sha256:") for i in v["images"].values())
    assert v["rejected"], "a probe that rejects nothing did not test anything"


def test_every_keyword_a_handwritten_fix_writes_is_known():
    toks = _replacement_tokens()
    assert {"modp4096", "modp3072", "sha384", "aes256", "ke1_mlkem768", "sha256", "aes256gcm16"} <= toks
    for t in toks:
        assert vocab.kind(t, "ike") or vocab.kind(t, "esp") or vocab.kind(t, "ah"), t


def test_invented_or_malformed_keywords_are_unknown():
    for bad in ("modp3076", "sha384x", "aes256gcm17", "MODP3072", "", "modp3072;", "modp 3072",
                "modp3072\n", "sha256_sha384_modp1024", "../etc", "mоdp3072"):   # last one has a Cyrillic o
        for ctx in ("ike", "esp", "ah"):
            assert vocab.kind(bad, ctx) is None, (bad, ctx)
    assert vocab.kind(None, "ike") is None


def test_kinds_come_from_strongswan():
    assert vocab.kind("modp3072", "ike")["types"] == ["ke"]
    assert vocab.kind("ecp384", "ike")["types"] == ["ke"]
    assert vocab.kind("ke1_mlkem768", "ike")["types"] == ["ake1"]
    assert vocab.kind("sha384", "ike")["types"] == ["integ", "prf"]
    assert vocab.kind("prfsha384", "ike")["types"] == ["prf"]
    assert vocab.kind("aes256", "ike") == {"types": ["encr"], "names": {"encr": ["AES_CBC_256"]}, "aead": False}
    assert vocab.kind("aes256gcm16", "esp")["aead"] is True
    assert vocab.kind("3des", "ike")["names"] == {"encr": ["3DES_CBC"]}


def test_evidence_is_what_tunnelscope_saw_on_a_capture():
    ev = vocab.ike_evidence("modp4096")
    assert ev == [{"attribute": "ike_dh_group", "value": "MODP-4096", "source": "testbed/captures/exp15/s-modp4096.pcap"}]
    assert [e["value"] for e in vocab.ike_evidence("sha384")] == ["HMAC-SHA2-384-192", "PRF-HMAC-SHA2-384"]
    assert vocab.ike_evidence("ke1_mlkem768")[0]["value"] == ["ML-KEM-768"]
    # never observed on any capture -> no evidence, never a guess
    assert vocab.ike_evidence("modp8192") is None
    assert vocab.ike_evidence("modp3076") is None
    assert vocab.line_evidence("ah_proposals", "sha256")[0]["value"] == ["HMAC-SHA2-256-128", "AES-128-GMAC"]
    assert vocab.line_evidence("esp_proposals", "aes256gcm16")[0]["attribute"] == "esp_cipher_family"
    assert vocab.line_evidence("esp_proposals", "aes999") is None


def test_image_check_refuses_a_different_image():
    v = vocab.load_vocab()
    assert vocab.check_image(v["images"]["testbed-alice-pq"]) is None
    assert "different image" in vocab.check_image("sha256:" + "0" * 64)
    assert "could not be identified" in vocab.check_image(None)


def test_vocabulary_ships_with_the_installed_package():
    """An installed wheel must carry the keyword list (as the rules YAML), or every generated
    fix would be refused for a missing file rather than for a reason."""
    import pathlib
    import tomllib
    root = pathlib.Path(vocab.__file__).parents[2]
    data = tomllib.loads((root / "pyproject.toml").read_text())["tool"]["setuptools"]["package-data"]["tunnelscope"]
    assert "remediate/*.json" in data


def test_a_tampered_vocabulary_cannot_smuggle_metacharacters():
    """The keyword file is data on disk. Even if an entry with sed/shell metacharacters were added
    to it, the shape check refuses the token before the vocabulary is consulted."""
    import copy
    v = copy.deepcopy(vocab.load_vocab())
    good = v["keywords"]["modp4096"]
    for bad in ("modp4096.*", "modp4096;reboot", "modp/4096", "modp4096&", "Modp4096", "modp 4096"):
        v["keywords"][bad] = good
        assert vocab.kind(bad, "ike", v) is None, bad
    assert vocab.kind("modp4096", "ike", v) is not None
