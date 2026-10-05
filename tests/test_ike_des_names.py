"""T-118 / EXP-47: a FortiGate-VM evaluation image offers only DES (IKE encryption id 2, ESP DES-CBC with HMAC-SHA-2). TunnelScope
used to print the IKE cipher as the unnamed 'encr-2' and could not list the true ESP family. The ESP lengths below are the
ones measured on the real FortiGate captures (arms S01-S05, FortiOS 7.6.7, 28 pings of 56 B and 12 of 1000 B each)."""
import pytest

from tunnelscope.evidence.extract import _SIEVE, extract_cipher_sieve
from tunnelscope.evidence.record import EvidenceRecord
from tunnelscope.ingest.tshark import IKE_ENCR

# IANA "IKEv2 Parameters", Transform Type 1 (read 2026-10-03)
IANA = {1: "DES-IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "Blowfish", 8: "3IDEA", 9: "DES-IV32",
        11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16", 18: "AES-GCM-8",
        19: "AES-GCM-12", 20: "AES-GCM-16", 28: "ChaCha20-Poly1305"}


def test_ike_encryption_names_follow_the_iana_registry():
    assert IKE_ENCR == IANA


def test_des_is_named_and_reserved_ids_stay_unnamed():
    assert IKE_ENCR.get(2) == "DES" and 10 not in IKE_ENCR and 0 not in IKE_ENCR


def _sieve(lengths, n=40):
    r = EvidenceRecord(src="10.61.0.1", dst="10.62.0.1", source_pcap="x.pcap")
    r._esp = [{"frame": i + 1, "esp_content": lengths[i % len(lengths)]} for i in range(n)]
    extract_cipher_sieve(r)
    return r.findings["esp_cipher_family"]


@pytest.mark.parametrize("lengths,truth", [
    ([108, 1052], "DES-CBC+HMAC-96"),                 # des-md5 and des-sha1 (96-bit ICV): measured on S01 and S02
    ([112, 1056], "DES-CBC+HMAC-SHA256-128"),         # S03
    ([120, 1064], "DES-CBC+HMAC-SHA384-192"),         # S04
    ([128, 1072], "DES-CBC+HMAC-SHA512-256"),         # S05
])
def test_the_true_des_family_is_in_the_candidate_set(lengths, truth):
    f = _sieve(lengths)
    assert f.status.value == "INFERRED" and truth in f.value, (truth, f.value)


def test_the_new_families_have_the_rfc4868_icv_sizes_and_nothing_else_changed():
    assert (_SIEVE["DES-CBC+HMAC-SHA256-128"], _SIEVE["DES-CBC+HMAC-SHA384-192"], _SIEVE["DES-CBC+HMAC-SHA512-256"]) == (
        dict(iv=8, icv=16, align=8), dict(iv=8, icv=24, align=8), dict(iv=8, icv=32, align=8))
    assert _SIEVE["DES-CBC+HMAC-96"] == dict(iv=8, icv=12, align=8) and _SIEVE["AES-GCM-16"] == dict(iv=8, icv=16, align=4)


def test_a_clearly_aead_pattern_still_excludes_a_des_family_when_the_lengths_do_not_fit():
    f = _sieve([100, 1048])                           # 100 = 4 mod 8 and 1048 = 0 mod 8: no 8-aligned DES family fits both
    assert "DES-CBC+HMAC-SHA256-128" not in f.value and "AES-GCM-16" in f.value
