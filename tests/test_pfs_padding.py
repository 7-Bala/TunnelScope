"""T-135 (EXP-26): an implementation that pads its encrypted IKE messages (MikroTik RouterOS, up to
~255 B, allowed by RFC 7296 sec 3.14) defeats the size-based PFS rule. PFS must then be UNKNOWN, never
a guess; implementations that pad minimally (strongSwan) keep their measured answers."""
import os

import pytest

from tunnelscope.evidence.extract import build_records, ike_extra_padding, min_empty_sk_len

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures")


def _pfs(path):
    recs = [r for r in build_records(os.path.join(CAP, path)) if getattr(r, "_ike", [])]
    return [r.findings["pfs"] for r in recs]


@pytest.mark.parametrize("arm", ["mt-m6", "mt-m7"])
def test_padding_implementation_gives_unknown_pfs_never_a_guess(arm):
    """M7 has PFS off and was read as PFS on (EXP-26's one wrong finding); M6's right answer was luck."""
    (f,) = _pfs(f"exp26/{arm}.pcap")
    assert f.status.value == "UNKNOWN", (f.status, f.value, f.note)
    assert "padding" in f.note


@pytest.mark.parametrize("path,want", [("rekey-cs-pfs-on-aes256gcm16-run2.pcap", True),
                                       ("exp07/e7-pfs-off.pcap", False)])
def test_minimal_padding_implementations_keep_their_answer(path, want):
    fs = [f for f in _pfs(path) if f.status.value == "INFERRED"]
    assert fs and all(f.value is want for f in fs), [(f.status, f.value) for f in _pfs(path)]


def test_rekey_only_capture_cannot_say_pfs_off_when_the_group_is_invisible():
    """EXP-47 addendum F: the same capture used to read INFERRED False; without the IKE_SA_INIT the group is unknown."""
    (f,) = _pfs("rekey-cs-pfs-off-aes256gcm16-run2.pcap")
    assert f.status.value == "UNKNOWN" and f.value is None, (f.status, f.value)


def test_minimum_empty_message_size_follows_rfc_7296():
    # 4 B SK header + IV + one block (pad + pad-length byte) + ICV
    assert min_empty_sk_len("AES-CBC-256", "HMAC-SHA2-256-128") == 4 + 16 + 16 + 16
    assert min_empty_sk_len("3DES", "HMAC-SHA1-96") == 4 + 8 + 8 + 12
    assert min_empty_sk_len("AES-CBC-128", "HMAC-SHA2-512-256") == 4 + 16 + 16 + 32
    assert min_empty_sk_len(None, None) == 68          # unknown suite: the largest minimum any suite has


def _msg(sk_next, sk_len, t=0.0):
    return {"exchange": 37, "sk_next": sk_next, "sk_len": sk_len, "t": t}


def test_extra_padding_detected_from_empty_messages_only():
    minimal = [_msg(0, 52), _msg(0, 52), _msg(41, 300)]          # non-empty messages say nothing
    assert ike_extra_padding(minimal, "AES-CBC-256", "HMAC-SHA2-256-128") is None
    assert ike_extra_padding([_msg(0, 116)], "AES-CBC-256", "HMAC-SHA2-256-128")      # above the minimum
    assert ike_extra_padding([_msg(0, 52), _msg(0, 68)], None, None)                  # sizes vary
    assert ike_extra_padding([_msg(41, 404)], "AES-CBC-256", "HMAC-SHA2-256-128") is None
