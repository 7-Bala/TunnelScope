"""Per-capture ingest memo (T-056).

Each reader spawns tshark, which re-reads the whole capture. ike_sa_crypto()
is called once per SA on the SAME file, so a capture carrying several tunnels
re-parsed it once per tunnel. Measured on a real capture: 10 SAs cost 10
spawns / 1.86s before, 1 spawn / 0.19s after.

Note what this does NOT do: a fleet scan analyses each capture exactly once,
so there is nothing to reuse across files and fleet runtime is unchanged
(19.7s vs 19.3s over 35 captures — noise). The win is repeated reads of one
capture, not many captures.
"""
import os
import shutil

from tunnelscope.ingest import tshark

CAP = os.path.join(os.path.dirname(__file__), "..", "testbed", "captures")
GOOD = os.path.join(CAP, "classical-baseline.pcap")


def _counting(monkeypatch):
    """Count real tshark invocations."""
    calls = {"n": 0}
    orig = tshark._run_fields

    def counted(*a, **kw):
        calls["n"] += 1
        return orig(*a, **kw)

    monkeypatch.setattr(tshark, "_run_fields", counted)
    return calls


def test_repeated_reads_of_one_capture_spawn_tshark_once(monkeypatch):
    tshark.clear_cache()
    calls = _counting(monkeypatch)
    first = tshark.ike_sa_crypto(GOOD)
    for _ in range(9):
        tshark.ike_sa_crypto(GOOD)
    assert calls["n"] == 1, "ike_sa_crypto re-parsed the capture per call"
    assert tshark.ike_sa_crypto(GOOD) == first


def test_cache_does_not_change_what_is_returned(monkeypatch):
    tshark.clear_cache()
    uncached = tshark.ike_messages(GOOD)
    tshark.clear_cache()
    recomputed = tshark.ike_messages(GOOD)
    assert uncached == recomputed


def test_a_capture_that_changes_on_disk_is_re_read(tmp_path, monkeypatch):
    # Fingerprint is (path, mtime_ns, size): serving a stale parse for a file
    # that changed would be worse than any speedup is worth.
    p = tmp_path / "c.pcap"
    shutil.copy(GOOD, p)
    tshark.clear_cache()
    calls = _counting(monkeypatch)
    tshark.ike_messages(str(p))
    tshark.ike_messages(str(p))
    assert calls["n"] == 1

    shutil.copy(os.path.join(CAP, "pq-mlkem768.pcap"), p)   # same path, new bytes
    second = tshark.ike_messages(str(p))
    assert calls["n"] == 2, "changed capture was served from cache"
    assert second == tshark.ike_messages(os.path.join(CAP, "pq-mlkem768.pcap"))


def test_cache_can_be_disabled(monkeypatch):
    tshark.clear_cache()
    monkeypatch.setattr(tshark, "_CACHE_CAPTURES", 0)
    calls = _counting(monkeypatch)
    tshark.ike_messages(GOOD)
    tshark.ike_messages(GOOD)
    assert calls["n"] == 2


def test_cache_is_bounded(monkeypatch):
    # A long-lived fleet scan must not grow memory without limit.
    tshark.clear_cache()
    monkeypatch.setattr(tshark, "_CACHE_CAPTURES", 2)
    for name in ["classical-baseline.pcap", "pq-mlkem768.pcap",
                 "pq-downgrade.pcap", "cs-aes128gcm16.pcap"]:
        tshark.ike_messages(os.path.join(CAP, name))
    assert len(tshark._CACHE) <= 2 * 3


def test_a_missing_capture_still_raises_through_the_cache():
    tshark.clear_cache()
    from tunnelscope.errors import InputError
    import pytest
    with pytest.raises(InputError):
        tshark.ike_messages("/definitely/not/here.pcap")
