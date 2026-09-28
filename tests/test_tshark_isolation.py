"""T-143: tshark reads untrusted captures, so it runs isolated (network denied where the OS allows, resource limits,
a minimal environment, an empty Wireshark profile, no name resolution), and a damaged or hostile capture fails
closed with a clear error: never a crash, a hang, or a partial result presented as complete."""
import random
import sys
from pathlib import Path

import pytest

from tunnelscope.errors import TunnelScopeError
from tunnelscope.ingest import tshark as T
from tunnelscope.report.report import analyze

CAP = Path(__file__).resolve().parents[1] / "testbed" / "captures"
SAMPLE = CAP / "pq-downgrade.pcap"


def _fresh(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_garbage_fails_closed(tmp_path):
    """Random bytes are either refused by tshark with its reason, or read (tshark's format guesser can take them for
    a log format) and yield no SA and no verdict: nothing is ever claimed from them."""
    for seed in range(5):
        p = _fresh(tmp_path, f"garbage-{seed}.pcap", bytes(random.Random(seed).getrandbits(8) for _ in range(4096)))
        try:
            a = analyze(str(p))
        except TunnelScopeError as e:
            assert "tshark could not read" in str(e)
            continue
        assert a["sas"] == []


def test_a_file_that_is_not_a_capture_is_refused_with_the_reason(tmp_path):
    p = _fresh(tmp_path, "notes.pcap", b"this is a text file, not a capture\n" * 50)
    with pytest.raises(TunnelScopeError, match="tshark could not read"):
        analyze(str(p))


def test_a_truncated_capture_never_crashes(tmp_path):
    data = SAMPLE.read_bytes()
    p = _fresh(tmp_path, "cut.pcap", data[: len(data) // 2 + 7])            # cut in the middle of a packet
    try:
        analyze(str(p))
    except TunnelScopeError:
        pass


def test_fuzzed_captures_either_analyse_or_fail_with_a_named_error(tmp_path):
    """40 seeded mutants of a real capture (random bytes flipped past the file header): each run ends in a result or
    a TunnelScope error; nothing else escapes, nothing hangs past the tshark timeout."""
    data = bytearray(SAMPLE.read_bytes())
    outcomes = {"analysed": 0, "refused": 0}
    for seed in range(40):
        rng = random.Random(seed)
        m = bytearray(data)
        for _ in range(rng.randint(1, 40)):
            m[rng.randrange(24, len(m))] = rng.getrandbits(8)
        p = _fresh(tmp_path, f"fuzz-{seed}.pcap", bytes(m))
        try:
            analyze(str(p))
            outcomes["analysed"] += 1
        except TunnelScopeError:
            outcomes["refused"] += 1
    assert sum(outcomes.values()) == 40, outcomes


def test_tshark_never_resolves_names_and_ignores_the_users_wireshark_profile(monkeypatch):
    seen = {}

    def fake(args, timeout):
        seen["args"] = args
        return T.subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(T, "run_isolated", fake)
    T._run_fields(str(SAMPLE), "esp", ["esp.spi"])
    assert seen["args"][1] == "-n"
    profile = T._empty_profile()
    assert Path(profile).is_dir() and not any(Path(profile).iterdir())


def test_the_child_runs_with_limits_and_a_minimal_environment(monkeypatch):
    monkeypatch.setenv("TUNNELSCOPE_GROQ_API_KEY", "planted-by-the-test")           # must not reach tshark
    r = T.run_isolated([sys.executable, "-c",
                        "import os, resource; print(resource.getrlimit(resource.RLIMIT_CORE)[0], "
                        "resource.getrlimit(resource.RLIMIT_NOFILE)[0], "
                        "sorted(k for k in os.environ if k.startswith('TUNNELSCOPE')))"], timeout=20)
    core, nofile, leaked = r.stdout.split(maxsplit=2)
    assert core == "0" and int(nofile) <= 256 and leaked.strip() == "[]"   # no operator settings or keys inherited


def test_the_sandbox_really_denies_the_network_or_says_it_cannot():
    if not T.sandbox_prefix():                     # no sandbox on this platform: the status must say so, never "denied"
        assert T.isolation_status()["network"].startswith("not isolated")
        return
    r = T.run_isolated([sys.executable, "-c", "import socket; socket.create_connection(('192.0.2.1', 9), 3)"],
                       timeout=20)
    assert r.returncode != 0
    assert "not permitted" in r.stderr.lower() or "network is unreachable" in r.stderr.lower(), r.stderr[-300:]
