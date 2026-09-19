"""T-083: PS gap closure — AH, protocol id, mode, replay, threat matrix / risk,
confidence, live analysis. Each test names the failure point it guards
(build/08-PS-GAP-CLOSURE-PLAN.md)."""
import json
import os
import shutil
import time

import pytest

from tunnelscope.evidence.extract import build_records
from tunnelscope.assess.engine import assess_record, load_baselines
from tunnelscope.risk import risk as rk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures")
E15 = os.path.join(CAP, "exp15")


def main(path):
    recs = [r for r in build_records(os.path.join(CAP, path))
            if getattr(r, "_ike", []) or getattr(r, "_esp", []) or getattr(r, "_ah", [])]
    return max(recs, key=lambda r: len(r._ike) + len(r._esp) + len(r._ah))


# ------------------------------------------------------------------ AH, protocol, mode ---

@pytest.mark.parametrize("arm,mode,alg", [("a-tun-sha256", "tunnel", "HMAC-SHA2-256-128"),
                                          ("a-tra-sha256", "transport", "HMAC-SHA2-256-128"),
                                          ("a-tra-sha1", "transport", "HMAC-SHA1-96"),
                                          ("a-tun-sha384", "tunnel", "HMAC-SHA2-384-192"),
                                          ("a-tra-sha512", "transport", "HMAC-SHA2-512-256")])
def test_ah_mode_and_integrity_from_plaintext_header(arm, mode, alg):
    F = main(f"exp15/{arm}.pcap").findings
    assert F["ipsec_protocols"].value == ["AH"]
    assert F["mode"].status.value == "OBSERVED" and F["mode"].value == mode
    assert alg in F["ah_integrity"].value


def test_ah_only_fails_confidentiality_and_md5_is_never_guessed():
    r = main("exp15/a-tra-sha1.pcap")
    v = {x.rule_id: x.verdict for x in assess_record(r)}
    assert v["RFC4301-CONFIDENTIALITY"] == "FAIL"
    assert v["RFC8221-AH-INTEG"] == "UNKNOWN"          # 12-byte ICV: MD5 or SHA-1, cannot tell
    assert v["RFC8221-AH-LEGACY"] == "FAIL"


def test_ah_rules_do_not_apply_to_esp():
    v = {x.rule_id for x in assess_record(main("cloud/c-w.pcap"))}
    assert "RFC8221-AH-INTEG" not in v and "RFC4301-CONFIDENTIALITY" in v


def test_transport_proven_only_below_the_floor():
    assert main("cs-transport-aes256gcm16.pcap").findings["mode"].value == "transport"
    for tun in ("cs-aes256gcm16.pcap", "exp15/s-modp1024.pcap", "exp15/s-3des.pcap", "cloud/c-w.pcap"):
        f = main(tun).findings["mode"]
        assert f.value is None and f.status.value == "UNKNOWN", tun   # never "tunnel" from ESP


def test_tunnel_floor_is_minimum_over_candidates():
    from tunnelscope.evidence.protocol import tunnel_floor
    assert tunnel_floor(["AES-GCM-16"]) == 56
    assert tunnel_floor(["AES-CBC+HMAC-SHA256-128"]) == 64
    assert tunnel_floor(["AES-GCM-16", "3DES-CBC+HMAC-SHA1-96"]) == 52
    assert tunnel_floor([]) is None


def test_sieve_keeps_3des_as_a_candidate():
    # regression: without the 3DES family a 3DES tunnel read "CBC excluded"
    fam = main("exp15/s-3des.pcap").findings["esp_cipher_family"]
    assert "3DES-CBC+HMAC-SHA1-96" in fam.value and "CBC excluded" not in fam.note


# ---------------------------------------------------------------------- replay ---

def test_replay_detected_and_capture_duplicate_is_not():
    atk = main("synthetic/replay-attack.pcap").findings["sequence_integrity"]
    dup = main("synthetic/replay-capture-dup.pcap").findings["sequence_integrity"]
    assert atk.value["replayed"] == 1 and atk.evidence
    assert dup.value["replayed"] == 0 and dup.value["capture_duplicates"] == 1
    assert "not visible passively" in atk.note          # enforcement never claimed


def test_clean_captures_have_no_replay():
    for p in ("cloud/c-m.pcap", "cs-aes256gcm16.pcap", "exp15/a-tun-sha256.pcap"):
        assert main(p).findings["sequence_integrity"].value["replayed"] == 0, p


# ----------------------------------------------------------- threat matrix / risk ---

def _risk(path, anomaly=None):
    r = main(path)
    return rk.assess_risk(r, assess_record(r), anomaly)


def test_risk_orders_weak_above_hardened():
    weak, default, hard = _risk("cloud/c-w.pcap"), _risk("cloud/c-m.pcap"), _risk("exp15/s-ecp384.pcap")
    assert weak["risk"]["score"] > default["risk"]["score"] > hard["risk"]["score"]
    assert weak["risk"]["band"] == "critical"


def test_every_present_threat_names_its_evidence():
    for p in ("cloud/c-w.pcap", "exp15/a-tra-sha1.pcap", "synthetic/replay-attack.pcap", "pq-downgrade.pcap"):
        for t in _risk(p)["threats"]:
            if t["status"] == "present":
                assert t["evidence"] and t["likelihood"] in (1, 2, 3), (p, t["id"])


def test_unknown_evidence_is_not_assessable_never_mitigated():
    r = main("rekey-cs-pfs-on-aes256gcm16-run2.pcap")     # no IKE_SA_INIT: DH/cipher unknown
    ts = {t.id: t for t in rk.threats(r, assess_record(r))}
    assert ts["TH-01"].status == "not_assessable"
    assert ts["TH-11"].status == "mitigated"                # PFS inferred on
    assert rk.risk_score(list(ts.values()))["coverage"] < 1


def test_risk_score_is_monotonic_and_bounded():
    t = [rk.Threat("A", "a", 3, "", status="present", likelihood=3)]
    one = rk.risk_score(t)["score"]
    two = rk.risk_score(t + [rk.Threat("B", "b", 1, "", status="present", likelihood=1)])["score"]
    none = rk.risk_score([rk.Threat("C", "c", 3, "", status="mitigated")])
    assert 0 < one < two <= 100 and one == 60
    assert none["score"] == 0 and "not that the tunnel is safe" in none["note"]


def test_downgrade_anomaly_raises_downgrade_and_drift_threats():
    an = {"status": "anomalous", "anomalies": [{"kind": "downgrade", "severity": "high", "message": "dh group downgraded"}]}
    ts = {t["id"]: t for t in _risk("cloud/c-m.pcap", an)["threats"]}
    assert ts["TH-03"]["status"] == "present" and ts["TH-12"]["status"] == "present"


def test_evidence_confidence_counts_statuses():
    c = _risk("cloud/c-w.pcap")["confidence"]
    assert c["observed"] + c["inferred"] + c["not_visible"] == c["attributes"]
    assert 0 < c["score"] < 100


# -------------------------------------------------------------------- labels, API ---

def test_handshake_and_data_cipher_are_labelled_apart():
    from tunnelscope.report.labels import label
    assert "Handshake" in label("ike_encr") and "Data" in label("esp_cipher_family")
    from tunnelscope.report.report import analyze, technical_report
    tech = technical_report(analyze(os.path.join(CAP, "cloud/c-w.pcap")))
    assert "| Handshake (IKE SA) encryption |" in tech and "| Data (ESP) cipher: candidates |" in tech


# ------------------------------------------------------------------------- live ---

def test_live_follow_processes_closed_windows_in_order(tmp_path):
    from tunnelscope.live.live import LiveMonitor
    d, h = tmp_path / "in", tmp_path / "hist"
    d.mkdir()
    for i, src in enumerate(["cloud/c-m.pcap", "cloud/c-m.pcap", "cloud/c-m.pcap", "cloud/c-w.pcap"]):
        p = d / f"w-{i}.pcap"
        shutil.copy(os.path.join(CAP, src), p)
        os.utime(p, (time.time() - 100 + i, time.time() - 100 + i))
    (d / "notes.txt").write_text("ignored")
    m = LiveMonitor(follow=str(d), window=5, history=str(h))
    rows = m.poll_once()                       # all idle -> all four taken
    assert [r["file"] for r in rows] == ["w-0.pcap", "w-1.pcap", "w-2.pcap", "w-3.pcap"]
    assert rows[-1]["sas"][0]["anomaly"]["status"] == "anomalous"
    assert not list(d.glob("*.pcap"))            # analysed windows deleted by default
    assert m.status()["windows"][0]["file"] == "w-3.pcap"


def test_live_never_reads_the_growing_newest_file(tmp_path):
    from tunnelscope.live.live import LiveMonitor
    old, new = tmp_path / "a.pcap", tmp_path / "b.pcap"
    shutil.copy(os.path.join(CAP, "cloud/c-m.pcap"), old)
    shutil.copy(os.path.join(CAP, "cloud/c-m.pcap"), new)
    os.utime(old, (time.time() - 5, time.time() - 5))
    m = LiveMonitor(follow=str(tmp_path), window=30)
    assert [p.name for p in m.ready_files()] == ["a.pcap"]


def test_live_bad_window_is_reported_not_fatal(tmp_path):
    from tunnelscope.live.live import LiveMonitor
    (tmp_path / "junk.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 4)
    os.utime(tmp_path / "junk.pcap", (time.time() - 200, time.time() - 200))
    m = LiveMonitor(follow=str(tmp_path), window=5)
    (row,) = m.poll_once()
    assert row["ok"] is False and m.status()["errors"]


def test_live_needs_exactly_one_source():
    from tunnelscope.errors import InputError
    from tunnelscope.live.live import LiveMonitor
    with pytest.raises(InputError):
        LiveMonitor()
    with pytest.raises(InputError):
        LiveMonitor(interface="en0", follow="/tmp")
