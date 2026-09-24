"""T-108: verification captures carry traffic through the tunnel (ESP/AH algorithms are only
inferred from data packets), and a rule that still cannot be judged is refused with the real reason."""
from fake_lab import ALICE_CONF, BOB_CONF, FakeLab

from tunnelscope.remediate import execute
from tunnelscope.remediate.execute import apply_remediation

A, B, FA = "sih26-alice-pq", "sih26-bob-pq", "/tmp/exp15-alice.conf"
AH_CANDIDATES = ["HMAC-MD5-96", "HMAC-SHA1-96", "AES-XCBC-96"]


def one_sa(rule, verdict, observed):
    return [{"verdicts": [{"rule_id": rule, "verdict": verdict, "observed": observed}]}]


def test_traffic_goes_through_the_tunnel_selectors_from_either_end():
    assert execute._traffic_argv(A) == ["ping", "-c", "8", "-i", "0.2", "-W", "1", "-I", "10.10.1.210", "10.10.2.210"]
    assert execute._traffic_argv(B)[-3:] == ["-I", "10.10.2.210", "10.10.1.210"]
    assert execute._traffic_argv("sih26-router") is None


def test_every_verification_capture_sends_traffic(monkeypatch, tmp_path):
    lab = FakeLab(baseline=one_sa("V-207193", "FAIL", "MODP-2048"),
                  verify=one_sa("V-207193", "PASS", "MODP-4096")).install(monkeypatch, tmp_path)
    r = apply_remediation("V-207193", A, confirm=True, history_dir=tmp_path)
    assert r["confirmed_fixed"] is True
    assert len(lab.pings) == 2 and all(c == A for c, _ in lab.pings), "baseline and verify captures"
    order = [a[0] for _, a, _ in lab.calls if a[0] in ("tcpdump", "ping", "pkill")]
    assert order[:3] == ["tcpdump", "ping", "pkill"], "the pings happen while tcpdump runs"


def test_a_passively_ambiguous_rule_is_refused_with_the_candidates(monkeypatch, tmp_path):
    ah = {A: {FA: ALICE_CONF.replace("esp_proposals = aes256gcm16", "ah_proposals = md5", 1)},
          B: {"/tmp/exp15-bob.conf": BOB_CONF.replace("esp_proposals = aes256gcm16", "ah_proposals = md5", 1)}}
    lab = FakeLab(files=ah, baseline=one_sa("RFC8221-AH-INTEG", "UNKNOWN", AH_CANDIDATES)).install(monkeypatch, tmp_path)
    r = apply_remediation("RFC8221-AH-INTEG", A, confirm=True, history_dir=tmp_path)
    assert r["decision"] == "refused" and r["stage"] == "baseline", r
    assert "cannot tell which of these" in r["error"] and "HMAC-SHA1-96" in r["error"]
    assert "cannot be judged from the wire" in r["error"]
    assert lab.fs[A] == ah[A], "nothing was changed"


def test_why_not_judged_messages():
    execute._LAST_CAPTURE.observed = {"R1": AH_CANDIDATES, "R3": "MODP-2048"}
    assert "cannot tell which of these the tunnel uses: HMAC-MD5-96, HMAC-SHA1-96, AES-XCBC-96" in execute.why_not_judged("R1", "UNKNOWN")
    assert "no protected data packets were seen" in execute.why_not_judged("R2", "UNKNOWN")
    assert "(it must be FAIL)" in execute.why_not_judged("R3", "NOT_OBSERVABLE")
