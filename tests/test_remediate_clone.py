"""T-100: the changed config is loaded by strongSwan in a throwaway clone before anything is
applied. Tests run against the in-memory lab (tests/fake_lab.py); the live proof is in the report."""
import pytest
from fake_lab import ALICE_CONF, FakeLab, fake_load

from tunnelscope.remediate import execute, plan
from tunnelscope.remediate.execute import clone_load_check, perform_sandboxed_dry_run, preview_remediation

A = "sih26-alice-pq"
F = "/tmp/exp15-alice.conf"
GOOD = ALICE_CONF.replace("proposals = aes256-sha256-modp2048", "proposals = aes256-sha256-modp4096")
INVENTED = ALICE_CONF.replace("proposals = aes256-sha256-modp2048", "proposals = aes256-sha256-modp3076")


@pytest.fixture
def lab(monkeypatch, tmp_path):
    return FakeLab().install(monkeypatch, tmp_path)


def test_fake_load_matches_the_one_thing_the_check_is_about():
    assert fake_load(ALICE_CONF)[:2] == (["t-tun", "s-modp1024"], [])
    loaded, failed, unknown = fake_load(INVENTED)
    assert failed == ["t-tun"] and unknown == ["modp3076"]


def test_a_good_change_loads(lab):
    r = clone_load_check(A, {F: ALICE_CONF}, {F: GOOD})
    assert r["ok"] is True, r
    assert r["files"][F] == {"before": {"loaded": 2, "failed": 0}, "after": {"loaded": 2, "failed": 0}}
    assert r["image"] == lab.images[A]


def test_an_invented_algorithm_is_refused_and_named(lab):
    r = clone_load_check(A, {F: ALICE_CONF}, {F: INVENTED})
    assert r["ok"] is False
    assert r["rejected_keywords"] == ["modp3076"]
    assert "t-tun" in r["reason"] and "modp3076" in r["reason"]


def test_connections_that_already_fail_are_the_baseline_not_a_refusal(lab):
    broken = ALICE_CONF.replace("proposals = aes128-sha1-modp1024", "proposals = aes128-sha1-bogus1")
    r = clone_load_check(A, {F: broken}, {F: broken.replace("aes256-sha256-modp2048", "aes256-sha256-modp4096")})
    assert r["ok"] is True, r
    assert r["files"][F]["before"]["failed"] == 1 and r["files"][F]["after"]["failed"] == 1


def test_one_more_failing_connection_is_refused(lab):
    worse = ALICE_CONF.replace("proposals = aes128-sha1-modp1024", "proposals = aes128-sha1-bogus1")
    r = clone_load_check(A, {F: ALICE_CONF}, {F: worse})
    assert r["ok"] is False and "s-modp1024" in r["reason"]


def test_lab_connection_must_load_after_the_change(lab):
    # t-tun fails both before and after: nothing got worse, but the lab tunnel still cannot exist
    both = ALICE_CONF.replace("proposals = aes256-sha256-modp2048", "proposals = aes256-sha256-bogus2")
    r = clone_load_check(A, {F: both}, {F: both.replace("version = 2\n        proposals = aes256-sha256-bogus2",
                                                        "version = 2\n        proposals = aes256-sha256-bogus2 ")})
    assert r["ok"] is False and "t-tun does not load" in r["reason"]


@pytest.mark.parametrize("mode,phrase", [("timeout", "did not finish"), ("charon", "complete result"),
                                         ("truncated", "complete result")])
def test_clone_failures_are_refusals(lab, mode, phrase):
    lab.fail["clone"] = mode
    r = clone_load_check(A, {F: ALICE_CONF}, {F: GOOD})
    assert r["ok"] is False and phrase in r["reason"]
    if mode == "timeout":
        assert any(n.startswith("tunnelscope-clone-") for n in lab.removed), "a timed-out clone must be removed"


def test_unknown_image_is_a_refusal(lab):
    lab.fail["inspect"] = True
    r = clone_load_check(A, {F: ALICE_CONF}, {F: GOOD})
    assert r["ok"] is False and "could not identify the image" in r["reason"]
    assert lab.clone_runs == []


def test_clone_runs_isolated_on_the_image_id_with_the_fixed_script(lab):
    clone_load_check(A, {F: ALICE_CONF}, {F: GOOD})
    (argv,) = lab.clone_runs
    assert argv[argv.index("--network") + 1] == "none"
    assert "--rm" in argv and execute.CLONE_LABEL in argv
    assert lab.images[A] in argv and "testbed-alice-pq" not in argv      # the id, never the tag
    assert argv[argv.index("-c") + 1] == execute._CLONE_SCRIPT


def test_stale_clones_are_swept_fresh_ones_are_left(lab):
    import time
    now = int(time.time())
    lab.clones_left = [f"tunnelscope-clone-{now - 1000}-abcd1234", f"tunnelscope-clone-{now}-abcd1234", "unrelated"]
    clone_load_check(A, {F: ALICE_CONF}, {F: GOOD})
    assert lab.removed == [f"tunnelscope-clone-{now - 1000}-abcd1234"]


def test_nothing_changed_starts_no_clone(lab):
    r = clone_load_check(A, {F: ALICE_CONF}, {F: ALICE_CONF})
    assert r["ok"] is True and lab.clone_runs == []


def test_dry_run_refuses_an_invented_algorithm_that_passes_every_other_check(lab):
    """The measured failure (build/13 section 2.1): `modp3076` passes the command allowlist and
    the diff checks. Only loading it catches it."""
    cmd = plan._in_connection(plan._IKE_PROPOSALS + " s/modp2048/modp3076/g")
    assert plan.validate_command_safety(cmd) == (True, None)
    report = {}
    ok, err, diffs = perform_sandboxed_dry_run(A, [cmd], report=report)
    assert ok is False and "does not load in a clone" in err and "modp3076" in err
    assert report["clone_check"]["rejected_keywords"] == ["modp3076"]
    assert lab.fs[A][F] == ALICE_CONF, "the real file is untouched"


def test_handwritten_plans_pass_the_clone_check_too(lab):
    for rule in ("V-207193", "V-207223", "DST-PQ-KE"):
        lab.fs = FakeLab().fs
        report = {}
        ok, err, _ = perform_sandboxed_dry_run(A, plan.plan_for(rule, include_exec=True)["exec_commands"], report=report)
        assert ok, (rule, err)
        assert report["clone_check"]["ok"] is True


def test_preview_shows_the_clone_result_for_both_ends(lab):
    r = preview_remediation("V-207193", A)
    assert r["ok"] is True, r
    assert r["clone_check"]["ok"] is True
    assert r["peer"]["clone_check"]["ok"] is True
    assert len(lab.clone_runs) == 2


def test_apply_is_blocked_before_any_change_when_the_clone_refuses(lab, monkeypatch):
    lab.fail["clone"] = "charon"
    r = execute.apply_remediation("V-207193", A, confirm=True)
    assert r["ok"] is False and r["stage"] == "dry_run"
    assert lab.fs[A] == {F: ALICE_CONF}
    assert set(lab.fs["sih26-bob-pq"]) == {"/tmp/exp15-bob.conf"}
    assert not any(a[0] == "tcpdump" for _, a, _ in lab.calls), "no capture, nothing applied"


def test_docker_commands_in_execute_are_argument_lists():
    """The clone adds `docker run`; it must not add a shell or a string command."""
    import inspect
    src = inspect.getsource(execute._docker)
    assert '["docker", *argv]' in src and "shell" not in src
