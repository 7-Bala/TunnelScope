"""End-to-end test of live gateway fixes (DEC-063) against the two real strongSwan gateways that
setup.sh builds. Everything goes through SSH, exactly as on a real site. Run as root, after setup.sh:

    sudo testbed/live-gateway/teardown.sh && sudo testbed/live-gateway/setup.sh
    sudo .venv/bin/python testbed/live-gateway/e2e.py

Scenarios, each checked on the gateways' real files and the real tunnel:
  A  every gate refuses before anything changes (no terms, wrong sentences, changed definition)
  B  one end changed, other end cannot agree -> tunnel fails verification -> automatic rollback,
     files byte for byte, tunnel back up and no worse than the baseline
  C  both ends changed (peer registered) -> confirmed fixed, rule FAIL -> PASS, tunnel up after rekey
  D  TunnelScope "dies" after applying: the watchdog on the gateway restores the files by itself,
     and the next run records that restore in the audit log
Prints one JSON summary; exit 0 only if every check passed.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from tunnelscope.remediate import execute, gateways  # noqa: E402

ROOT = Path("/srv/tunnelscope-gw")
KEY = ROOT / "client"
HIST = ROOT / "history-e2e"
RULE = "V-207193"
GW = {"office-a": "192.168.77.10", "office-b": "192.168.77.11"}
checks: list[dict] = []


def check(name: str, ok: bool, detail=None) -> bool:
    checks.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail is not None else ""), flush=True)
    return ok


def conf(g: str) -> str:
    return (ROOT / g / "swanctl" / "swanctl.conf").read_text()


def sha(g: str) -> str:
    return hashlib.sha256(conf(g).encode()).hexdigest()[:16]


def register(name: str, peer: str | None = None) -> None:
    execute.save_gateway(name, {"host": GW[name], "connection": "office-link", "config_globs": ["/etc/swanctl/swanctl.conf"],
                                "identity_file": str(KEY / "id_ed25519"), "known_hosts_file": str(KEY / "known_hosts"),
                                "peer": peer}, HIST)


def accept(name: str) -> dict:
    return execute.accept_terms(gateways.PREFIX + name, gateways.accept_phrase(name), "e2e operator", HIST)


def leftovers(g: str) -> list[str]:
    return sorted(p.name for p in (ROOT / g / "tmp").iterdir()) + \
        sorted(p.name for p in (ROOT / g / "swanctl").iterdir() if p.name.endswith(execute.SNAP_SUFFIX))


def fix(ack: str | None):
    pv = execute.preview_remediation(RULE, "gw:office-a", caller="e2e", history_dir=HIST)
    if not pv.get("ok"):
        return pv, None
    return pv, execute.apply_remediation(RULE, "gw:office-a", confirm=True, caller="e2e", history_dir=HIST,
                                         digest=pv["digest"], require_digest=True, risk_ack=ack)


def main() -> int:
    shutil.rmtree(HIST, ignore_errors=True)
    start = {g: sha(g) for g in GW}
    check("start: both gateways offer MODP-2048", all("modp2048" in conf(g) for g in GW))

    # ---- A: gates
    register("office-a"), register("office-b")
    pv, _ = fix("x")
    check("A1 no terms accepted -> refused at consent", pv.get("stage") == "consent", pv.get("error"))
    bad = execute.accept_terms("gw:office-a", "i agree", "e2e operator", HIST)
    check("A2 wrong acceptance sentence -> refused", not bad["ok"], bad.get("error"))
    check("A3 correct acceptance recorded", accept("office-a")["ok"] and accept("office-b")["ok"])
    pv, res = fix("yes")
    check("A4 wrong per-change sentence -> refused at consent", res and res.get("stage") == "consent", res and res.get("error"))
    check("A5 preview ran the load check on the gateway", pv.get("clone_check", {}).get("ok") is True,
          pv.get("clone_check", {}).get("image"))
    check("A6 nothing changed by A1-A5", {g: sha(g) for g in GW} == start)

    # ---- B: one end only -> rollback
    pv, res = fix(gateways.ack_phrase(RULE, "office-a"))
    svc = (res or {}).get("service_restored") or {}
    check("B1 baseline FAIL", res and res.get("verdict_before") == "FAIL")
    check("B2 not confirmed, rolled back", res and res.get("confirmed_fixed") is False and res.get("rolled_back") is True,
          res and res.get("reason"))
    check("B3 rollback verified byte for byte", res and res.get("rollback_verified") is True and sha("office-a") == start["office-a"])
    check("B4 tunnel back up, no rule worse than baseline", svc.get("tunnel_up") is True and svc.get("matches_baseline") is True, svc)
    check("B5 no snapshot, manifest or capture left", not leftovers("office-a"), leftovers("office-a"))

    # ---- C: both ends -> confirmed
    register("office-a", peer="office-b")
    pv, _ = fix("x")
    check("C1 changed definition -> consent needed again", pv.get("stage") == "consent", pv.get("error"))
    accept("office-a")
    t0 = time.monotonic()
    pv, res = fix(gateways.ack_phrase(RULE, "office-a"))
    check("C2 confirmed fixed: FAIL -> PASS on a fresh capture",
          res and res.get("confirmed_fixed") is True and res.get("verdict_before") == "FAIL" and res.get("verdict_after") == "PASS",
          res and res.get("reason"))
    check("C3 tunnel survived a forced rekey", (res or {}).get("rekey", {}).get("tunnel_after_rekey") is True)
    check("C4 both ends now MODP-4096", all("modp4096" in conf(g) and "modp2048" not in conf(g) for g in GW))
    check("C5 no snapshot, manifest or capture left", not leftovers("office-a") and not leftovers("office-b"))
    check("C6 duration", True, f"{time.monotonic() - t0:.1f} s")

    # ---- D: watchdog restores by itself when TunnelScope never confirms
    execute._CTX.history_dir = HIST
    before = conf("office-a")
    token = "e2ewatchdog01"
    files = execute.snapshot_configs("gw:office-a", token)
    execute.arm_commit_confirmed_watchdog("gw:office-a", token, timeout_s=6)
    cmd = execute.plan_for(RULE, include_exec=True)["exec_commands"][0].replace("modp4096", "modp3072")
    cmd = cmd.replace("modp(1024|1536|2048)", "modp4096")
    execute._run_plan_command("gw:office-a", cmd, list(files))
    execute._reload("gw:office-a", list(files))
    changed = "modp3072" in conf("office-a")
    check("D1 change applied, then TunnelScope stops without confirming", changed)
    time.sleep(12)
    check("D2 watchdog on the gateway restored the file byte for byte", conf("office-a") == before)
    ev = execute.reconcile_watchdog_events(HIST)
    check("D3 next run records the watchdog restore in the audit log",
          any(e.get("decision") == "watchdog_rollback" and e.get("token") == token for e in ev))
    check("D4 no snapshot or manifest left", not leftovers("office-a"), leftovers("office-a"))

    ok = all(c["ok"] for c in checks)
    print(json.dumps({"ok": ok, "passed": sum(c["ok"] for c in checks), "total": len(checks), "checks": checks}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
