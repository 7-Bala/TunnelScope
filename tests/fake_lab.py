"""In-memory stand-in for the Docker lab, for the remediation tests.

It answers the `docker exec` calls `tunnelscope.remediate.execute` makes, keeps real config file
contents per container, and runs sed scripts (parsed with the production parser, applied with a
Python translation of the small allowed grammar). So a test can check what actually happened to
a file (changed, restored byte for byte, untouched) rather than only which commands were called.

Two things it deliberately refuses: any `sh -c` script other than the four fixed helper scripts
in execute.py (so a plan command reaching a shell fails the test), and any program it does not
know. The sed emulation is not GNU sed: real sed behaviour is checked only in the live lab.

It also plays the throwaway clone of T-100 (`docker run ... _CLONE_SCRIPT`): it unpacks the tar
the engine sends and "loads" each file the way strongSwan would for the one thing the check is
about, a proposal keyword strongSwan does not know. Known keywords come from the generated
strongswan_keywords.json, so the fake and the product agree on what exists.
"""
from __future__ import annotations

import fnmatch
import io
import posixpath
import tarfile
import re
import subprocess
from pathlib import Path

from tunnelscope.remediate import execute, plan, vocab


class _Res:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _ere(rx: str) -> str:
    return rx.replace("[[:space:]]", r"\s").replace("[:space:]", r"\s")


def _repl(repl: str) -> str:
    out, i = [], 0
    while i < len(repl):
        c = repl[i]
        if c == "\\" and i + 1 < len(repl):
            n = repl[i + 1]
            # GNU sed back-references are one digit: "\12" is group 1 then "2"
            out.append(f"\\g<{n}>" if n.isdigit() else ("\\\\" if n == "\\" else n))
            i += 2
            continue
        out.append(r"\g<0>" if c == "&" else c)
        i += 1
    return "".join(out)


class _Sed:
    def __init__(self):
        self.active: dict[int, bool] = {}

    def _selected(self, node: dict, line: str) -> bool:
        a1, a2 = node["addr1"], node["addr2"]
        if a1 is None:
            sel = True
        elif a2 is None:
            sel = re.search(_ere(a1["regex"]), line) is not None
        elif self.active.get(id(node)):
            sel = True
            if re.search(_ere(a2["regex"]), line):
                self.active[id(node)] = False
        elif re.search(_ere(a1["regex"]), line):
            sel = True
            self.active[id(node)] = True
        else:
            sel = False
        return sel != node["negate"]

    def line(self, node: dict, text: str) -> str:
        if not self._selected(node, text):
            return text
        if node["kind"] == "s":
            flags = re.I if "I" in node["flags"] else 0
            return re.sub(_ere(node["regex"]), _repl(node["repl"]), text,
                          count=0 if "g" in node["flags"] else 1, flags=flags)
        return self.line(node["body"], text)


def run_sed(script: str, content: str) -> str:
    tree, sed = plan.parse_sed_script(script), _Sed()
    return "\n".join(sed.line(tree, ln) for ln in content.split("\n"))


def sas(**verdicts: str) -> list[dict]:
    """One SA carrying the given verdicts: sas(**{"V-207193": "FAIL"})."""
    return [{"verdicts": [{"rule_id": k, "verdict": v} for k, v in verdicts.items()]}]


# Same shape as the generated lab config (testbed/scripts/gen_exp15_conf.py): local/remote blocks
# before the proposals line, and a second, deliberately weak experiment connection whose name and
# auth IDs contain "modp1024". A correct fix changes t-tun only and never touches s-modp1024.
ALICE_CONF = """connections {
    # traffic: tunnel, AES-GCM-256
    t-tun {
        local_addrs  = 10.10.1.210
        remote_addrs = 10.10.2.210
        local {
            auth = psk
            id = a-t-tun
        }
        remote {
            auth = psk
            id = b-t-tun
        }
        version = 2
        proposals = aes256-sha256-modp2048
        children {
            t-tun {
                mode = tunnel
                esp_proposals = aes256gcm16
            }
        }
    }
    # suite: deliberately weak arm
    s-modp1024 {
        local_addrs  = 10.10.1.211
        remote_addrs = 10.10.2.211
        local {
            auth = psk
            id = a-s-modp1024
        }
        remote {
            auth = psk
            id = b-s-modp1024
        }
        version = 2
        proposals = aes128-sha1-modp1024
        children {
            s-modp1024 {
                esp_proposals = aes128-sha1
            }
        }
    }
}
"""

BOB_CONF = (ALICE_CONF.replace("10.10.1.", "Y").replace("10.10.2.", "10.10.1.").replace("Y", "10.10.2.")
            .replace("id = a-", "id = X-").replace("id = b-", "id = a-").replace("id = X-", "id = b-"))


_PROPOSAL_LINE = re.compile(r"^\s*(proposals|esp_proposals|ah_proposals)\s*=\s*(.*)$")
_TOP_CONN = re.compile(r"^    ([^\s{}#]+) \{\s*$")


def fake_load(conf: str) -> tuple[list[str], list[str], list[str]]:
    """(loaded, failed, unknown keywords) for one swanctl.conf, judged only on proposal keywords."""
    known = vocab.load_vocab()["keywords"]
    loaded, failed, unknown, current, bad = [], [], [], None, False
    in_conns = False
    for line in conf.splitlines():
        code = line.split("#", 1)[0]
        if code.startswith("connections {"):
            in_conns = True
            continue
        if in_conns and code.startswith("}"):
            in_conns = False
        if not in_conns:
            continue
        m = _TOP_CONN.match(code)
        if m:
            if current is not None:
                (failed if bad else loaded).append(current)
            current, bad = m.group(1), False
            continue
        p = _PROPOSAL_LINE.match(code)
        if p and current is not None:
            for tok in re.split(r"[-,\s]+", p.group(2).strip()):
                if tok and tok not in known:
                    bad = True
                    unknown.append(tok)
    if current is not None:
        (failed if bad else loaded).append(current)
    return loaded, failed, unknown


def fake_clone_output(tar_bytes: bytes) -> str:
    out, log = [], []
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        members = sorted((m for m in tar.getmembers() if m.name.startswith("c/")), key=lambda m: m.name)
        for m in members:
            text = tar.extractfile(m).read().decode()
            loaded, failed, unknown = fake_load(text)
            out.append(f"TS_FILE {m.name[2:]}")
            out += [f"loaded connection '{n}'" for n in loaded]
            out += [f"loading connection '{n}' failed: invalid value for: proposals, config discarded" for n in failed]
            out.append(f"successfully loaded {len(loaded)} connections, 0 unloaded" if not failed else
                       f"loaded {len(loaded)} of {len(loaded) + len(failed)} connections, {len(failed)} failed to load, 0 unloaded")
            out.append("TS_END")
            log += [f"07[CFG] algorithm '{t}' not recognized" for t in unknown]
    return "\n".join(out + ["TS_LOG"] + log + ["TS_DONE"]) + "\n"


class FakeLab:
    def __init__(self, files=None, baseline=None, verify=None, running=None):
        self.fs = {c: dict(f) for c, f in (files or {
            "sih26-alice-pq": {"/tmp/exp15-alice.conf": ALICE_CONF},
            "sih26-bob-pq": {"/tmp/exp15-bob.conf": BOB_CONF},
        }).items()}
        self.analyses = {"baseline": baseline, "verify": verify}
        self.running = set(running) if running is not None else set(execute.get_allowed_targets())
        self.calls: list[tuple[str, list[str], bool]] = []
        self.watchdogs: list[tuple[str, int, str]] = []
        self.fail: dict[str, object] = {}
        self.captures_dir: Path | None = None
        self.before_verify = None  # hook run when the verify capture is analysed
        self.clone_runs: list[list[str]] = []   # argv of every clone started
        self.clones_left: list[str] = []        # clone names `docker ps -a` still reports
        self.removed: list[str] = []            # names passed to `docker rm -f`
        # what `swanctl --list-sas --raw` reports; "down" makes the SA vanish after a forced rekey
        self.rekey_outcome = "up"
        self.ike_spi = 1
        self.sa_fields = "version=2 state=ESTABLISHED encr-alg=AES_CBC encr-keysize=256 integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 dh-group=MODP_4096"
        self.rekeys: list[str] = []
        ids = vocab.load_vocab()["images"]
        self.images = {"sih26-alice-pq": ids["testbed-alice-pq"], "sih26-bob-pq": ids["testbed-bob-pq"]}

    def install(self, monkeypatch, tmp_path):
        monkeypatch.setattr(subprocess, "run", self.run)
        monkeypatch.setattr(execute.time, "sleep", lambda s: None)
        self.captures_dir = tmp_path / "captures"
        self.captures_dir.mkdir(exist_ok=True)
        monkeypatch.setattr(execute, "_captures_dir", lambda: self.captures_dir)
        import tunnelscope.report.report as report
        monkeypatch.setattr(report, "analyze", self.analyze)
        return self

    # -- what analyze() returns for each capture phase
    def analyze(self, path):
        name = Path(path).name
        phase = "baseline" if "baseline" in name else "post_rollback" if "post_rollback" in name else "verify"
        if phase == "verify" and self.before_verify:
            self.before_verify(self)
        # after a rollback the files are the originals, so by default the tunnel looks like the baseline
        a = self.analyses.get(phase, self.analyses["baseline"])
        return {"sas": a(self) if callable(a) else (a or [])}

    def _ls(self, fs: dict) -> list[str]:
        found = []
        for glob in plan.CONFIG_GLOBS.split():
            d, pat = posixpath.split(glob)
            found += [p for p in fs if posixpath.dirname(p) == d and not posixpath.basename(p).startswith(".")
                      and fnmatch.fnmatchcase(posixpath.basename(p), pat)]
        return sorted(found)

    def fire_watchdog(self, container: str) -> None:
        """What _WATCHDOG_SCRIPT does when its timer runs out."""
        fs = self.fs[container]
        manifest = fs.get(execute.MANIFEST)
        if not manifest:
            return
        lines = [x for x in manifest.splitlines() if x]
        token, files = lines[0], lines[1:]
        for f in files:
            if f + execute.SNAP_SUFFIX in fs:
                fs[f] = fs[f + execute.SNAP_SUFFIX]
            fs.pop(f + execute.SNAP_SUFFIX, None)
        fs.pop(execute.MANIFEST, None)
        fs[execute.WATCHDOG_MARKER] = f"{token} 1790000000\n"

    def run(self, cmd, *args, **kwargs):
        assert cmd[0] == "docker", cmd
        if cmd[1] == "ps" and "--filter" in cmd:
            return _Res(0, "".join(n + "\n" for n in self.clones_left).encode())
        if cmd[1] == "ps":
            return _Res(0, "".join(n + "\n" for n in sorted(self.running)))
        if cmd[1] == "inspect":
            c = cmd[-1]
            if self.fail.get("inspect") or c not in self.running or c not in self.images:
                return _Res(1, b"", b"Error: No such object")
            return _Res(0, (self.images[c] + "\n").encode())
        if cmd[1] == "rm":
            self.removed.append(cmd[-1])
            self.clones_left = [n for n in self.clones_left if n != cmd[-1]]
            return _Res(0, b"")
        if cmd[1] == "run":
            self.clone_runs.append(list(cmd))
            assert cmd[cmd.index("-c") + 1] == execute._CLONE_SCRIPT, "only the fixed clone script may run in a clone"
            mode = self.fail.get("clone")
            if mode == "timeout":
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
            if mode == "charon":
                return _Res(0, b"TS_ERR charon\n")
            if mode == "truncated":
                return _Res(0, fake_clone_output(kwargs["input"]).split("TS_LOG")[0].encode())
            return _Res(0, fake_clone_output(kwargs["input"]).encode())
        assert cmd[1] == "exec", cmd
        rest, detach = list(cmd[2:]), False
        if rest[0] == "-d":
            detach, rest = True, rest[1:]
        c, argv = rest[0], rest[1:]
        self.calls.append((c, list(argv), detach))
        if c not in self.running:
            return _Res(1, "", f"Error: No such container: {c}")
        fs = self.fs.setdefault(c, {})
        prog = argv[0]
        if prog == "sh":
            assert argv[1] == "-c", argv
            script = argv[2]
            if script == execute._LIST_CONFIGS_SCRIPT:
                return _Res(0, "".join(p + "\n" for p in self._ls(fs)))
            if script == execute._WRITE_MANIFEST_SCRIPT:
                fs[argv[3]] = "".join(x + "\n" for x in argv[4:])
                return _Res()
            if script == execute._WATCHDOG_SCRIPT:
                assert detach, "the watchdog must run detached"
                self.watchdogs.append((c, int(argv[4]), argv[5]))
                return _Res()
            if script == execute._LAB_ALIAS_SCRIPT:
                return _Res()
            raise AssertionError(f"a non-fixed shell script reached container {c}: {script[:80]!r}")
        if prog == "cat":
            return _Res(0, fs[argv[1]]) if argv[1] in fs else _Res(1, "", "No such file")
        if prog == "cp":
            src, dst = argv[-2], argv[-1]
            if self.fail.get("cp") == (c, src) or src not in fs:
                return _Res(1, "", "cp: cannot copy")
            fs[dst] = fs[src]
            return _Res()
        if prog == "rm":
            p = argv[-1]
            for k in [k for k in fs if k == p or ("-rf" in argv and k.startswith(p + "/"))]:
                del fs[k]
            return _Res()
        if prog == "mkdir":
            return _Res()
        if prog == "sed":
            assert argv[1:3] == ["-i", "-E"], argv
            real_files = not argv[4].startswith(execute.DRYRUN_DIR)
            if self.fail.get("sed") == c or (self.fail.get("sed_real") == c and real_files):
                return _Res(1, "", "sed: -e expression #1, char 3: unknown option to `s'")
            for p in argv[4:]:
                if p not in fs:
                    return _Res(2, "", f"sed: can't read {p}")
                fs[p] = run_sed(argv[3], fs[p])
            return _Res()
        if prog == "swanctl":
            if "--rekey" in argv:
                self.rekeys.append(argv[argv.index("--rekey") + 1])
                if "--ike" in argv and self.rekey_outcome == "up":
                    self.ike_spi += 1
                return _Res()
            if "--list-sas" in argv:
                if self.rekeys and self.rekey_outcome == "down":
                    return _Res(0, "list-sas reply {}\n")
                return _Res(0, "list-sa event {t-tun {uniqueid=1 " + self.sa_fields +
                            f" initiator-spi={self.ike_spi:016x} responder-spi={self.ike_spi + 7:016x}"
                            " child-sas {t-tun-1 {name=t-tun state=INSTALLED mode=TUNNEL protocol=ESP}}}}\nlist-sas reply {}\n")
            return _Res()
        if prog == "tcpdump":
            if not self.fail.get("no_capture"):
                name = Path(argv[argv.index("-w") + 1]).name
                (self.captures_dir / name).write_bytes(b"fake-pcap")
            return _Res()
        if prog in ("pkill", "ip"):
            return _Res()
        raise AssertionError(f"unexpected program in the fake lab: {argv}")
