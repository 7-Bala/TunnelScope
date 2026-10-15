"""EXP-54 mutation checks: each mutant of the rule files must fail at least one test in tests/test_rule_sources.py.

    mkdir -p SCRATCH/experiments && cp -R tunnelscope tests pyproject.toml SCRATCH/ && cp -R experiments/exp54-rule-sources SCRATCH/experiments/
    .venv/bin/python experiments/exp54-rule-sources/mutate.py SCRATCH "$PWD"
"""
import os, re, shutil, subprocess, sys
REPO = sys.argv[1]       # a scratch copy of tunnelscope/, tests/ and experiments/exp54-rule-sources/ (tests/conftest.py strips TUNNELSCOPE_*, so the rules directory cannot be redirected)
SRC_REPO = sys.argv[2]   # the real checkout (its rules are copied in before each mutant; its .venv runs pytest)
M = [
 ("M1 quote word changed (V-207193)", "disa-vpn-srg-v2r6.yaml", 'Verify all IKE proposals are set to use DH Group of 16 or greater', 'Verify all IKE proposals are set to use DH Group of 14 or greater'),
 ("M2 page changed (RFC8247-ENCR 6 -> 7)", "rfc8247-ikev2.yaml", 'page: "rfc8247:6"', 'page: "rfc8247:7"'),
 ("M3 sha256 changed (rfc8221)", "rfc8221-4303-ipsec.yaml", 'sha256: e070689e', 'sha256: e070689f'),
 ("M4 severity changed (V-207223 medium -> high)", "disa-vpn-srg-v2r6.yaml", 'severity: medium\n    fail_message: "IKE integrity below SHA2-384"', 'severity: high\n    fail_message: "IKE integrity below SHA2-384"'),
 ("M5 assertion value changed (V-207193 16 -> 14)", "disa-vpn-srg-v2r6.yaml", 'dh_group_ge, value: 16', 'dh_group_ge, value: 14'),
 ("M6 quote list emptied (CNSA2-AUTH)", "profiles/cnsa2-ipsec.yaml", '      - "This profile REQUIRES the use of digital signature ML-DSA-87"', '      []'),
 ("M7 note removed (V-207223)", "disa-vpn-srg-v2r6.yaml", re.compile(r'    note: "DISA rates this requirement High \(CAT I\).*?"\n'), ''),
 ("M8 unknown source key (CVE-WATCH-INIT-PAYLOADS)", "cve-2026-78135.yaml", 'source: [rfc7296, nvd-CVE-2013-7294, nvd-CVE-2013-6467]', 'source: [rfc7296, nvd-CVE-2013-7294, nvd-CVE-1999-0001]'),
]
res = []
for name, f, old, new in M:
    d = os.path.join(REPO, "tunnelscope", "rules"); shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(os.path.join(SRC_REPO, "tunnelscope", "rules"), d)
    p = os.path.join(d, f); t = open(p).read()
    if isinstance(old, str):
        assert t.count(old) == 1, (name, t.count(old)); t2 = t.replace(old, new)
    else:
        assert old.search(t), name; t2 = old.sub(new, t, count=1)
    assert t2 != t, name
    open(p, "w").write(t2)
    r = subprocess.run([os.path.join(SRC_REPO, ".venv", "bin", "python"), "-m", "pytest", "-q", "-x", "tests/test_rule_sources.py"], capture_output=True, text=True, cwd=REPO)
    caught = r.returncode != 0
    first = next((l for l in r.stdout.splitlines() if l.startswith("FAILED")), "") or r.stdout.strip().splitlines()[-1]
    print(("CAUGHT " if caught else "SURVIVED ") + name + "  <- " + first[:110]); res.append(caught)
print(sum(res), "of", len(res), "caught")
