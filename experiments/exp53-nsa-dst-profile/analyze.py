"""EXP-53 scorer (pre-registered in PREREG.md, bad7fdf). Writes results/summary.json.

    .venv/bin/python experiments/exp53-nsa-dst-profile/analyze.py --nsa-pdf PATH/NSA-configuring-ipsec-vpns.pdf \
        --dst-pdf PATH/dst-taskforce-4feb26.pdf --main-worktree DIR

H1: default verdicts on every capture, this checkout vs a clean worktree of main (run there with main's code). The DST baseline is
    a default baseline, so its provenance edit is covered here.
H2: every quote in the NSA profile is in the normalised `pdftotext -raw` text of the NSA PDF, and every quote added to the DST
    baseline is in the normalised text of the DST PDF, each with its pre-registered hash.
H3: the PREREG table's verdicts (parsed from PREREG.md itself, so the two cannot drift).
H4: no profile rule PASSes on an absent / UNKNOWN / NOT_OBSERVABLE attribute, over the whole corpus.
H5: the DST rules keep id, attribute, assertion, severity and message (pinned by tests/test_nsa_ipsec_profile.py; here compared with main).
"""
import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CAPS = os.path.join(REPO, "testbed", "captures")
PROFILE = "nsa-ipsec-config"
NSA_SHA256 = "5b972578242cca5c49233863754b5bea9493ef416380434a0f08c68030ecff56"
DST_SHA256 = "461d8b42aea3847a3f9083e369065eff7985b03f8e4b1e9974f236ce93d99f31"
LETTER = {"P": "PASS", "F": "FAIL", "U": "UNKNOWN", "N": "NOT_OBSERVABLE", "-": None}


def captures():
    return sorted(p for p in glob.glob(os.path.join(CAPS, "**", "*.pcap*"), recursive=True) if not p.endswith(".json"))


def _default_verdicts(path):
    from tunnelscope.assess.engine import assess_record, load_baselines
    from tunnelscope.evidence.extract import build_records
    b = load_baselines()
    out = [[(v.rule_id, v.verdict, repr(v.observed), v.message) for v in assess_record(r, b)]
           for r in build_records(path)]
    return os.path.relpath(path, CAPS), hashlib.sha256(json.dumps(out).encode()).hexdigest(), len(out)


def dump_defaults(out_file):
    """Run in whichever checkout is on sys.path (this repo, or the main worktree)."""
    import tunnelscope
    with ProcessPoolExecutor(8) as ex:
        res = {p: [h, n] for p, h, n in ex.map(_default_verdicts, captures())}
    res["_module"] = os.path.dirname(os.path.abspath(tunnelscope.__file__))
    with open(out_file, "w") as fh:
        json.dump(res, fh)


def _profile_check(path):
    from tunnelscope.assess.engine import assess_record, load_baselines
    from tunnelscope.evidence.extract import build_records
    from tunnelscope.evidence.record import Status
    b = load_baselines(profiles=[PROFILE])
    rows, bad = [], []
    for r in build_records(path):
        vs = {v.rule_id: v.verdict for v in assess_record(r, b) if v.rule_id.startswith("NSA-")}
        rows.append(vs)
        for rule in b[-1]["rules"]:
            f = r.findings.get(rule["attribute"])
            if vs.get(rule["id"]) == "PASS" and (f is None or f.status in (Status.UNKNOWN, Status.NOT_OBSERVABLE)):
                bad.append(rule["id"])
    return os.path.relpath(path, CAPS), rows, bad


def normalise(t):
    t = re.sub(r"\s+", " ", t)
    return re.sub(r"(\w)- (\w)", r"\1-\2", t)


def _pdf_text(pdf, want_sha):
    with open(pdf, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != want_sha:
        sys.exit(f"refusing: {pdf} has SHA-256 {digest}, pre-registered {want_sha}")
    return digest, normalise(subprocess.run(["pdftotext", "-raw", pdf, "-"], capture_output=True, text=True, check=True).stdout)


def h2(nsa_pdf, dst_pdf):
    import yaml
    out = {}
    for name, pdf, sha, path in (
            ("nsa", nsa_pdf, NSA_SHA256, os.path.join(REPO, "tunnelscope", "rules", "profiles", f"{PROFILE}.yaml")),
            ("dst", dst_pdf, DST_SHA256, os.path.join(REPO, "tunnelscope", "rules", "dst-nqm-pq.yaml"))):
        digest, text = _pdf_text(pdf, sha)
        with open(path) as fh:
            rules = yaml.safe_load(fh)["rules"]
        checked = [{"rule": r["id"], "quote": q, "found": normalise(q) in text} for r in rules for q in r["quote"]]
        out[name] = {"pdf_sha256": digest, "quotes": len(checked), "found": sum(c["found"] for c in checked),
                     "missing": [c for c in checked if not c["found"]], "pass": all(c["found"] for c in checked)}
    out["pass"] = all(out[k]["pass"] for k in ("nsa", "dst"))
    return out


def prereg_table():
    rows = {}
    with open(os.path.join(HERE, "PREREG.md")) as fh:
        for line in fh:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) == 10 and ".pcap" in cells[0]:
                rows[cells[0].split()[0]] = [LETTER[c.split()[0]] for c in cells[1:]]
    return rows


def dst_rules_view(root):
    """The DST rules' engine-visible fields in a checkout (main's, or this branch's)."""
    import yaml
    with open(os.path.join(root, "tunnelscope", "rules", "dst-nqm-pq.yaml")) as fh:
        doc = yaml.safe_load(fh)
    return [(r["id"], r["attribute"], r["assert"], r["severity"], r["fail_message"], r["title"]) for r in doc["rules"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nsa-pdf")
    ap.add_argument("--dst-pdf")
    ap.add_argument("--main-worktree")
    ap.add_argument("--dump-defaults", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.dump_defaults:
        return dump_defaults(a.dump_defaults)
    sys.path.insert(0, REPO)
    from tunnelscope.assess.engine import load_baselines
    order = [r["id"] for r in load_baselines(profiles=[PROFILE])[-1]["rules"]]
    res_dir = os.path.join(HERE, "results")
    os.makedirs(res_dir, exist_ok=True)

    # H1: same script, run once per checkout in a clean environment (no TUNNELSCOPE_* variables)
    env = {"HOME": os.environ["HOME"], "PATH": os.environ["PATH"]}
    outs = {}
    for name, root in (("branch", REPO), ("main", os.path.abspath(a.main_worktree))):
        out = os.path.join(res_dir, f".defaults-{name}.json")
        subprocess.run([sys.executable, os.path.abspath(__file__), "--dump-defaults", out], cwd=root, check=True,
                       env={**env, "PYTHONPATH": root})
        with open(out) as fh:
            outs[name] = json.load(fh)
        os.remove(out)
        mod = outs[name].pop("_module")
        if mod != os.path.join(root, "tunnelscope"):     # H1 must compare two different code trees
            sys.exit(f"H1 run for {name} imported {mod}, expected {root}/tunnelscope")
    diff = sorted(p for p in set(outs["branch"]) | set(outs["main"]) if outs["branch"].get(p) != outs["main"].get(p))
    main_head = subprocess.run(["git", "-C", a.main_worktree, "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True).stdout.strip()

    with ProcessPoolExecutor(8) as ex:
        prof = {p: (rows, bad) for p, rows, bad in ex.map(_profile_check, captures())}

    table = prereg_table()
    h3 = []
    for cap, want in table.items():
        rows = prof[cap][0]
        got = [rows[0].get(rid) for rid in order] if len(rows) == 1 else None
        h3.append({"capture": cap, "sas": len(rows), "want": want, "got": got, "match": got == want})

    counts = {rid: {} for rid in order}
    for rows, _ in prof.values():
        for vs in rows:
            for rid in order:
                v = vs.get(rid) or "no verdict"
                counts[rid][v] = counts[rid].get(v, 0) + 1
    h4_bad = {p: bad for p, (_, bad) in prof.items() if bad}
    dst_branch, dst_main = dst_rules_view(REPO), dst_rules_view(os.path.abspath(a.main_worktree))

    summary = {
        "captures": len(prof), "sas": sum(len(r) for r, _ in prof.values()),
        "H1_defaults_unchanged": {"main": main_head, "captures_compared": len(outs["main"]),
                                  "differences": diff, "pass": not diff and len(outs["main"]) == len(prof)},
        "H2_quotes_verbatim": h2(a.nsa_pdf, a.dst_pdf),
        "H3_preregistered_verdicts": {"rows": h3, "matched": sum(r["match"] for r in h3), "of": len(h3),
                                      "pass": all(r["match"] for r in h3) and len(h3) == 10},
        "H4_no_pass_without_evidence": {"violations": h4_bad, "pass": not h4_bad},
        "H5_dst_rules_unchanged": {"main": dst_main, "branch": dst_branch, "pass": dst_main == dst_branch},
        "verdict_counts_per_rule": counts,
    }
    with open(os.path.join(res_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1, sort_keys=True)
    print(json.dumps({k: v.get("pass") for k, v in summary.items() if isinstance(v, dict) and "pass" in v}))


if __name__ == "__main__":
    main()
