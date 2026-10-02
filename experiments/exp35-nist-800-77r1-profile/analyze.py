"""EXP-35 scorer (pre-registered in PREREG.md, 654e2ff). Writes results/summary.json.

    .venv/bin/python experiments/exp35-nist-800-77r1-profile/analyze.py --pdf PATH/NIST.SP.800-77r1.pdf --main-worktree DIR

H1: default verdicts on every capture, this checkout vs a clean worktree of main (run there with main's code).
H2: every profile quote is in the normalised `pdftotext -raw` text of the PDF with the pre-registered hash.
H3: the PREREG table's verdicts (parsed from PREREG.md itself, so the two cannot drift).
H4: no profile rule PASSes on an absent / UNKNOWN / NOT_OBSERVABLE attribute, over the whole corpus.
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
PROFILE = "nist-sp800-77r1"
PDF_SHA256 = "bc2a36dcccf96476d4e0d09468901726c930f2554115c440988bae746074bd70"
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
        vs = {v.rule_id: v.verdict for v in assess_record(r, b) if v.rule_id.startswith("NIST77")}
        rows.append(vs)
        for rule in b[-1]["rules"]:
            f = r.findings.get(rule["attribute"])
            if vs.get(rule["id"]) == "PASS" and (f is None or f.status in (Status.UNKNOWN, Status.NOT_OBSERVABLE)):
                bad.append(rule["id"])
    return os.path.relpath(path, CAPS), rows, bad


def normalise(t):
    t = re.sub(r"\s+", " ", t)
    return re.sub(r"(\w)- (\w)", r"\1-\2", t)


def h2(pdf):
    import yaml
    with open(pdf, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    if digest != PDF_SHA256:
        sys.exit(f"refusing: {pdf} has SHA-256 {digest}, pre-registered {PDF_SHA256}")
    text = normalise(subprocess.run(["pdftotext", "-raw", pdf, "-"], capture_output=True, text=True, check=True).stdout)
    with open(os.path.join(REPO, "tunnelscope", "rules", "profiles", f"{PROFILE}.yaml")) as fh:
        rules = yaml.safe_load(fh)["rules"]
    checked = [{"rule": r["id"], "quote": q, "found": q in text} for r in rules for q in r["quote"]]
    return {"pdf_sha256": digest, "quotes": len(checked), "found": sum(c["found"] for c in checked),
            "missing": [c for c in checked if not c["found"]], "pass": all(c["found"] for c in checked)}


def prereg_table():
    rows = {}
    with open(os.path.join(HERE, "PREREG.md")) as fh:
        for line in fh:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) == 12 and ".pcap" in cells[0]:
                rows[cells[0].split()[0]] = [LETTER[c.split()[0]] for c in cells[1:]]
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdf")
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
    esp_decided = {rid: {k: counts[rid].get(k, 0) for k in ("PASS", "FAIL")}
                   for rid in ("NIST77-ESP-ENCR", "NIST77-ESP-INTEG")}

    summary = {
        "captures": len(prof), "sas": sum(len(r) for r, _ in prof.values()),
        "H1_defaults_unchanged": {"main": main_head, "captures_compared": len(outs["main"]),
                                  "differences": diff, "pass": not diff and len(outs["main"]) == len(prof)},
        "H2_quotes_verbatim": h2(a.pdf),
        "H3_preregistered_verdicts": {"rows": h3, "matched": sum(r["match"] for r in h3), "of": len(h3),
                                      "pass": all(r["match"] for r in h3) and len(h3) == 10},
        "H3_corpus_esp_rules_undecided": {"counts": esp_decided,
                                          "pass": all(v == {"PASS": 0, "FAIL": 0} for v in esp_decided.values())},
        "H4_no_pass_without_evidence": {"violations": h4_bad, "pass": not h4_bad},
        "verdict_counts_per_rule": counts,
    }
    with open(os.path.join(res_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1, sort_keys=True)
    print(json.dumps({k: v.get("pass") for k, v in summary.items() if isinstance(v, dict) and "pass" in v}))


if __name__ == "__main__":
    main()
