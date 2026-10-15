"""EXP-54 scorer (pre-registered in PREREG.md). Writes results/summary.json.

    .venv/bin/python experiments/exp54-rule-sources/analyze.py --main-worktree DIR [--sources DIR]

H1: (a) verdicts of all default baselines and all opt-in profiles on every capture are identical to a clean worktree of main;
    (b) every rule's engine-visible fields, the rule order and the file's baseline/authority/url are identical to main's.
H2: every quote is in one of its rule's registered sources (hash-checked), is at least 20 characters, and equals the PREREG appendix.
H3: pages: every quote hits a declared (source, page); every declared page is hit; "n/a" rules hit no paged source.
H4: every rule in the rules directory has non-empty section, page and quote.
H5: every note in the PREREG appendix is in its rule, verbatim.
"""
import argparse
import glob
import hashlib
import html
import importlib.util
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CAPS = os.path.join(REPO, "testbed", "captures")
RULES = os.path.join(REPO, "tunnelscope", "rules")
NEW_FIELDS = {"section", "page", "quote", "source", "note"}
FILES = ["cve-2026-78135.yaml", "disa-vpn-srg-v2r6.yaml", "rfc8221-4303-ipsec.yaml", "rfc8247-ikev2.yaml", "profiles/cnsa2-ipsec.yaml"]


def _exp53():
    spec = importlib.util.spec_from_file_location("exp53", os.path.join(REPO, "experiments", "exp53-nsa-dst-profile", "analyze.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _verdicts(path):
    from tunnelscope.assess.engine import assess_record, available_profiles, load_baselines
    from tunnelscope.evidence.extract import build_records
    b = load_baselines(profiles=available_profiles())
    out = [[(v.rule_id, v.verdict, repr(v.observed), v.message) for v in assess_record(r, b)] for r in build_records(path)]
    return os.path.relpath(path, CAPS), hashlib.sha256(json.dumps(out).encode()).hexdigest(), len(out)


def dump_verdicts(out_file):
    """Run in whichever checkout is on sys.path (this repo, or the main worktree)."""
    import tunnelscope
    caps = _exp53().captures()
    with ProcessPoolExecutor(8) as ex:
        res = {p: [h, n] for p, h, n in ex.map(_verdicts, caps)}
    res["_module"] = os.path.dirname(os.path.abspath(tunnelscope.__file__))
    with open(out_file, "w") as fh:
        json.dump(res, fh)


def normalise(t):
    t = re.sub(r"\s+", " ", t)
    return re.sub(r"(\w)- (\w)", r"\1-\2", t)


def pages(kind, path):
    raw = open(path, encoding="utf-8", errors="replace").read()
    if kind == "txt":
        out, cur = [], []
        for line in raw.splitlines():
            cur.append(line)
            m = re.search(r"\[Page (\d+)\]\s*$", line)
            if m:
                out.append((int(m.group(1)), normalise(" ".join(cur))))
                cur = []
        if cur:
            out.append((None, normalise(" ".join(cur))))
        return out
    if kind == "html":
        t = re.sub(r"(?is)<(script|style).*?</\1>", " ", raw)
        return [(None, normalise(html.unescape(re.sub(r"<[^>]+>", " ", t))))]
    d = json.loads(raw)
    v = d["vulnerabilities"][0]["cve"] if "vulnerabilities" in d else d
    return [(None, normalise(" ".join(x["value"] for x in v["descriptions"] if x["lang"] == "en")))]


def kind_of(name):
    return "nvd" if name.endswith(".json") else "html" if name.endswith(".html") else "txt"


def prereg():
    """(source hashes, {rule: (section, pages, [quotes], note|None)}) parsed from PREREG.md itself."""
    text = open(os.path.join(HERE, "PREREG.md"), encoding="utf-8").read()
    hashes = {}
    rules = {}
    for line in text.splitlines():
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if line.startswith("| `") and len(cells) == 4 and re.fullmatch(r"[0-9a-f]{64}", cells[2]):
            hashes[cells[0]] = (cells[1], cells[2])
        elif re.match(r"\| \d+ \|", line) and len(cells) == 7:
            rules[cells[1]] = {"file": cells[2], "source": [s.strip().strip("`") for s in cells[3].split(",")],
                               "section": cells[4], "page": cells[5], "n": int(cells[6]), "quote": [], "note": None}
    cur = None
    for line in text.split("## Appendix", 1)[1].splitlines():
        m = re.fullmatch(r"\*\*(.+)\*\*", line.strip())
        if m:
            cur = m.group(1)
        elif cur and line.startswith("- “") and line.endswith("”"):
            rules[cur]["quote"].append(line[3:-1])
        elif cur and line.startswith("- *Note to be recorded:* "):
            rules[cur]["note"] = line[len("- *Note to be recorded:* "):]
    return hashes, rules


def load_yaml(root, rel):
    import yaml
    with open(os.path.join(root, "tunnelscope", "rules", rel)) as fh:
        return yaml.safe_load(fh)


def all_rule_files(root):
    base = os.path.join(root, "tunnelscope", "rules")
    return sorted(os.path.relpath(p, base) for p in glob.glob(os.path.join(base, "*.yaml")) + glob.glob(os.path.join(base, "profiles", "*.yaml")))


def strip(doc):
    d = {k: v for k, v in doc.items() if k not in ("sources", "rules")}
    return [d, [{k: v for k, v in r.items() if k not in NEW_FIELDS} for r in doc["rules"]]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--main-worktree")
    ap.add_argument("--sources", default=os.path.expanduser("~/Datasets/sources/part4"))
    ap.add_argument("--dump", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.dump:
        return dump_verdicts(a.dump)
    main_root = os.path.abspath(a.main_worktree)
    res_dir = os.path.join(HERE, "results")
    os.makedirs(res_dir, exist_ok=True)
    reg_hashes, reg_rules = prereg()

    # H1(a)
    env = {"HOME": os.environ["HOME"], "PATH": os.environ["PATH"]}
    outs = {}
    for name, root in (("branch", REPO), ("main", main_root)):
        out = os.path.join(res_dir, f".verdicts-{name}.json")
        subprocess.run([sys.executable, os.path.abspath(__file__), "--dump", out], cwd=root, check=True, env={**env, "PYTHONPATH": root})
        with open(out) as fh:
            outs[name] = json.load(fh)
        os.remove(out)
        mod = outs[name].pop("_module")
        if mod != os.path.join(root, "tunnelscope"):
            sys.exit(f"H1 run for {name} imported {mod}, expected {root}/tunnelscope")
    diff = sorted(p for p in set(outs["branch"]) | set(outs["main"]) if outs["branch"].get(p) != outs["main"].get(p))
    main_head = subprocess.run(["git", "-C", main_root, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()

    # H1(b)
    files = all_rule_files(REPO)
    view_diff = [f for f in sorted(set(files) | set(all_rule_files(main_root)))
                 if f not in files or not os.path.isfile(os.path.join(main_root, "tunnelscope", "rules", f))
                 or strip(load_yaml(REPO, f)) != strip(load_yaml(main_root, f))]
    h1 = {"main": main_head, "captures_compared": len(outs["main"]), "verdict_differences": diff,
          "rule_files_compared": len(files), "rule_view_differences": view_diff,
          "pass": not diff and not view_diff and len(outs["main"]) == len(outs["branch"]) and len(outs["main"]) > 0}

    # H2 / H3
    cache, src_report = {}, {}
    for key, (fname, want) in reg_hashes.items():
        path = os.path.join(a.sources, fname)
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        src_report[key] = digest == want
        if digest != want:
            sys.exit(f"refusing: {path} has SHA-256 {digest}, pre-registered {want}")
        cache[key] = pages(kind_of(fname), path)
    checked, missing, short, not_registered, page_viol, meta_viol, sources_map_viol = 0, [], [], [], [], [], []
    notes_missing = []
    for rel in FILES:
        doc = load_yaml(REPO, rel)
        smap = doc.get("sources") or {}
        for key, ent in smap.items():
            if key not in reg_hashes or ent.get("sha256") != reg_hashes[key][1] or ent.get("file") != reg_hashes[key][0]:
                sources_map_viol.append((rel, key))
        for r in doc["rules"]:
            reg = reg_rules.get(r["id"])
            if reg is None or reg["file"] != rel:
                meta_viol.append((r["id"], "not in the PREREG table / wrong file"))
                continue
            if (r.get("section"), r.get("page"), r.get("source")) != (reg["section"], reg["page"], reg["source"]):
                meta_viol.append((r["id"], "section/page/source differs from the PREREG"))
            if list(r.get("quote") or []) != reg["quote"] or len(reg["quote"]) != reg["n"]:
                not_registered.append(r["id"])
            if reg["note"] and r.get("note") != reg["note"]:
                notes_missing.append(r["id"])
            if not reg["note"] and r.get("note"):
                notes_missing.append(r["id"] + " (unregistered note)")
            if any(k not in smap for k in r.get("source", [])):
                sources_map_viol.append((rel, r["id"], "source key not in the sources map"))
            hit_pages = set()
            declared = set() if r["page"] == "n/a" else {(s.split(":")[0].strip(), int(n)) for s in r["page"].split(";") for n in s.split(":")[1].split(",")}
            for q in r["quote"]:
                checked += 1
                if len(q) < 20:
                    short.append((r["id"], q))
                hits = {(k, p) for k in r["source"] for p, t in cache[k] if normalise(q) in t}
                if not hits:
                    missing.append((r["id"], q))
                    continue
                paged = {h for h in hits if h[1] is not None}
                if not declared and paged:
                    page_viol.append((r["id"], q, "page is n/a but the quote is in a paged source"))
                elif declared and not (paged & declared) and len(paged) == len(hits):
                    page_viol.append((r["id"], q, "only paged hits, none on a declared page"))
                hit_pages |= paged & declared
            if hit_pages != declared:
                page_viol.append((r["id"], "declared page never hit", sorted(declared - hit_pages)))
    h2 = {"quotes": checked, "missing": missing, "too_short": short, "differ_from_prereg": not_registered,
          "source_hashes_ok": src_report, "sources_map_violations": sources_map_viol,
          "pass": not missing and not short and not not_registered and not sources_map_viol and all(src_report.values())
          and set(reg_rules) == {r["id"] for rel in FILES for r in load_yaml(REPO, rel)["rules"]}}
    h3 = {"violations": page_viol, "meta_violations": meta_viol, "pass": not page_viol and not meta_viol}

    # H4
    total, lacking = 0, []
    for rel in files:
        for r in load_yaml(REPO, rel)["rules"]:
            total += 1
            if not (r.get("section") and r.get("page") and isinstance(r.get("quote"), list) and r["quote"]):
                lacking.append((rel, r["id"]))
    h4 = {"rules": total, "without_source": lacking, "pass": not lacking}
    h5 = {"notes_registered": sum(1 for v in reg_rules.values() if v["note"]), "problems": notes_missing, "pass": not notes_missing}

    summary = {"H1_nothing_the_engine_reads_changed": h1, "H2_quotes_verbatim": h2, "H3_pages": h3, "H4_coverage": h4, "H5_notes": h5}
    with open(os.path.join(res_dir, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1, sort_keys=True)
    print(json.dumps({k: v["pass"] for k, v in summary.items()}))


if __name__ == "__main__":
    main()
