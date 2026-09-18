#!/usr/bin/env python3
"""T-054 — full-findings differential (plan §5 P1-1).

Runs the extractor pipeline of two code versions (a base git ref and the working
tree) over the SAME set of captures (the working tree's testbed/captures) and
compares every finding's status, value and confidence, record by record. Any
difference fails the run unless it matches an entry in build/findings-allow.txt.

This is the check T-052/T-053 did by hand: a change that "only fixes X" must
show that it changes only X. Unit tests and the e2e check cover the fields
with ground truth; this covers every other finding on every capture.

  python3 build/findings_diff.py --base origin/main          # compare, exit 1 on unallowed change
  python3 build/findings_diff.py --base HEAD --report out.md # also write a markdown report

Allow-file lines:  <pcap glob> :: <finding glob>  # <reason, required>
e.g.               encap/ipv6-* :: *  # T-057: IPv6 ESP now parsed
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAP = os.path.join(ROOT, "testbed", "captures")
ALLOW = os.path.join(ROOT, "build", "findings-allow.txt")

# Runs inside a child process with the code under test first on sys.path, so
# base and head never share imported modules. Kept free of anything newer than
# the oldest base it has to run against: only build_records and plain fields.
_DUMP = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from tunnelscope.evidence.extract import build_records
out = {}
for rel in json.load(sys.stdin):
    try:
        recs = build_records(sys.argv[2] + "/" + rel)
    except Exception as e:
        out[rel] = {"<error>": {"<pipeline>": ["ERROR", type(e).__name__, None]}}
        continue
    per = {}
    for r in recs:
        if getattr(r, "_esp_only", False) or not r.ike_spi_i:
            key = "esp:" + "|".join(sorted([r.src, r.dst]))
        else:
            key = "ike:" + r.ike_spi_i
        f = {}
        for name, x in r.findings.items():
            conf = getattr(x, "confidence", None)
            f[name] = [x.status.value, x.value, round(conf, 3) if isinstance(conf, float) else conf]
        per[key] = json.loads(json.dumps(f, sort_keys=True, default=str))
    out[rel] = per
json.dump(out, sys.stdout, sort_keys=True)
"""


def captures() -> list[str]:
    rels = []
    for d, _, files in os.walk(CAP):
        for fn in files:
            if fn.endswith(".pcap"):   # every capture, EXP-05's sub-dataset included (plan §4.2: all of them)
                rels.append(os.path.relpath(os.path.join(d, fn), CAP))
    return sorted(rels)


def dump(code_root: str, rels: list[str]) -> dict:
    proc = subprocess.run([sys.executable, "-c", _DUMP, code_root, CAP], input=json.dumps(rels),
                          capture_output=True, text=True, cwd=code_root)
    if proc.returncode != 0:
        raise SystemExit(f"dump failed for {code_root}:\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def load_allow(path: str) -> list[tuple[str, str, str]]:
    rules = []
    if not os.path.exists(path):
        return rules
    for n, line in enumerate(open(path), 1):
        body = line.split("#", 1)
        spec, reason = body[0].strip(), (body[1].strip() if len(body) > 1 else "")
        if not spec:
            continue
        if "::" not in spec or not reason:
            raise SystemExit(f"{path}:{n}: need '<pcap glob> :: <finding glob>  # reason'")
        pcap_glob, finding_glob = (s.strip() for s in spec.split("::", 1))
        rules.append((pcap_glob, finding_glob, reason))
    return rules


def diff(base: dict, head: dict) -> list[tuple[str, str, str, object, object]]:
    """(pcap, record, finding, base value, head value) for every difference."""
    out = []
    for pcap in sorted(set(base) | set(head)):
        b, h = base.get(pcap, {}), head.get(pcap, {})
        for rec in sorted(set(b) | set(h)):
            if rec not in b or rec not in h:
                out.append((pcap, rec, "<record>", "present" if rec in b else "absent",
                            "present" if rec in h else "absent"))
                continue
            for name in sorted(set(b[rec]) | set(h[rec])):
                bv, hv = b[rec].get(name), h[rec].get(name)
                if bv != hv:
                    out.append((pcap, rec, name, bv, hv))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", required=True, help="git ref to compare against (e.g. origin/main)")
    ap.add_argument("--allow", default=ALLOW)
    ap.add_argument("--report", help="write a markdown report here")
    args = ap.parse_args()

    rels = captures()
    with tempfile.TemporaryDirectory() as tmp:
        wt = os.path.join(tmp, "base")
        subprocess.run(["git", "-C", ROOT, "worktree", "add", "--detach", wt, args.base],
                       check=True, capture_output=True)
        try:
            base = dump(wt, rels)
        finally:
            subprocess.run(["git", "-C", ROOT, "worktree", "remove", "--force", wt], capture_output=True)
    head = dump(ROOT, rels)

    rules = load_allow(args.allow)
    used = set()
    changes = diff(base, head)
    rows = []
    for pcap, rec, name, bv, hv in changes:
        hit = next((i for i, (pg, fg, _) in enumerate(rules)
                    if fnmatch.fnmatch(pcap, pg) and fnmatch.fnmatch(name, fg)), None)
        if hit is not None:
            used.add(hit)
        rows.append((hit, pcap, rec, name, bv, hv))
    bad = [r for r in rows if r[0] is None]

    lines = [f"# Findings differential: `{args.base}` → working tree", "",
             f"{len(rels)} captures · {len(changes)} changed finding(s) · "
             f"{len(changes) - len(bad)} allowed · **{len(bad)} not allowed**", ""]
    if rows:
        lines += ["| Allowed by | Capture | Record | Finding | Base | Head |", "|---|---|---|---|---|---|"]
        for hit, pcap, rec, name, bv, hv in rows:
            who = f"line: {rules[hit][2]}" if hit is not None else "**NOT ALLOWED**"
            lines.append(f"| {who} | `{pcap}` | `{rec}` | `{name}` | `{json.dumps(bv)[:80]}` | "
                         f"`{json.dumps(hv)[:80]}` |")
    stale = [r for i, r in enumerate(rules) if i not in used]
    if stale:
        lines += ["", "Allow-file entries that matched nothing (safe to delete once merged):"]
        lines += [f"- `{pg} :: {fg}`  # {reason}" for pg, fg, reason in stale]
    text = "\n".join(lines) + "\n"
    print(text)
    if args.report:
        open(args.report, "w").write(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
