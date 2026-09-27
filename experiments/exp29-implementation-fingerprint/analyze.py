"""EXP-29 scoring on the held-out TEST split exactly as PREREG.md defines it (the rules were frozen in commit
271ad83 before this ran). Writes results/score.json.

  .venv/bin/python experiments/exp29-implementation-fingerprint/analyze.py
"""
import csv
import json
from collections import Counter
from pathlib import Path

from tunnelscope.evidence.extract import build_records

ROOT = Path(__file__).resolve().parents[2]
CAP = ROOT / "testbed" / "captures"
RESULTS = Path(__file__).resolve().parent / "results"
TRAIN_LSW = {"e7-gcm128", "e7-gcm256", "e7-cbc128", "e7-cbc256", "e7-chacha"}


def test_set():
    """-> [(path, truth initiator, truth responder, group)]"""
    out = []
    for r in csv.DictReader(open(ROOT / "dataset" / "MANIFEST.csv")):
        impl, exp, path = r["implementation"], r["experiment"], r["path"]
        if exp in ("EXP-01/02-cipher", "SYNTHETIC-detector-fixture"):
            continue
        if "openbsd" in impl:
            continue       # EXP-10: two implementations, added below with a truth per end (scorer fix, see RESULT.md)
        if impl.startswith("strongswan"):
            out.append((path, "strongSwan", "strongSwan", "strongSwan " + impl.split("-")[1]))
        elif impl.startswith("libreswan") and Path(path).stem not in TRAIN_LSW:
            out.append((path, "Libreswan", "Libreswan", "Libreswan EXP-07 held-out arms"))
    for p in sorted((CAP / "exp10").glob("*.pcap")):
        out.append((f"exp10/{p.name}", "strongSwan", "OpenBSD iked", "EXP-10 strongSwan -> OpenBSD iked"))
    for p in sorted((CAP / "exp29").glob("*.pcap")):
        out.append((f"exp29/{p.name}", "Libreswan", "Libreswan", "Libreswan new session (after freeze)"))
    for a in (5, 6, 7, 8):
        out.append((f"exp26/mt-m{a}.pcap", "MikroTik RouterOS", "MikroTik RouterOS", "MikroTik M5-M8"))
    for p in sorted((CAP / "exp27").glob("*.pcap")):
        out.append((f"exp27/{p.name}", "strongSwan", "strongSwan", "strongSwan 6.1.0"))
    for p in sorted((CAP / "exp17" / "ike").glob("*.pcap")):
        out.append((f"exp17/ike/{p.name}", "strongSwan", "strongSwan", "strongSwan 6.1.0"))
    # the EXP-10 pair is excluded from MANIFEST's strongSwan rows above because its implementation column
    # names both ends; drop any duplicate path
    seen, uniq = set(), []
    for row in out:
        if row[0] not in seen:
            seen.add(row[0])
            uniq.append(row)
    return uniq


def main():
    RESULTS.mkdir(exist_ok=True)
    rows = []
    for path, ti, tr, group in test_set():
        for rec in build_records(str(CAP / path)):
            if not getattr(rec, "_ike", []):
                continue
            f = rec.findings["implementation"]
            has_init = any(m["exchange"] == 34 for m in rec._ike)
            for end, truth in (("initiator", ti), ("responder", tr)):
                got = (f.value or {}).get(end)
                res = "unknown" if got is None else "correct" if got == truth else "wrong"
                rows.append({"capture": path, "sa": rec.key(), "group": group, "end": end, "truth": truth,
                             "label": got, "result": res, "has_ike_sa_init": has_init, "note": f.note})
    known = [r for r in rows if r["truth"] != "OpenBSD iked" and r["has_ike_sa_init"]]
    by_group = {}
    for g in sorted({r["group"] for r in rows}):
        rs = [r for r in rows if r["group"] == g and r["has_ike_sa_init"]]
        by_group[g] = dict(Counter(r["result"] for r in rs))
    iked = [r for r in rows if r["truth"] == "OpenBSD iked" and r["has_ike_sa_init"]]
    hyp = {"H1_zero_wrong": {"wrong": [r for r in rows if r["result"] == "wrong"],
                             "pass": not any(r["result"] == "wrong" for r in rows)},
           "H2_coverage": {"labelled_correct": sum(r["result"] == "correct" for r in known), "ends": len(known)},
           "H3_iked_unknown": {"results": [r["result"] for r in iked], "pass": bool(iked) and all(r["result"] == "unknown" for r in iked)},
           "H4_strongswan_6": by_group.get("strongSwan 6.1.0", {})}
    hyp["H2_coverage"]["share"] = round(hyp["H2_coverage"]["labelled_correct"] / max(1, len(known)), 3)
    hyp["H2_coverage"]["pass"] = hyp["H2_coverage"]["share"] >= 0.8
    (RESULTS / "score.json").write_text(json.dumps({"hypotheses": hyp, "by_group": by_group, "rows": rows},
                                                   indent=1, default=str) + "\n")
    s = dict(hyp)
    s["H1_zero_wrong"] = {"wrong": [(r["capture"], r["end"], r["truth"], r["label"]) for r in hyp["H1_zero_wrong"]["wrong"]],
                          "pass": hyp["H1_zero_wrong"]["pass"]}
    print(json.dumps({"hypotheses": s, "by_group": by_group}, indent=1, default=str))


if __name__ == "__main__":
    main()
