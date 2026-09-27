"""EXP-28 scoring as PREREG.md defines it. Controls: the lab configs that produced the captures (initiator and
responder sides). Drift arms D1-D6 and the key-length honesty arm K: a copy of a control connection's parsed
config with exactly one field changed (the parser itself is validated by T-120). Writes results/score.json.

  .venv/bin/python experiments/exp28-config-vs-wire/analyze.py
"""
import copy
import json
from collections import Counter
from pathlib import Path

from tunnelscope.config import parse_file
from tunnelscope.config.reconcile import MATCH, MISMATCH, NOT_COMPARABLE, esp_family, reconcile, role
from tunnelscope.evidence.extract import build_records

ROOT = Path(__file__).resolve().parents[2]
CONFIGS, CAPS = ROOT / "testbed" / "configs", ROOT / "testbed" / "captures"
RESULTS = Path(__file__).resolve().parent / "results"


def pairs():
    """(config file, side, tunnel, capture) for every connection with a capture of the same name
    (or its rekey-*-run2 capture)."""
    caps = {p.stem: p for p in CAPS.rglob("*.pcap")}
    out, seen = [], set()
    for cf in sorted(p for p in CONFIGS.rglob("*.conf") if p.name != "strongswan.conf"):
        side = "responder-file" if "bob" in str(cf) else "initiator-file"
        for t in parse_file(cf)["tunnels"]:
            for stem in (t["name"], f"rekey-{t['name']}-run2"):
                if stem in caps and (side, stem) not in seen:
                    seen.add((side, stem))
                    out.append((cf, side, t, caps[stem]))
    return out


def record(cap, cache={}):
    if cap not in cache:
        cache[cap] = next(r for r in build_records(str(cap)) if getattr(r, "_ike", []))
    return cache[cap]


def outcome(comps, field):
    return next((c for c in comps if c.field == field), None)


def drifts(t, rec):
    """-> [(arm, field, changed tunnel)] : one field changed per copy."""
    out = []
    wire = {a: rec.findings[a].value for a in ("ike_dh_group", "ike_encr", "pfs", "pq_key_exchange") if a in rec.findings}
    if t["ike_proposals"]:
        d = copy.deepcopy(t)
        new = "MODP-3072" if wire.get("ike_dh_group") == "ECP-384" else "ECP-384"
        for p in d["ike_proposals"]:
            p["ke"] = [new]
        out.append(("D1", "ike_dh_group", d))
        d = copy.deepcopy(t)
        new = "AES-CBC-128" if wire.get("ike_encr") != "AES-CBC-128" else "AES-CBC-256"
        for p in d["ike_proposals"]:
            p["encr"] = [new]
        out.append(("D2", "ike_encr", d))
        d = copy.deepcopy(t)
        if any(p["addke"] for p in d["ike_proposals"]):
            for p in d["ike_proposals"]:
                p["addke"] = {}
        else:
            for p in d["ike_proposals"]:
                p["addke"] = {1: ["ML-KEM-768"]}
        out.append(("D6", "pq_key_exchange", d))
    if len(t["children"]) == 1 and t["children"][0]["esp_proposals"]:
        esp = t["children"][0]["esp_proposals"]
        fams = {esp_family(e, (p["integ"] or [None])[0]) for p in esp for e in p["encr"]}
        d = copy.deepcopy(t)
        if "AES-GCM-16" in fams:
            d["children"][0]["esp_proposals"] = [{**esp[0], "encr": ["AES-CBC-256"], "integ": ["HMAC-SHA2-256-128"]}]
        else:
            d["children"][0]["esp_proposals"] = [{**esp[0], "encr": ["AES-GCM-16-256"], "integ": []}]
        out.append(("D3", "esp_cipher_family", d))
        d = copy.deepcopy(t)
        for p in d["children"][0]["esp_proposals"]:
            p["encr"] = [e.replace("-256", "-128") if e.endswith("-256") else e.replace("-128", "-256") for e in p["encr"]]
        out.append(("K", "esp_key_length", d))
        if t["children"][0]["pfs"] is not None:
            d = copy.deepcopy(t)
            d["children"][0]["pfs"] = not t["children"][0]["pfs"]
            out.append(("D4", "pfs", d))
    if t.get("ppk") is not None or t["name"].startswith("ppk-"):
        d = copy.deepcopy(t)
        d["ppk"] = None if t.get("ppk") else {"id": "drift", "required": False}
        out.append(("D5", "pq_ppk", d))
    return out


def main():
    RESULTS.mkdir(exist_ok=True)
    controls, drift_rows = [], []
    for cf, side, t, cap in pairs():
        rec = record(cap)
        comps = reconcile(t, rec)
        controls.append({"config": str(cf.relative_to(ROOT)), "side": side, "connection": t["name"], "capture": cap.name,
                         "outcomes": {c.field: c.outcome for c in comps},
                         "mismatches": [c.__dict__ for c in comps if c.outcome == MISMATCH],
                         "unobservable_as_match": [c.field for c in comps if c.outcome == MATCH and c.wire is None]})
        if side != "initiator-file":
            continue
        for arm, field, d in drifts(t, rec):
            c = outcome(reconcile(d, rec), field)
            # observable = the wire shows the field AND it is this config's own business in this capture
            # (EXP-28 first run: a-start's initiator is the cloud side, so alice's config is the responder there)
            own = field not in ("pq_key_exchange", "pq_ppk") or role(t, rec) == "initiator" or isinstance(c.wire, list)
            wire_ok = field != "esp_key_length" and c.wire is not None and own
            drift_rows.append({"arm": arm, "connection": t["name"], "capture": cap.name, "field": field,
                               "outcome": c.outcome, "config": c.config, "wire": c.wire, "note": c.note,
                               "wire_shows_field": wire_ok})
    cm = [m for r in controls for m in r["mismatches"]]
    by_arm = {}
    for arm in ("D1", "D2", "D3", "D4", "D5", "D6", "K"):
        rows = [r for r in drift_rows if r["arm"] == arm]
        by_arm[arm] = {"n": len(rows), "outcomes": dict(Counter(r["outcome"] for r in rows)),
                       "observable": sum(r["wire_shows_field"] for r in rows),
                       "observable_detected": sum(r["wire_shows_field"] and r["outcome"] == MISMATCH for r in rows)}
    observable = [r for r in drift_rows if r["arm"] != "K" and r["wire_shows_field"]]
    hyp = {"H1_no_false_alarms": {"control_pairs": len(controls),
                                  "initiator_files": sum(r["side"] == "initiator-file" for r in controls),
                                  "responder_files": sum(r["side"] == "responder-file" for r in controls),
                                  "mismatches": len(cm), "pass": not cm},
           "H2_catches_drift": {"observable_changes": len(observable),
                                "detected": sum(r["outcome"] == MISMATCH for r in observable),
                                "missed": [r for r in observable if r["outcome"] != MISMATCH],
                                "not_comparable_changes": sum(1 for r in drift_rows if r["arm"] != "K" and not r["wire_shows_field"]),
                                "by_arm": by_arm},
           "H3_key_length_honesty": {"n": by_arm["K"]["n"], "outcomes": by_arm["K"]["outcomes"],
                                     "pass": by_arm["K"]["n"] > 0 and set(by_arm["K"]["outcomes"]) == {NOT_COMPARABLE}},
           "H4_unobservable_never_match": {"violations": [(r["connection"], r["unobservable_as_match"]) for r in controls
                                                          if r["unobservable_as_match"]]}}
    hyp["H2_catches_drift"]["pass"] = not hyp["H2_catches_drift"]["missed"]
    hyp["H4_unobservable_never_match"]["pass"] = not hyp["H4_unobservable_never_match"]["violations"]
    (RESULTS / "score.json").write_text(json.dumps({"hypotheses": hyp, "controls": controls, "drift": drift_rows},
                                                   indent=1, default=str) + "\n")
    summary = copy.deepcopy(hyp)
    summary["H2_catches_drift"]["missed"] = [(r["arm"], r["connection"], r["outcome"], r["config"], r["wire"])
                                             for r in hyp["H2_catches_drift"]["missed"]]
    print(json.dumps(summary, indent=1, default=str))
    for m in cm:
        print("CONTROL MISMATCH", m)


if __name__ == "__main__":
    main()
