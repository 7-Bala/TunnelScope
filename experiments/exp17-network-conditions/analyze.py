#!/usr/bin/env python3
"""EXP-17 analysis: network conditions (delay, jitter, packet loss).
Evaluates predictions P17-1 through P17-6 and writes results/exp17_results.json.
"""
import csv
import gzip
import importlib.util
import json
from pathlib import Path
import sys

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/models"))
sys.path.insert(0, str(ROOT))

from make_traffic_data import load  # noqa: E402
from tunnelscope.assess.engine import assess_record  # noqa: E402
from tunnelscope.evidence.extract import build_records  # noqa: E402
from tunnelscope.evidence.record import EvidenceRecord  # noqa: E402
from tunnelscope.leakage.attacker import _model, extract_attacker, window_features  # noqa: E402
from tunnelscope.leakage.mode_model import infer_mode  # noqa: E402


def macro_f1(y_true, y_pred):
    return round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4)


def load_exp17_sessions(cap_dir: Path):
    manifest_file = cap_dir / "manifest.csv"
    if not manifest_file.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_file}")

    sessions = []
    seen = set()
    with open(manifest_file, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 7:
                continue
            tag, arm, cls, rep, seed, npk, sha = [x.strip() for x in row[:7]]
            if tag in seen:
                continue
            seen.add(tag)

            prof, part = arm.split("-", 1)
            pkt_file = cap_dir / f"{tag}.pkts.csv.gz"
            pkts = []
            if pkt_file.exists():
                with gzip.open(pkt_file, "rt") as gf:
                    greader = csv.reader(gf)
                    next(greader, None)  # header: t,dir,len
                    for r in greader:
                        if len(r) >= 3 and r[2]:
                            pkts.append((float(r[0]), r[1], int(r[2])))

            windows = window_features(pkts)
            sessions.append({
                "tag": tag,
                "arm": arm,
                "profile": prof,
                "part": part,
                "class": cls,
                "rep": int(rep),
                "seed": int(seed),
                "packets_count": int(npk),
                "sha256": sha,
                "pkts": pkts,
                "windows": windows,
            })
    return sessions


def analyze_p17_1_and_2(sessions, rf):
    """P17-1 (wan) and P17-2 (lossy): evaluate shipped model on pooled windows."""
    out = {}
    for prof in ("wan", "lossy"):
        prof_sessions = [s for s in sessions if s["profile"] == prof]
        X_all, y_all = [], []
        for s in prof_sessions:
            for w in s["windows"]:
                X_all.append(w)
                y_all.append(s["class"])

        X_all = np.array(X_all, float) if X_all else np.empty((0, 31), float)
        y_all = np.array(y_all) if y_all else np.empty((0,), dtype=str)

        if len(y_all) > 0:
            y_pred = rf.predict(X_all)
            total_macro = macro_f1(y_all, y_pred)
            classes = sorted(list(set(y_all)))
            per_class_scores = f1_score(y_all, y_pred, average=None, labels=classes, zero_division=0)
            per_class = {c: round(float(v), 4) for c, v in zip(classes, per_class_scores)}
        else:
            total_macro = 0.0
            per_class = {}

        part_macros = {}
        for part in ("syn", "real"):
            X_part, y_part = [], []
            for s in prof_sessions:
                if s["part"] == part:
                    for w in s["windows"]:
                        X_part.append(w)
                        y_part.append(s["class"])
            if X_part:
                yp = rf.predict(np.array(X_part, float))
                part_macros[part] = macro_f1(np.array(y_part), yp)
            else:
                part_macros[part] = 0.0

        out[prof] = {
            "windows": len(y_all),
            "macro_f1": total_macro,
            "per_part": part_macros,
            "per_class": per_class,
        }
    return out


def analyze_p17_3(sessions, X_base, y_base):
    """P17-3: Leave-one-repetition-out over 3 impaired reps, added to base training data."""
    out = {}
    for prof in ("wan", "lossy"):
        X_prof, y_prof, rep_prof = [], [], []
        for s in sessions:
            if s["profile"] == prof:
                for w in s["windows"]:
                    X_prof.append(w)
                    y_prof.append(s["class"])
                    rep_prof.append(s["rep"])

        X_prof = np.array(X_prof, float) if X_prof else np.empty((0, 31), float)
        y_prof = np.array(y_prof) if y_prof else np.empty((0,), dtype=str)
        rep_prof = np.array(rep_prof, int) if rep_prof else np.empty((0,), dtype=int)

        loro_scores = {}
        for k in (1, 2, 3):
            train_mask = rep_prof != k
            test_mask = rep_prof == k
            if not test_mask.any():
                loro_scores[f"rep{k}"] = 0.0
                continue

            X_train = np.vstack([X_base, X_prof[train_mask]])
            y_train = np.concatenate([y_base, y_prof[train_mask]])

            X_test = X_prof[test_mask]
            y_test = y_prof[test_mask]

            clf = RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1, min_samples_leaf=2)
            clf.fit(X_train, y_train)
            pred = clf.predict(X_test)
            loro_scores[f"rep{k}"] = macro_f1(y_test, pred)

        mean_f1 = round(float(np.mean(list(loro_scores.values()))), 4) if loro_scores else 0.0
        out[prof] = {
            "loro_macro_f1": loro_scores,
            "mean": mean_f1,
        }
    return out


def build_evidence_record(s):
    rec = EvidenceRecord(src="10.0.0.1", dst="10.0.0.2", source_pcap="x")
    rec._esp = [
        {
            "t": t,
            "src": "10.0.0.1" if d == "out" else "10.0.0.2",
            "dst": "10.0.0.2" if d == "out" else "10.0.0.1",
            "ip_len": n,
            "esp_content": n - 28,
            "esp_content_known": True,
            "frame": i + 1,
        }
        for i, (t, d, n) in enumerate(s["pkts"])
    ]
    return rec


def analyze_p17_4(sessions):
    """P17-4: Safety test for infer_mode: zero sessions answered 'transport'."""
    counts = {
        "wan": {"syn": {"tunnel": 0, "transport": 0, "abstained": 0},
                "real": {"tunnel": 0, "transport": 0, "abstained": 0},
                "total": {"tunnel": 0, "transport": 0, "abstained": 0}},
        "lossy": {"syn": {"tunnel": 0, "transport": 0, "abstained": 0},
                  "real": {"tunnel": 0, "transport": 0, "abstained": 0},
                  "total": {"tunnel": 0, "transport": 0, "abstained": 0}},
    }
    total_transport = 0

    for s in sessions:
        rec = build_evidence_record(s)
        finding = infer_mode(rec, ["AES-GCM-16"])
        if finding is None or finding.value is None:
            ans = "abstained"
        elif finding.value == "tunnel":
            ans = "tunnel"
        elif finding.value == "transport":
            ans = "transport"
            total_transport += 1
        else:
            ans = "abstained"

        counts[s["profile"]][s["part"]][ans] += 1
        counts[s["profile"]]["total"][ans] += 1

    return {"by_profile": counts, "total_transport": total_transport}


def analyze_p17_5(sessions):
    """P17-5: Mixed-traffic false flag share <= 15% on single-class impaired sessions."""
    out = {}
    for prof in ("wan", "lossy"):
        prof_sessions = [s for s in sessions if s["profile"] == prof]
        n_total = len(prof_sessions)
        flagged_mixed = 0
        answered_correct = 0
        answered_wrong = 0
        abstained_other = 0

        for s in prof_sessions:
            rec = build_evidence_record(s)
            extract_attacker(rec)
            finding = rec.findings.get("traffic_type")
            if finding is None:
                abstained_other += 1
            elif finding.value is None and "mixed" in getattr(finding, "note", ""):
                flagged_mixed += 1
            elif finding.value is not None:
                val = finding.value
                pred_cls = val.get("class") if isinstance(val, dict) else str(val)
                if pred_cls == s["class"]:
                    answered_correct += 1
                else:
                    answered_wrong += 1
            else:
                abstained_other += 1

        flagged_share = round(float(flagged_mixed / n_total), 4) if n_total else 0.0
        out[prof] = {
            "total_sessions": n_total,
            "flagged_mixed": flagged_mixed,
            "flagged_share": flagged_share,
            "answered_correct": answered_correct,
            "answered_wrong": answered_wrong,
            "abstained_other": abstained_other,
        }
    return out


def analyze_p17_6(cap_dir: Path):
    """P17-6: IKE bring-ups under loss: check_exp15 and CVE-2026-78135 verdict."""
    spec = importlib.util.spec_from_file_location("validate_e2e", ROOT / "build/validate_e2e.py")
    validate_e2e = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validate_e2e)
    check_exp15 = validate_e2e.check_exp15

    ike_dir = cap_dir / "ike"
    pcap_files = sorted(ike_dir.glob("ike-*.pcap"))

    results = {
        "wan": {"established": 0, "not_established": 0, "mismatches": [], "cve_verdicts": {"PASS": 0, "UNKNOWN": 0, "FAIL": 0}},
        "lossy": {"established": 0, "not_established": 0, "mismatches": [], "cve_verdicts": {"PASS": 0, "UNKNOWN": 0, "FAIL": 0}},
    }

    for pcap in pcap_files:
        gt_file = pcap.with_suffix(".groundtruth.json")
        if not gt_file.exists():
            continue
        with open(gt_file, "r") as gf:
            gt = json.load(gf)

        prof = gt.get("profile") or ("wan" if "-wan-" in pcap.name else "lossy")
        init_res = gt.get("initiate_result", "")

        if "successfully" not in init_res:
            results[prof]["not_established"] += 1
            continue

        results[prof]["established"] += 1

        # (a) IKE suite check via check_exp15
        problems = check_exp15({"path": f"exp17/ike/{pcap.name}"})
        if problems:
            results[prof]["mismatches"].append({"file": pcap.name, "problems": problems})

        # (b) CVE-2026-78135 assessment
        recs = build_records(str(pcap))
        ike_recs = [r for r in recs if getattr(r, "_ike", [])]
        main_rec = max(ike_recs, key=lambda r: len(getattr(r, "_ike", []))) if ike_recs else (max(recs, key=lambda r: len(getattr(r, "_ike", []))) if recs else None)

        cve_v = "UNKNOWN"
        if main_rec is not None:
            verdicts = assess_record(main_rec)
            for v in verdicts:
                if v.rule_id == "CVE-2026-78135":
                    cve_v = v.verdict
                    break
        if cve_v in results[prof]["cve_verdicts"]:
            results[prof]["cve_verdicts"][cve_v] += 1
        else:
            results[prof]["cve_verdicts"][cve_v] = 1

    total_mismatches = sum(len(results[p]["mismatches"]) for p in results)
    total_cve_fail = sum(results[p]["cve_verdicts"].get("FAIL", 0) for p in results)

    return {
        "by_profile": results,
        "total_mismatches": total_mismatches,
        "total_cve_fail": total_cve_fail,
    }


def main():
    cap_dir = ROOT / "testbed/captures/exp17"
    sessions = load_exp17_sessions(cap_dir)
    print(f"Loaded {len(sessions)} EXP-17 sessions from {cap_dir / 'manifest.csv'}")

    # Load shipped model and base training data
    shipped_rf = _model()[0]
    X_base, y_base, _, _, _, _ = load()
    print(f"Loaded {len(y_base)} base windows from existing datasets")

    # Predictions
    p17_1_2 = analyze_p17_1_and_2(sessions, shipped_rf)
    p17_3 = analyze_p17_3(sessions, X_base, y_base)
    p17_4 = analyze_p17_4(sessions)
    p17_5 = analyze_p17_5(sessions)
    p17_6 = analyze_p17_6(cap_dir)

    res = {
        "exp17_sessions": len(sessions),
        "P17-1": p17_1_2["wan"],
        "P17-2": p17_1_2["lossy"],
        "P17-3": p17_3,
        "P17-4": p17_4,
        "P17-5": p17_5,
        "P17-6": p17_6,
    }

    # Thresholds from PREREG.md:
    # P17-1 >= 0.70 on wan
    # P17-2 >= 0.50 on lossy
    # P17-3 >= 0.90 on both profiles (mean)
    # P17-4 zero "transport" answers
    # P17-5 flagged share <= 0.15 on both profiles
    # P17-6 zero mismatches and zero CVE FAIL
    v1 = bool(res["P17-1"]["macro_f1"] >= 0.70)
    v2 = bool(res["P17-2"]["macro_f1"] >= 0.50)
    v3 = bool(res["P17-3"]["wan"]["mean"] >= 0.90 and res["P17-3"]["lossy"]["mean"] >= 0.90)
    v4 = bool(res["P17-4"]["total_transport"] == 0)
    v5 = bool(res["P17-5"]["wan"]["flagged_share"] <= 0.15 and res["P17-5"]["lossy"]["flagged_share"] <= 0.15)
    v6 = bool(res["P17-6"]["total_mismatches"] == 0 and res["P17-6"]["total_cve_fail"] == 0)

    res["verdicts"] = {
        "P17-1 wan macro_f1 >= 0.70": v1,
        "P17-2 lossy macro_f1 >= 0.50": v2,
        "P17-3 loro mean >= 0.90 both": v3,
        "P17-4 zero transport answers": v4,
        "P17-5 flagged share <= 0.15 both": v5,
        "P17-6 zero mismatches and zero CVE FAIL": v6,
    }

    out_file = ROOT / "experiments/exp17-network-conditions/results/exp17_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(res, indent=2, default=float))
    print(json.dumps(res, indent=1, default=float))


if __name__ == "__main__":
    main()
