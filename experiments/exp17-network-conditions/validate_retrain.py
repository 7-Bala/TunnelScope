#!/usr/bin/env python3
"""EXP-17 follow-up: evaluate retrained traffic classifier and mixed-traffic detector
on the enlarged EXP-17 dataset across all repetitions (leave-one-repetition-out).

Writes results/exp17_retrain_results.json with:
  - wan and lossy macro-F1 (per repetition and mean)
  - mixed-traffic detector false-flag rate per profile on impaired single-class sessions
  - booleans: whether wan and lossy both reach >= 0.90 macro-F1, and whether false-flag rate <= 15%.
"""
import csv
import gzip
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
from tunnelscope.evidence.record import EvidenceRecord  # noqa: E402
import tunnelscope.leakage.attacker as attacker_mod  # noqa: E402
from tunnelscope.leakage.attacker import extract_attacker, window_features  # noqa: E402
import tunnelscope.leakage.mixed as mixed_mod  # noqa: E402


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


def analyze_retrain_loro(sessions, X_base, y_base):
    """Leave-one-repetition-out over all impaired reps in EXP-17 (train on clean + all EXP-17 reps != k,
    test on rep k per profile), matching the retrained model training procedure and P17-3 macro-F1."""
    X_exp, y_exp, rep_exp, prof_exp = [], [], [], []
    for s in sessions:
        for w in s["windows"]:
            X_exp.append(w)
            y_exp.append(s["class"])
            rep_exp.append(s["rep"])
            prof_exp.append(s["profile"])

    X_exp = np.array(X_exp, float) if X_exp else np.empty((0, 31), float)
    y_exp = np.array(y_exp) if y_exp else np.empty((0,), dtype=str)
    rep_exp = np.array(rep_exp, int) if rep_exp else np.empty((0,), dtype=int)
    prof_exp = np.array(prof_exp) if prof_exp else np.empty((0,), dtype=str)

    reps = sorted(set(rep_exp.tolist()))
    loro_wan = {}
    loro_lossy = {}

    for k in reps:
        train_mask = rep_exp != k
        X_train = np.vstack([X_base, X_exp[train_mask]])
        y_train = np.concatenate([y_base, y_exp[train_mask]])

        clf = RandomForestClassifier(n_estimators=300, random_state=0, n_jobs=-1, min_samples_leaf=2)
        clf.fit(X_train, y_train)

        # test on rep k for wan
        wan_test = (rep_exp == k) & (prof_exp == "wan")
        if wan_test.any():
            pred_wan = clf.predict(X_exp[wan_test])
            loro_wan[f"rep{k}"] = macro_f1(y_exp[wan_test], pred_wan)
        else:
            loro_wan[f"rep{k}"] = 0.0

        # test on rep k for lossy
        lossy_test = (rep_exp == k) & (prof_exp == "lossy")
        if lossy_test.any():
            pred_lossy = clf.predict(X_exp[lossy_test])
            loro_lossy[f"rep{k}"] = macro_f1(y_exp[lossy_test], pred_lossy)
        else:
            loro_lossy[f"rep{k}"] = 0.0

    return {
        "wan": {
            "loro_macro_f1": loro_wan,
            "mean": round(float(np.mean(list(loro_wan.values()))), 4) if loro_wan else 0.0,
        },
        "lossy": {
            "loro_macro_f1": loro_lossy,
            "mean": round(float(np.mean(list(loro_lossy.values()))), 4) if loro_lossy else 0.0,
        },
    }


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


def analyze_mixed_detector_false_flags(sessions):
    """Mixed-traffic detector false flag share on single-class impaired sessions (P17-5 method)."""
    # Clear caches to ensure models are loaded from the latest on-disk .npz
    attacker_mod._model.cache_clear()
    mixed_mod._model.cache_clear()

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


def main():
    cap_dir = ROOT / "testbed/captures/exp17"
    print(f"Loading EXP-17 sessions from {cap_dir}...")
    sessions = load_exp17_sessions(cap_dir)
    print(f"Loaded {len(sessions)} total EXP-17 sessions")

    # Load clean data (sources other than EXP-17)
    X_all, y_all, arm_all, rep_all, sess_all, src_all = load()
    clean_mask = (src_all != "EXP-17")
    X_base = X_all[clean_mask]
    y_base = y_all[clean_mask]
    print(f"Loaded {len(y_base)} base clean windows from EXP-05, EXP-15, EXP-16")

    # Evaluate retrained classifier with LORO
    print("Evaluating retrained traffic classifier with LORO across all EXP-17 repetitions...")
    loro_res = analyze_retrain_loro(sessions, X_base, y_base)

    # Evaluate mixed detector false-flag rate
    print("Evaluating mixed-traffic detector false-flag rate on impaired sessions...")
    mixed_res = analyze_mixed_detector_false_flags(sessions)

    wan_mean = loro_res["wan"]["mean"]
    lossy_mean = loro_res["lossy"]["mean"]
    wan_ffr = mixed_res["wan"]["flagged_share"]
    lossy_ffr = mixed_res["lossy"]["flagged_share"]

    macro_both_ge_90 = bool(wan_mean >= 0.90 and lossy_mean >= 0.90)
    ffr_both_le_15 = bool(wan_ffr <= 0.15 and lossy_ffr <= 0.15)

    res = {
        "exp17_sessions": len(sessions),
        "wan": {
            "loro_macro_f1": loro_res["wan"]["loro_macro_f1"],
            "mean": wan_mean,
            "total_sessions": mixed_res["wan"]["total_sessions"],
            "flagged_mixed": mixed_res["wan"]["flagged_mixed"],
            "flagged_share": wan_ffr,
            "answered_correct": mixed_res["wan"]["answered_correct"],
            "answered_wrong": mixed_res["wan"]["answered_wrong"],
            "abstained_other": mixed_res["wan"]["abstained_other"],
        },
        "lossy": {
            "loro_macro_f1": loro_res["lossy"]["loro_macro_f1"],
            "mean": lossy_mean,
            "total_sessions": mixed_res["lossy"]["total_sessions"],
            "flagged_mixed": mixed_res["lossy"]["flagged_mixed"],
            "flagged_share": lossy_ffr,
            "answered_correct": mixed_res["lossy"]["answered_correct"],
            "answered_wrong": mixed_res["lossy"]["answered_wrong"],
            "abstained_other": mixed_res["lossy"]["abstained_other"],
        },
        "verdicts": {
            "wan macro-F1 >= 0.90": bool(wan_mean >= 0.90),
            "lossy macro-F1 >= 0.90": bool(lossy_mean >= 0.90),
            "wan and lossy both reach >= 0.90 macro-F1": macro_both_ge_90,
            "wan mixed false-flag rate <= 0.15": bool(wan_ffr <= 0.15),
            "lossy mixed false-flag rate <= 0.15": bool(lossy_ffr <= 0.15),
            "mixed false-flag rate <= 15% both profiles": ffr_both_le_15,
        }
    }

    out_file = ROOT / "experiments/exp17-network-conditions/results/exp17_retrain_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(res, f, indent=2)
    print(f"Results written to {out_file.relative_to(ROOT)}")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
