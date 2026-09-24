#!/usr/bin/env python3
"""EXP-20 analysis (PREREG.md): five training recipes on the frozen scoreboard (build/models/benchmark.py),
then the pre-registered ship bar, applied mechanically. Writes results/summary.json.

  .venv/bin/python experiments/exp20-real-ipsec-and-users/analyze.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "build/models"))
from benchmark import Recipe, score, sources  # noqa: E402


def no_wg_web(name, s):
    return (s.y != "web") if name == "wg" else np.ones(len(s.y), bool)


RECIPES = [
    Recipe("R0 shipped: lab + VNAT", ("lab", "vnat")),
    Recipe("R1 + real IPsec (USBVPN)", ("lab", "vnat", "usbvpn")),
    Recipe("R2 + real people (WireGuard, no web)", ("lab", "vnat", "wg"), select=no_wg_web),
    Recipe("R3 + USBVPN + WireGuard (no web): candidate", ("lab", "vnat", "usbvpn", "wg"), select=no_wg_web),
    Recipe("R4 = R3 + WireGuard web (Q5)", ("lab", "vnat", "usbvpn", "wg")),
]


def startup_fit_seconds(recipe: Recipe, src) -> tuple[float, int]:
    """Time the product's own fit (n_jobs=1, as tunnelscope.leakage.attacker._model) on everything."""
    from sklearn.ensemble import RandomForestClassifier
    Xs, ys = [], []
    for name in recipe.learn_from:
        s = src[name]
        keep = np.ones(len(s.y), bool) if recipe.select is None else recipe.select(name, s)
        Xs.append(s.X[keep]); ys.append(s.y[keep])
    X, y = np.vstack(Xs), np.concatenate(ys)
    t = time.time()
    RandomForestClassifier(n_estimators=200, random_state=0, n_jobs=1, min_samples_leaf=2).fit(X, y)
    return round(time.time() - t, 2), int(len(y))


def main() -> None:
    src = sources()
    out = {"sources": {k: {"windows": int(len(v.y)), "groups": int(len(set(v.group))),
                           "per_class": {c: int((v.y == c).sum()) for c in sorted(set(v.y))}}
                       for k, v in src.items()}}
    res = {}
    for r in RECIPES:
        t = time.time()
        res[r.name] = score(r, src)
        res[r.name]["startup_fit_s"], res[r.name]["train_windows"] = startup_fit_seconds(r, src)
        print(f"{r.name}: done in {time.time() - t:.0f} s", flush=True)
    out["recipes"] = res

    r0, r3, r4 = (res[RECIPES[i].name] for i in (0, 3, 4))
    sizes = {p: (ROOT / "build/models" / p).stat().st_size for p in ("usbvpn_windows.npz", "wg_windows.npz")}

    def bar(rx):
        sel0, selx = r0["A_real_ipsec"]["selective"], rx["A_real_ipsec"]["selective"]
        return {
            "A_up_by_0_05": rx["A_real_ipsec"]["macro_f1"] >= r0["A_real_ipsec"]["macro_f1"] + 0.05,
            "D_not_down_0_02": rx["D_lab_real_apps_loro"]["mean"] >= r0["D_lab_real_apps_loro"]["mean"] - 0.02,
            "C_not_down_0_02": rx["C_real_openvpn_vnat"]["macro_f1"] >= r0["C_real_openvpn_vnat"]["macro_f1"] - 0.02,
            "B_not_down_0_02": rx["B_real_users_wireguard"]["without_web"]["macro_f1"]
                               >= r0["B_real_users_wireguard"]["without_web"]["macro_f1"] - 0.02,
            "A_abstain_accuracy_not_down": (sel0["accuracy_when_answering"] is None
                                            or (selx["accuracy_when_answering"] or 0) >= sel0["accuracy_when_answering"]),
            "files_under_5_mb": all(v < 5 * 1024 * 1024 for v in sizes.values()),
            "startup_fit_under_5_s": rx["startup_fit_s"] < 5.0,
        }
    q5 = {
        "A_macro_not_lower": r4["A_real_ipsec"]["macro_f1"] >= r3["A_real_ipsec"]["macro_f1"],
        "A_video_f1_not_down_0_02": r4["A_real_ipsec"]["per_class"]["video"] >= r3["A_real_ipsec"]["per_class"]["video"] - 0.02,
        "C_not_down_0_02": r4["C_real_openvpn_vnat"]["macro_f1"] >= r3["C_real_openvpn_vnat"]["macro_f1"] - 0.02,
    }
    out["window_file_bytes"] = sizes
    out["ship_bar_R3"], out["ship_bar_R4"] = bar(r3), bar(r4)
    out["Q5_R4_replaces_R3"] = q5
    out["Q5_pass"] = all(q5.values())
    # decision, mechanically: R4 if Q5 passes and R4 clears the bar; else R3 if R3 clears it; else nothing
    out["ship"] = ("R4" if out["Q5_pass"] and all(out["ship_bar_R4"].values())
                   else "R3" if all(out["ship_bar_R3"].values()) else None)
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results/summary.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: out[k] for k in ("ship_bar_R3", "ship_bar_R4", "Q5_R4_replaces_R3", "Q5_pass", "ship")}, indent=1))


if __name__ == "__main__":
    main()
