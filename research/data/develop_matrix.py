#!/usr/bin/env python3
"""DEVELOP (doc 12) decision-matrix arithmetic, kept as code so it can be re-run.

Reads research/data/develop_scores.json:
  {"weights": {"W1": 12, ...},                  # fixed before scoring (commit 6425af2)
   "concepts": {"C1": {"W1": [score, "evidence"], ...}, ...}}

Prints weighted totals (0-100 scale: sum(w*s)/5) and a sensitivity analysis:
the winner under the committed weights, equal weights, and several deliberately
skewed weightings, plus leave-one-criterion-out. A selection that flips under
mild re-weighting is fragile and must be reported as such.
"""
import json
import sys
from pathlib import Path

P = Path(__file__).parent / "develop_scores.json"


def totals(weights, concepts):
    return {c: round(sum(weights[w] * s[w][0] for w in weights) / 5, 1) for c, s in concepts.items()}


def rank(t):
    return sorted(t.items(), key=lambda kv: -kv[1])


def main():
    d = json.loads(P.read_text())
    W, C = d["weights"], d["concepts"]
    assert sum(W.values()) == 100, sum(W.values())
    for c, s in C.items():
        missing = set(W) - set(s)
        assert not missing, f"{c} missing {missing}"
        for w, (score, ev) in s.items():
            assert 1 <= score <= 5 and ev.strip(), f"{c}.{w} needs a 1-5 score and evidence"

    scen = {"committed": W, "equal": {w: 100 / len(W) for w in W}}
    def skew(name, boost):
        ww = {w: W[w] * boost.get(w, 1) for w in W}; s = sum(ww.values())
        scen[name] = {w: v * 100 / s for w, v in ww.items()}
    skew("AI-heavy (W6 x3)", {"W6": 3})
    skew("demo-heavy (W10 x3)", {"W10": 3})
    skew("feasibility-heavy (W4,W12 x3)", {"W4": 3, "W12": 3})
    skew("evidence-light (W2 x0.25)", {"W2": 0.25})
    skew("problem-fit-heavy (W1 x3)", {"W1": 3})
    for w in W:
        skew(f"drop {w}", {w: 0})

    out = {}
    for name, ww in scen.items():
        t = totals(ww, C); r = rank(t); out[name] = r
    base = out["committed"]
    print("Committed weights:")
    for c, v in base:
        print(f"  {c:4} {v:5.1f}")
    print("\nSensitivity (winner, runner-up, margin):")
    flips = []
    for name, r in out.items():
        print(f"  {name:32} {r[0][0]} {r[0][1]:5.1f}  |  {r[1][0]} {r[1][1]:5.1f}  (+{r[0][1]-r[1][1]:.1f})")
        if r[0][0] != base[0][0]:
            flips.append(name)
    print("\nScenarios where the winner changes:", flips or "none")
    json.dump({"ranking": out, "flips": flips}, open(Path(__file__).parent / "develop_results.json", "w"), indent=1)


if __name__ == "__main__":
    main()
