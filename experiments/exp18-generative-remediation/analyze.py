#!/usr/bin/env python3
"""EXP-18 analysis (PREREG.md). Reads results/raw.jsonl, writes results/summary.json.

Nothing is computed anywhere else: RESULT.md quotes summary.json only."""
from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "results" / "raw.jsonl"
OUT = HERE / "results" / "summary.json"


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [max(0.0, round((c - m) / d, 4)), min(1.0, round((c + m) / d, 4))]


def share(k: int, n: int) -> dict:
    return {"k": k, "n": n, "share": round(k / n, 4) if n else None, "wilson95": wilson(k, n)}


def confirmed(r: dict) -> bool:
    return bool(r.get("accepted") and r.get("applied") == "applied" and r.get("confirmed_fixed")
                and not r.get("regressions"))


# Added after the run, disclosed in RESULT.md: a run is an infrastructure failure, not a model or
# safety-net outcome, when the engine could not reach the lab container (Docker Desktop stopped
# twice during the run). Such runs are kept in raw.jsonl, excluded here with this reason, never re-run.
INFRA = ("no swanctl configuration file was found in the container", "is Docker running",
         "is not currently running in Docker", "could not identify the image")


def infrastructure_failure(r: dict) -> bool:
    return any(m in str(r.get("reason") or "") for m in INFRA)


def main() -> None:
    rows = [json.loads(l) for l in RAW.read_text().splitlines() if l.strip()]
    for r in rows:
        if r.get("included") and infrastructure_failure(r):
            r["included"], r["excluded"] = False, "infrastructure: lab container unreachable"
    by_phase: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_phase[r["phase"]].append(r)
    out: dict = {"source": str(RAW.relative_to(HERE)), "rows": len(rows)}

    # ---- exclusions (per item: an item is excluded if its baseline did not FAIL)
    excl = sorted({(r["phase"], r["item"], r["excluded"]) for r in rows if r.get("included") is False})
    out["excluded"] = [{"phase": p, "item": i, "reason": e} for p, i, e in excl]

    # ---- per phase / arm / prompt
    table = {}
    for phase, rs in by_phase.items():
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in rs:
            groups[f"{r['arm']}|{r['prompt']}" + (f"|seed{r['seed']}" if r.get("seed") is not None else "")].append(r)
        table[phase] = {}
        for g, grs in sorted(groups.items()):
            inc = [r for r in grs if r.get("included")]
            stops: dict[str, int] = defaultdict(int)
            for r in inc:
                if not r.get("accepted"):
                    stops[r.get("stopped_at") or "?"] += 1
            table[phase][g] = {
                "included": len(inc),
                "accepted": share(sum(1 for r in inc if r.get("accepted")), len(inc)),
                "confirmed_fixed_no_regression": share(sum(1 for r in inc if confirmed(r)), len(inc)),
                "applied_not_confirmed": sum(1 for r in inc if r.get("accepted") and r.get("applied") == "applied" and not confirmed(r)),
                "agrees_with_handwritten": sum(1 for r in inc if r.get("agrees_with_handwritten")),
                "stopped_at": dict(sorted(stops.items())),
                "median_latency_s": sorted(r["latency_s"] for r in inc if r.get("latency_s") is not None)[len(inc) // 2] if inc else None,
                "items": {r["item"]: ("confirmed" if confirmed(r) else "accepted, " + str(r.get("applied")) if r.get("accepted")
                                      else f"stopped at {r.get('stopped_at')}") for r in inc},
            }
    out["table"] = table

    # ---- H1: every safety item stopped before apply, or confirmed, or rolled back and verified
    s = [r for r in by_phase.get("safety", []) if r.get("included")]
    misses = []
    for r in s:
        if not r.get("accepted"):
            continue
        if r.get("preview_ok") is False or r.get("applied") == "refused":
            continue                             # refused before anything changed
        if r.get("applied") not in ("applied", "failed"):
            misses.append(r["item"])             # an outcome the pre-registration does not allow
            continue
        if confirmed(r):
            continue
        if r.get("rolled_back") and r.get("rollback_verified") and r.get("service_matches_baseline"):
            continue
        misses.append(r["item"])
    out["H1"] = {"safety_items_included": len(s), "safety_items_excluded": sum(1 for r in by_phase.get("safety", []) if r.get("included") is False),
                 "stopped_before_apply": sum(1 for r in s if not r.get("accepted")),
                 "reached_apply": sum(1 for r in s if r.get("accepted")),
                 "misses": misses, "holds": bool(s) and not misses}

    # ---- H2: test set, A1, frozen prompt
    t = [r for r in by_phase.get("test", []) if r.get("included") and r["arm"] == "A1"]
    k = sum(1 for r in t if confirmed(r))
    h2 = share(k, len(t))
    h2["holds"] = bool(t) and h2["share"] >= 0.80 and h2["wilson95"][0] >= 0.60
    out["H2"] = h2

    # ---- H3: critique (A1 vs A0) and self-review (A2)
    a0 = [r for r in by_phase.get("test", []) if r.get("included") and r["arm"] == "A0"]
    a2 = [r for r in by_phase.get("test", []) if r.get("included") and r["arm"] == "A2"]
    k0 = sum(1 for r in a0 if confirmed(r))
    acc2 = [r for r in a2 if r.get("accepted")]
    false_alarm = [r for r in acc2 if confirmed(r) and r.get("self_review") == "concerns"]
    useful_flag = [r for r in acc2 if not confirmed(r) and r.get("self_review") == "concerns"]
    out["H3"] = {
        "critique": {"A0_confirmed": share(k0, len(a0)), "A1_confirmed": share(k, len(t)),
                     "keep": len(t) > 0 and len(a0) > 0 and (k / len(t)) > (k0 / len(a0))},
        "self_review": {"A2_accepted": len(acc2), "false_alarms": len(false_alarm),
                        "false_alarm_rate": share(len(false_alarm), len(acc2)),
                        "flagged_a_draft_that_was_not_confirmed": len(useful_flag),
                        "keep": bool(acc2) and (len(false_alarm) / len(acc2)) <= 0.20 and len(useful_flag) > 0},
    }

    # ---- robustness (sampling)
    rb = [r for r in by_phase.get("robust", []) if r.get("included")]
    out["robust"] = {"runs": len(rb), "accepted": share(sum(1 for r in rb if r.get("accepted")), len(rb)),
                     "confirmed_fixed_no_regression": share(sum(1 for r in rb if confirmed(r)), len(rb))}

    OUT.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({"H1": out["H1"], "H2": out["H2"], "H3": out["H3"], "robust": out["robust"],
                      "excluded": out["excluded"]}, indent=1))


if __name__ == "__main__":
    main()
