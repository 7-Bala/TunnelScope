#!/usr/bin/env bash
# The ONE command that says whether a change is safe (T-086).
#   build/check_all.sh            everything (about 5-8 minutes; needs Docker-free, network optional)
#   build/check_all.sh --fast     unit tests + guard + dashboard only (about 1 minute), for while you work
# Scope a task:   ALLOW="README.md docs/" build/check_all.sh --fast
# Full output goes to logs/check_all.log. Exit code 0 only if every line below says PASS.
set -uo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
FAST=0; [ "${1:-}" = "--fast" ] && FAST=1
mkdir -p logs; LOG=logs/check_all.log; : > "$LOG"
rows=(); fail=0
run() {   # run "name" cmd...
    local name="$1"; shift
    echo "=== $name" >> "$LOG"
    if "$@" >> "$LOG" 2>&1; then rows+=("PASS  $name"); else rows+=("FAIL  $name"); fail=1; fi
}
skip() { rows+=("SKIP  $1  ($2)"); }
live() {  # live "name" check: build/live_checks.py exit 0 PASS, 3 SKIP (reason = its last line), else FAIL
    local name="$1" out rc; echo "=== $name" >> "$LOG"
    out=$("$PY" build/live_checks.py "$2" 2>&1); rc=$?; echo "$out" >> "$LOG"
    if [ $rc -eq 0 ]; then rows+=("PASS  $name"); elif [ $rc -eq 3 ]; then skip "$name" "$(echo "$out" | tail -1)"; else rows+=("FAIL  $name"); fail=1; fi
}

run "guard: diff is in scope, no protected/test/secret problems" "$PY" build/guard_diff.py
run "unit tests (pytest)" "$PY" -m pytest -q
if [ -d fleet-dashboard/node_modules ]; then
    run "dashboard type-check (tsc)" bash -c 'cd fleet-dashboard && npx tsc -b'
    run "dashboard lint (errors only)" bash -c 'cd fleet-dashboard && npm run lint'
    run "dashboard build" bash -c 'cd fleet-dashboard && npm run build'
else
    skip "dashboard checks" "run: cd fleet-dashboard && npm ci"
fi
if [ "$FAST" -eq 0 ]; then
    run "ground truth: every capture vs what the endpoints reported" "$PY" build/validate_e2e.py
    run "dataset: hashes, provenance, splits" "$PY" dataset/validate.py
    run "findings differential: only intended changes" "$PY" build/findings_diff.py --base "${BASE:-main}"
    live "live: local model loads offline and answers (Apple Silicon only)" model
    live "live: generator smoke, real model on the real lab config (not the evaluation)" generator
    if curl -sI --max-time 5 https://wiki.wireshark.org >/dev/null 2>&1; then
        run "third-party captures (Wireshark wiki)" "$PY" build/validate_external.py
    else
        skip "third-party captures" "no network"
    fi
else
    skip "ground truth / dataset / findings diff / third-party" "--fast"
fi

echo; printf '%s\n' "${rows[@]}"; echo
if [ "$fail" -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL  (details: $LOG; last lines of each failure below)"; grep -n "^===\|Error\|FAILED\|error TS" "$LOG" | tail -15; fi
exit "$fail"
