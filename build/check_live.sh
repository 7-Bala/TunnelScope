#!/usr/bin/env bash
# Live checks (real local model / real Docker lab). Exit 0 PASS, 1 FAIL, 3 SKIP (reason printed).
#   build/check_live.sh model        one check      build/check_live.sh          all of them
set -uo pipefail
cd "$(dirname "$0")/.."
PY=.venv/bin/python; [ -x "$PY" ] || PY=python3
if [ $# -gt 0 ]; then exec "$PY" build/live_checks.py "$1"; fi
worst=0
for c in $("$PY" -c "import sys; sys.path.insert(0,'build'); import live_checks; print(' '.join(live_checks.CHECKS))"); do
    "$PY" build/live_checks.py "$c"; rc=$?
    echo "[$c] exit $rc"
    if [ $rc -eq 1 ]; then worst=1; elif [ $rc -eq 3 ] && [ $worst -eq 0 ]; then worst=3; fi
done
exit $worst
