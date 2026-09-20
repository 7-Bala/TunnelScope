#!/usr/bin/env bash
# Build a compact review pack of the CURRENT branch against main (T-086).
#   handoff/review_pack.sh            fast checks (about 1 minute)
#   handoff/review_pack.sh --full     full check_all (5-8 minutes)
# Output: handoff/reviews/<branch>.md (gitignored). Paste it to Claude.
set -uo pipefail
cd "$(dirname "$0")/.."
BR=$(git rev-parse --abbrev-ref HEAD); OUT="handoff/reviews/${BR//\//_}.md"; mkdir -p handoff/reviews
MAXLINES=${MAXLINES:-500}
MODE="--fast"; [ "${1:-}" = "--full" ] && MODE=""
{
  echo "# Review pack: $BR  ($(date '+%F %T'))"
  echo; echo "## Commits"; git log main..HEAD --format='- %h %s'
  echo; echo "## Files changed vs main"; git diff --stat main | tail -40
  echo; echo "## Untracked files"; git ls-files --others --exclude-standard | head -30
  echo; echo "## Guard"; ALLOW="${ALLOW:-}" python3 build/guard_diff.py 2>&1 | head -30
  echo; echo "## Checks ($([ -z "$MODE" ] && echo full || echo fast))"; echo '```'
  ALLOW="${ALLOW:-}" build/check_all.sh $MODE 2>&1 | tail -25; echo '```'
  echo; echo "## TODO.md lines added"; git diff -U0 main -- TODO.md | grep '^+[^+]' | cut -c1-400
  echo; echo "## Test files touched"; git diff --stat main -- tests/ | tail -8
  N=$(git diff main -- . ':!*.lock' ':!package-lock.json' ':!*.npz' ':!*.csv' ':!*.gz' | wc -l | tr -d ' ')
  echo; echo "## Diff ($N lines; showing up to $MAXLINES)"; echo '```diff'
  git diff main -- . ':!*.lock' ':!package-lock.json' ':!*.npz' ':!*.csv' ':!*.gz' | head -"$MAXLINES"; echo '```'
  for f in $(git ls-files --others --exclude-standard | grep -vE '\.(pcap|gz|npz|csv|png|jpg)$' | head -8); do
    echo; echo "## New file: $f"; echo '```'; head -120 "$f"; echo '```'
  done
} > "$OUT" 2>&1
echo "$OUT  ($(wc -l < "$OUT") lines)"
