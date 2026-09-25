#!/usr/bin/env bash
# TunnelScope one-command launcher.
#   ./start.sh              check the stack, build what is missing, start the engine, open the dashboard
#   ./start.sh --dev        also run the Vite dev server (hot reload) on :5173
#   ./start.sh -d           start in the background and return; ./start.sh stop ends it
#   ./start.sh stop|status|logs|test|doctor
# Options: --port N (engine, default 8765)  --no-browser  --rebuild (force dashboard rebuild)
#          --no-history (don't learn tunnels' normal behaviour / no anomaly detection)
#          --live-follow DIR | --live-interface IFACE [--window S]  (live stream analysis, dashboard "Live" tab)
# Everything is local: the engine binds 127.0.0.1 only. Logs: ./logs/  State: ./.run/
# DEC-038: a git-ignored .env file at the repo root, if present, is loaded before the engine starts
# (e.g. TUNNELSCOPE_GENERATOR_BACKEND=cloud, TUNNELSCOPE_GEMINI_API_KEY=...); see .env.example.
set -uo pipefail
cd "$(dirname "$0")"
ROOT=$PWD LOGS=$ROOT/logs RUN=$ROOT/.run VENV=$ROOT/.venv DASH=$ROOT/fleet-dashboard
PORT=${TUNNELSCOPE_PORT:-8765}; HIST=$ROOT/.tunnelscope-history; LIVE=();  DEV=0; DETACH=0; BROWSER=1; REBUILD=0; CMD=start
mkdir -p "$LOGS" "$RUN"
[ -f "$ROOT/.env" ] && { set -a; . "$ROOT/.env"; set +a; }

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'; else B= G= Y= R= D= N=; fi
say()  { printf '%s\n' "$*"; printf '%s %s\n' "$(date '+%F %T')" "$*" | sed $'s/\033\\[[0-9;]*m//g' >> "$LOGS/start.log"; }
ok()   { say "${G}✓${N} $*"; }
warn() { say "${Y}!${N} $*"; }
die()  { say "${R}✗${N} $*"; exit 1; }

while [ $# -gt 0 ]; do case $1 in
  start|stop|status|logs|test|doctor) CMD=$1;;
  --dev) DEV=1;; -d|--detach) DETACH=1;; --no-browser) BROWSER=0;; --rebuild) REBUILD=1;;
  --port) PORT=${2:?--port needs a number}; shift;;
  --no-history) HIST="";;
  --live-follow|--live-interface|--window) LIVE+=("$1" "${2:?$1 needs a value}"); shift;;
  -h|--help) sed -n 2,10p "$0" | sed 's/^# \{0,1\}//'; exit 0;;
  *) die "unknown argument: $1 (try --help)";; esac; shift; done

pidalive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }
rotate() { [ -f "$1" ] && [ "$(wc -c <"$1")" -gt 5242880 ] && mv "$1" "$1.1"; return 0; }
health() { curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" 2>/dev/null; }
py() { "$VENV/bin/python" "$@"; }

stop_all() {
  local n=0
  for p in engine dev; do
    if pidalive "$RUN/$p.pid"; then
      pid=$(cat "$RUN/$p.pid"); kill "$pid" 2>/dev/null; pkill -P "$pid" 2>/dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.3; done
      kill -9 "$pid" 2>/dev/null; n=$((n+1)); ok "stopped $p (pid $pid)"
    fi; rm -f "$RUN/$p.pid"
  done; [ $n -eq 0 ] && say "nothing was running"; return 0
}

case $CMD in
stop) stop_all; exit 0;;
status)
  for p in engine dev; do pidalive "$RUN/$p.pid" && ok "$p running (pid $(cat "$RUN/$p.pid"))" || say "$p: not running"; done
  h=$(health) && ok "engine healthy on :$PORT  $h" || say "engine not answering on :$PORT"
  ls -1 "$LOGS" | sed 's/^/  log: logs\//'; exit 0;;
logs) touch "$LOGS/engine.log"; exec tail -n 60 -F "$LOGS"/engine.log "$LOGS"/dashboard.log "$LOGS"/start.log 2>/dev/null;;
esac

# ---- 1. prerequisites -------------------------------------------------------
say "${B}TunnelScope${N} ${D}$(date '+%F %T')${N}"
PYBIN=""
for c in python3.13 python3.12 python3.11 python3; do
  command -v $c >/dev/null && $c -c 'import sys;sys.exit(sys.version_info<(3,11))' && { PYBIN=$(command -v $c); break; }
done
[ -n "$PYBIN" ] || die "Python >= 3.11 not found (install it, then re-run)"
command -v tshark >/dev/null || die "tshark not found. macOS: brew install wireshark   Debian/Ubuntu: apt install tshark"
ok "python $($PYBIN -V 2>&1 | cut -d' ' -f2), $(tshark -v 2>/dev/null | head -1)"

# ---- 2. python environment (venv, created once) -----------------------------
if [ ! -x "$VENV/bin/python" ]; then
  say "creating .venv …"; "$PYBIN" -m venv "$VENV" >>"$LOGS/setup.log" 2>&1 || die "venv failed, see logs/setup.log"
fi
if ! py -c 'import tunnelscope, yaml, numpy, sklearn' 2>/dev/null; then
  say "installing TunnelScope (needs network the first time only) …"
  py -m pip install -q -e ".[dev]" >>"$LOGS/setup.log" 2>&1 || die "pip install failed, see logs/setup.log (air-gapped? use build/offline/make_bundle.sh)"
fi
ok "python environment ready (.venv)"

# ---- 3. analysis-stack check (tshark fields intact, baselines load) ----------
if out=$(py -m tunnelscope.cli doctor 2>&1); then ok "doctor: analysis stack verified"
else say "$out" | tail -5; die "doctor failed: the analysis stack is not trustworthy, fix the above first"; fi
if [ $CMD = doctor ]; then echo "$out"; exit 0; fi

# ---- 4. tests (only when asked) ---------------------------------------------
if [ $CMD = test ]; then
  py -m pytest -q 2>&1 | tee "$LOGS/test.log"; exit ${PIPESTATUS[0]}
fi

# ---- 5. dashboard build (skipped if up to date) ------------------------------
if command -v npm >/dev/null && [ -d "$DASH" ]; then
  [ -d "$DASH/node_modules" ] && [ $REBUILD -eq 0 ] || { say "installing dashboard packages …"; (cd "$DASH" && npm ci --no-audit --no-fund) >>"$LOGS/setup.log" 2>&1 || die "npm ci failed, see logs/setup.log"; }
  if [ $REBUILD -eq 1 ] || [ ! -f "$DASH/dist/index.html" ] || [ -n "$(find "$DASH/src" "$DASH/index.html" "$DASH/package.json" -newer "$DASH/dist/index.html" -print -quit)" ]; then
    say "building dashboard …"; rotate "$LOGS/build.log"
    (cd "$DASH" && npm run build) >"$LOGS/build.log" 2>&1 || { tail -15 "$LOGS/build.log"; die "dashboard build failed (logs/build.log)"; }
    ok "dashboard built"
  else ok "dashboard up to date"; fi
elif [ -f "$DASH/dist/index.html" ]; then ok "dashboard: using existing build (no npm)"
else warn "no Node/npm and no build: the engine will serve its built-in basic page at /"; fi

# ---- 6. start ----------------------------------------------------------------
if pidalive "$RUN/engine.pid" || health >/dev/null; then
  warn "engine already running on :$PORT (./start.sh stop first to restart)"
else
  rotate "$LOGS/engine.log"
  say "starting engine …"
  nohup "$VENV/bin/python" -m tunnelscope.cli serve --no-browser --port "$PORT" ${HIST:+--history "$HIST"} ${LIVE[@]+"${LIVE[@]}"} >>"$LOGS/engine.log" 2>&1 &
  echo $! >"$RUN/engine.pid"
  for _ in $(seq 1 40); do health >/dev/null && break; pidalive "$RUN/engine.pid" || break; sleep 0.25; done
  health >/dev/null || { tail -10 "$LOGS/engine.log"; rm -f "$RUN/engine.pid"; die "engine did not come up (logs/engine.log). Port $PORT busy? try --port"; }
  ok "engine healthy on http://127.0.0.1:$PORT  ${D}(anomaly history: ${HIST:-off}; live: ${LIVE[*]:-off})${N}"
fi
URL=http://127.0.0.1:$PORT/
if [ $DEV -eq 1 ]; then
  rotate "$LOGS/dashboard.log"
  (cd "$DASH" && exec nohup npm run dev -- --host 127.0.0.1 >>"$LOGS/dashboard.log" 2>&1) &
  echo $! >"$RUN/dev.pid"; sleep 2; URL=http://127.0.0.1:5173/
  ok "dev server (hot reload) on $URL  ${D}(proxies /api to the engine)${N}"
fi

say ""; say "  ${B}Open:${N} $URL    ${D}logs: ./start.sh logs   stop: ./start.sh stop${N}"
[ $BROWSER -eq 1 ] && { open "$URL" 2>/dev/null || xdg-open "$URL" 2>/dev/null || true; }

if [ $DETACH -eq 1 ]; then say "running in the background"; exit 0; fi
trap 'echo; stop_all; exit 0' INT TERM
say "${D}Ctrl-C stops everything. Live log:${N}"
tail -n 0 -F "$LOGS/engine.log" 2>/dev/null
