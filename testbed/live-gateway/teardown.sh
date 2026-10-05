#!/usr/bin/env bash
# Stop and remove the two test gateways built by setup.sh (namespaces, bridge, their charon and sshd).
set -uo pipefail
ROOT=${TS_GW_ROOT:-/srv/tunnelscope-gw}
for gw in office-a office-b; do
  for pid in $(ip netns pids "$gw" 2>/dev/null); do kill "$pid" 2>/dev/null; done
  sleep 0.3
  for pid in $(ip netns pids "$gw" 2>/dev/null); do kill -9 "$pid" 2>/dev/null; done
  ip netns del "$gw" 2>/dev/null
  ip link del "v-$gw" 2>/dev/null
done
ip link del tsbr0 2>/dev/null
[ "${1:-}" = "--purge" ] && rm -rf "$ROOT"
echo "removed office-a, office-b and tsbr0"
