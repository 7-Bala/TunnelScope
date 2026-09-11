#!/bin/bash
# Start pluto in the foreground (no systemd). Same optional route injection as
# the strongSwan images (see testbed/TOPOLOGY.md).
set -e
if [ -n "${ROUTE_CIDR:-}" ] && [ -n "${ROUTE_GW:-}" ]; then
    ip route add "$ROUTE_CIDR" via "$ROUTE_GW" || echo "route add failed (may already exist)"
fi
ipsec initnss >/dev/null 2>&1 || true          # create the NSS database on first start
mkdir -p /run/pluto
exec /usr/libexec/ipsec/pluto --config /etc/ipsec.conf --nofork --stderrlog
