#!/bin/bash
# Minimal entrypoint: run charon (the IKE daemon) in the foreground, having
# already loaded swanctl config via `swanctl --load-all` from a sidecar
# script or docker-compose command override. We do not use the legacy
# `ipsec` starter script — vici/swanctl only, consistent with the project's
# decision to treat strongSwan config as the ground-truth source (T2).
set -e

# Ensure the vici socket directory exists.
mkdir -p /var/run/charon

# Optional route injection (ROUTE_CIDR via ROUTE_GW), used because alice/bob
# sit on separate Docker bridge networks joined only through `router` — see
# testbed/TOPOLOGY.md. This is host networking setup, not IPsec config, and
# is intentionally kept out of swanctl.conf.
if [ -n "${ROUTE_CIDR:-}" ] && [ -n "${ROUTE_GW:-}" ]; then
    ip route add "$ROUTE_CIDR" via "$ROUTE_GW" || echo "route add failed (may already exist)"
fi

exec /usr/lib/ipsec/charon 2>&1
