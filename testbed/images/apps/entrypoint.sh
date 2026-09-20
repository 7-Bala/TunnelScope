#!/bin/bash
# Route the peer subnet through the lab router, then idle: the harness starts
# the servers and drives the clients so each capture is one clean session.
set -e
[ -n "${ROUTE_CIDR:-}" ] && ip route replace "$ROUTE_CIDR" via "$ROUTE_GW" || true
mkdir -p /run/sshd
exec sleep infinity
