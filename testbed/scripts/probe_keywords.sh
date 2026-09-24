#!/bin/sh
# Regenerate tunnelscope/remediate/strongswan_keywords.json from the lab images (T-100).
# Needs Docker running and the lab images built (cd testbed && docker compose build alice-pq bob-pq).
set -e
cd "$(dirname "$0")/../.."
exec .venv/bin/python testbed/scripts/probe_keywords.py "$@"
