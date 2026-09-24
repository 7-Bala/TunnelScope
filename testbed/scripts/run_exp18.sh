#!/bin/sh
# EXP-18 runner (see experiments/exp18-generative-remediation/PREREG.md). Lab up, model on disk.
#   testbed/scripts/run_exp18.sh dev --prompt P0 | test | safety | robust
set -e
cd "$(dirname "$0")/../.."
exec .venv/bin/python testbed/scripts/run_exp18.py "$@"
