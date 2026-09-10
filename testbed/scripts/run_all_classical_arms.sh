#!/bin/bash
# Run every classical (non-PQ, non-PFS) experiment arm needed for EXP-01 and
# EXP-02. PFS arms (EXP-03) and PQ arms (EXP-04, separate PQ image) are run
# by their own scripts.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARMS="cs-aes128gcm16 cs-aes256gcm16 cs-aes128cbc-sha256 cs-aes256cbc-sha256 cs-aes128ctr-sha256 cs-chacha20poly1305 cs-transport-aes256gcm16"
for arm in $ARMS; do
    echo "############################################## $arm ##############################################"
    bash "$HERE/run_arm.sh" "$arm"
done
echo "All classical arms captured."
