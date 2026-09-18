#!/usr/bin/env bash
# Build an offline install bundle for an air-gapped TunnelScope install
# (build/05-DEPLOYMENT-ONPREM.md).
#
# Run on an internet-connected STAGING machine with the same OS, CPU
# architecture and Python minor version as the air-gapped target: wheels such
# as numpy and scikit-learn are platform-specific. The bundle then crosses the
# air gap as one file and installs with no network at all.
#
# Usage: build/offline/make_bundle.sh [OUT_DIR]      (default build/offline/out)
#   REBUILD_DASHBOARD=1   rebuild fleet-dashboard first (needs Node/npm);
#                         otherwise the existing fleet-dashboard/dist is used.
set -euo pipefail

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-$ROOT/build/offline/out}"
cd "$ROOT"

if [[ "${REBUILD_DASHBOARD:-0}" == "1" || ! -f fleet-dashboard/dist/index.html ]]; then
    echo "== building the dashboard"
    (cd fleet-dashboard && npm ci && npm run build)
fi

VERSION="$(python3 -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])')"
PLATFORM="$(python3 -c 'import sysconfig,sys;print(f"{sysconfig.get_platform()}-py{sys.version_info.major}{sys.version_info.minor}")')"
NAME="tunnelscope-offline-${VERSION}-${PLATFORM}"
STAGE="$OUT/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE/wheels"

# the dashboard ships inside the package (tunnelscope/web/); removed again
# afterwards so a stale copy never shadows a fresh fleet-dashboard/dist in a
# development checkout
rm -rf tunnelscope/web
cp -R fleet-dashboard/dist tunnelscope/web
trap 'rm -rf "$ROOT/tunnelscope/web"' EXIT

echo "== wheels: tunnelscope + every dependency, for $PLATFORM"
python3 -m pip wheel . --wheel-dir "$STAGE/wheels" --quiet
rm -rf build/lib tunnelscope.egg-info/SOURCES.txt 2>/dev/null || true

cp build/05-DEPLOYMENT-ONPREM.md "$STAGE/DEPLOYMENT.md"
cat > "$STAGE/INSTALL.txt" <<TXT
TunnelScope ${VERSION} offline bundle (${PLATFORM})

Prerequisite from your own OS repository: tshark (Wireshark CLI) and Python ${PLATFORM##*-py}.

  sha256sum -c SHA256SUMS
  python3 -m venv /opt/tunnelscope
  /opt/tunnelscope/bin/pip install --no-index --find-links wheels tunnelscope
  /opt/tunnelscope/bin/tunnelscope doctor

See DEPLOYMENT.md for what it stores, what it contacts (nothing), and how to verify that.
TXT
(cd "$STAGE" && find wheels -type f -name '*.whl' | sort | while read -r f; do sha256 "$f"; done > SHA256SUMS)
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "== bundle: $OUT/$NAME.tar.gz"
ls "$STAGE/wheels"
