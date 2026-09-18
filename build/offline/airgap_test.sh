#!/usr/bin/env bash
# Mentor follow-up B: prove the on-premise / air-gapped claim instead of
# asserting it (build/05-DEPLOYMENT-ONPREM.md).
#
#   1. STAGING container (network on) = the organisation's connected build box:
#      builds the offline bundle with build/offline/make_bundle.sh.
#   2. TARGET container (--network none) = the air-gapped analyst machine:
#      verifies checksums, installs from the bundle with pip --no-index, runs
#      doctor, assess, and the dashboard server + a real upload, all under
#      strace recording every connect() any process attempts.
#   3. Pass only if every check passes AND no process attempted a connection
#      to anything but loopback or a local socket.
#
# Both containers use the same image: Debian 12 + Python 3.11 + tshark from
# the OS repository (the organisation's approved base image; tshark is the one
# prerequisite that comes from the OS, not from our bundle).
#
# Usage: build/offline/airgap_test.sh      (needs Docker; writes build/offline/AIRGAP-TEST.md)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
OUT="$WORK/out"
mkdir -p "$OUT"
IMAGE=tunnelscope-airgap-base
REPORT="$ROOT/build/offline/AIRGAP-TEST.md"

echo "== base image (Debian 12, Python 3.11, tshark, strace)"
docker build -q -t "$IMAGE" - >/dev/null <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      python3 python3-venv tshark strace curl ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
DOCKERFILE

echo "== 1. staging (network on): build the bundle"
docker run --rm -v "$ROOT":/src:ro -v "$OUT":/out "$IMAGE" bash -euc '
  mkdir /tmp/src
  tar -C /src --exclude=./fleet-dashboard/node_modules --exclude=./.git --exclude=./testbed/captures/exp05 -cf - . | tar -C /tmp/src -xf -
  python3 -m venv /tmp/build && . /tmp/build/bin/activate
  pip install -q --upgrade pip
  cd /tmp/src && build/offline/make_bundle.sh /out
'
BUNDLE="$(ls "$OUT"/*.tar.gz)"
echo "   $(basename "$BUNDLE")  $(du -h "$BUNDLE" | cut -f1)"

echo "== 2. target (--network none): install and run under strace"
CAPS="$ROOT/testbed/captures"
set +e
docker run --rm --network none --cap-add SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$OUT":/bundle:ro -v "$CAPS/pq-downgrade.pcap":/caps/pq-downgrade.pcap:ro \
  -v "$CAPS/encap/ipv6-aes128cbc-sha256.pcap":/caps/ipv6.pcap:ro \
  "$IMAGE" bash -uc '
  fail() { echo "CHECK FAIL: $*"; exit 1; }
  ip route 2>/dev/null | grep -q default && fail "container unexpectedly has a default route"
  echo "CHECK network: no default route, only loopback"
  cat > /tmp/run.sh <<"RUN"
set -eu
cd /tmp && tar xzf /bundle/*.tar.gz && cd tunnelscope-offline-*
sha256sum -c --quiet SHA256SUMS && echo "CHECK checksums: every wheel matches SHA256SUMS"
python3 -m venv /opt/tunnelscope
/opt/tunnelscope/bin/pip install -q --no-index --find-links wheels tunnelscope
echo "CHECK install: pip --no-index from the bundle only"
cd /tmp
/opt/tunnelscope/bin/tunnelscope doctor
/opt/tunnelscope/bin/tunnelscope assess /caps/pq-downgrade.pcap --json > /tmp/assess.json
/opt/tunnelscope/bin/python - <<"PY"
import json
v = json.load(open("/tmp/assess.json"))
baselines = sorted({x["baseline"] for x in v})
pq = [x for x in v if x["rule_id"] == "DST-PQ-DOWNGRADE"]
assert len(v) >= 8 and len(baselines) >= 3, (len(v), baselines)
assert pq and pq[0]["verdict"] == "FAIL", pq
print(f"CHECK assess: {len(v)} verdicts across {baselines}; DST-PQ-DOWNGRADE = FAIL")
PY
/opt/tunnelscope/bin/tunnelscope serve --no-browser --port 8765 > /tmp/serve.log 2>&1 &
SERVE=$!
for i in $(seq 1 50); do curl -sf http://127.0.0.1:8765/health > /tmp/health.json && break; sleep 0.2; done
grep -q "\"dashboard\": true" /tmp/health.json && echo "CHECK serve: /health ok, packaged dashboard found"
curl -sf http://127.0.0.1:8765/ | grep -q "<div id=\"root\">" && echo "CHECK serve: dashboard page served from the installed package"
curl -sf --data-binary @/caps/ipv6.pcap "http://127.0.0.1:8765/api/analyze?name=ipv6.pcap" > /tmp/analyze.json
/opt/tunnelscope/bin/python -c "
import json; d = json.load(open(\"/tmp/analyze.json\"))
assert d.get(\"ok\"), d
print(\"CHECK upload: /api/analyze ok on a real IPv6 capture,\", len(d.get(\"sas\", d.get(\"records\", []))), \"record(s)\")"
kill $SERVE
RUN
  strace -f -qq -e trace=connect -o /tmp/connect.log bash /tmp/run.sh || fail "a step failed (see above)"
  echo "---- connect() attempts by every process (strace -f):"
  grep -o "sa_family=AF_[A-Z0-9]*[^}]*" /tmp/connect.log | sort | uniq -c
  if grep "connect(" /tmp/connect.log | grep -v "AF_UNIX" | grep -v "127.0.0.1" | grep -v "inet_pton(AF_INET6, \"::1\"" | grep -q .; then
    echo "---- NON-LOCAL connection attempts:"; grep "connect(" /tmp/connect.log | grep -v AF_UNIX | grep -v 127.0.0.1 | head
    fail "a process tried to reach something beyond this machine"
  fi
  echo "CHECK outbound: zero connection attempts beyond loopback / local sockets"
' | tee "$WORK/target.log"
STATUS=${PIPESTATUS[0]}
set -e

{
  echo "# Air-gapped install test (mentor follow-up B)"
  echo
  echo "Generated by \`build/offline/airgap_test.sh\` on $(date -u +%Y-%m-%dT%H:%MZ). Result: **$([[ $STATUS == 0 ]] && echo PASS || echo FAIL)**."
  echo
  echo "Bundle: \`$(basename "$BUNDLE")\` ($(du -h "$BUNDLE" | cut -f1)), built in a network-on staging container."
  echo "Target: same image, \`docker run --network none\`, everything under \`strace -f -e trace=connect\`."
  echo
  echo '```'
  cat "$WORK/target.log"
  echo '```'
} > "$REPORT"
echo "== report: $REPORT"
rm -rf "$WORK"
exit "$STATUS"
