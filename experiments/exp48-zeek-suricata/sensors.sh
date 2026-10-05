#!/bin/sh
# EXP-48: run Suricata and Zeek (official images, offline, default configuration) over every capture of the work tree.
# usage: sensors.sh OUT_DIR   (needs Docker; images pulled once; digests are printed so RESULT can quote them)
set -eu
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/../.." && pwd); out=${1:?out dir}
mkdir -p "$out/suricata" "$out/zeek"
for img in jasonish/suricata zeek/zeek; do docker image inspect --format "$img {{.Id}} {{index .RepoDigests 0}}" "$img:latest"; done | tee "$out/images.txt"
docker run --rm --entrypoint sh -v "$repo/testbed/captures:/caps:ro" -v "$out/suricata:/out" jasonish/suricata:latest -c '
  cd /caps; find . -name "*.pcap" | sort | while read -r f; do
    n=$(echo "${f#./}" | tr / _); mkdir -p "/out/$n"; suricata -r "/caps/${f#./}" -l "/out/$n" -k none </dev/null >"/out/$n/stdout.txt" 2>&1 || echo "suricata exit $? for $f" >>/out/errors.txt
  done'
docker run --rm --entrypoint sh -v "$repo/testbed/captures:/caps:ro" -v "$out/zeek:/out" zeek/zeek:latest -c '
  cd /caps; find . -name "*.pcap" | sort | while read -r f; do
    n=$(echo "${f#./}" | tr / _); mkdir -p "/out/$n"; (cd "/out/$n" && zeek -C -r "/caps/${f#./}" </dev/null >stdout.txt 2>&1) || echo "zeek exit $? for $f" >>/out/errors.txt
  done'
echo done
