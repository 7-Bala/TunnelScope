#!/usr/bin/env bash
# EXP-26 lab: two MikroTik RouterOS CHR VMs joined by a QEMU UDP "cable".
#   testbed/mikrotik/boot.sh <workdir>      workdir holds vm-a.img, vm-b.img (copies of chr-*-arm64.img)
#   testbed/mikrotik/boot.sh <workdir> stop
# Emulated Cortex-A72: RouterOS arm64 panics at boot under -cpu host/hvf on Apple Silicon (EXP-26 PREREG).
# Management (127.0.0.1 only): REST a:8081 b:8082, ssh a:2221 b:2222, serial a:4451 b:4452, QEMU monitor a:4461 b:4462.
set -euo pipefail
W=${1:?workdir}; cd "$W"
if [ "${2:-}" = stop ]; then
  for v in a b; do [ -f $v.pid ] && kill "$(cat $v.pid)" 2>/dev/null; rm -f $v.pid; done; echo stopped; exit 0
fi
FW=$(brew --prefix qemu)/share/qemu/edk2-aarch64-code.fd
vm() {  # name rest ssh local_port remote_port serial monitor
  qemu-system-aarch64 -M virt -cpu cortex-a72 -accel tcg,thread=multi -m 1024 -smp 2 -bios "$FW" \
    -drive file="vm-$1.img",if=none,id=hd0,format=raw -device virtio-blk-pci,drive=hd0 \
    -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:$2-:80,hostfwd=tcp:127.0.0.1:$3-:22 \
    -device virtio-net-pci,netdev=mgmt,romfile= \
    -netdev dgram,id=link,local.type=inet,local.host=127.0.0.1,local.port=$4,remote.type=inet,remote.host=127.0.0.1,remote.port=$5 \
    -device virtio-net-pci,netdev=link,romfile= \
    -serial tcp:127.0.0.1:$6,server,nowait -monitor tcp:127.0.0.1:$7,server,nowait \
    -display none -daemonize -pidfile "$1.pid"
}
vm a 8081 2221 12345 12346 4451 4461
vm b 8082 2222 12346 12345 4452 4462
echo "booted: a pid $(cat a.pid), b pid $(cat b.pid)"
