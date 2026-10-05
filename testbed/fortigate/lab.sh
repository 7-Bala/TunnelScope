#!/bin/bash
# T-118 step 2: a FortiGate-VM (ARM64, FortiOS 7.6.7) and an Alpine/strongSwan peer, joined by a virtual wire, on Apple
# silicon with QEMU + Hypervisor.framework. Everything lives under $FGT_LAB (default ~/Documents/SIH-2026-fortilab),
# outside the repository: fortios.qcow2 (from Fortinet's support portal, needs a FortiCloud account), the Alpine ISO,
# the VM disks and the captures. Nothing here is committed except these scripts.
#
#   lab.sh fgt          start the FortiGate (serial console tcp:4555, GUI https://127.0.0.1:8443)
#   lab.sh peer [iso]   start the peer (serial tcp:4556); pass the ISO for the first boot only
#   lab.sh cap-start NAME   record the wire (both directions) to $FGT_LAB/cap/NAME.pcap
#   lab.sh cap-stop NAME
#   lab.sh stop         power both off (graceful for the FortiGate is `execute shutdown` on its console)
set -eu
LAB="${FGT_LAB:-$HOME/Documents/SIH-2026-fortilab}"
FW=/opt/homebrew/share/qemu
Q=qemu-system-aarch64
mkdir -p "$LAB/cap"
common=(-machine virt,gic-version=3 -accel hvf -cpu host -display none
        -drive if=pflash,format=raw,readonly=on,file="$FW/edk2-aarch64-code.fd")

case "${1:-}" in
  fgt)
    [ -f "$LAB/vars-fgt.fd" ] || cp "$FW/edk2-arm-vars.fd" "$LAB/vars-fgt.fd"
    nohup $Q -name fgt "${common[@]}" -smp 1 -m 2048 \
      -drive if=pflash,format=raw,file="$LAB/vars-fgt.fd" \
      -drive file="$LAB/fortios.qcow2",if=none,id=disk0,format=qcow2 -device virtio-blk-pci,drive=disk0 \
      -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:8443-:443,hostfwd=tcp:127.0.0.1:2222-:22 \
      -device virtio-net-pci,netdev=mgmt,mac=52:54:00:aa:00:01 \
      -netdev socket,id=wire,listen=127.0.0.1:5001 -device virtio-net-pci,netdev=wire,mac=52:54:00:aa:00:02 \
      -monitor unix:"$LAB/fgt.mon",server,nowait \
      -serial tcp:127.0.0.1:4555,server=on,wait=off > "$LAB/qemu-fgt.log" 2>&1 &
    echo "fgt pid $!" ;;
  peer)
    [ -f "$LAB/peer.qcow2" ] || qemu-img create -q -f qcow2 "$LAB/peer.qcow2" 4G
    [ -f "$LAB/vars-peer.fd" ] || cp "$FW/edk2-arm-vars.fd" "$LAB/vars-peer.fd"
    iso=(); [ -n "${2:-}" ] && iso=(-device qemu-xhci -drive file="$2",media=cdrom,if=none,id=cd0,readonly=on -device usb-storage,drive=cd0)
    nohup $Q -name peer "${common[@]}" -smp 1 -m 1024 \
      -drive if=pflash,format=raw,file="$LAB/vars-peer.fd" \
      -drive file="$LAB/peer.qcow2",if=none,id=disk0,format=qcow2 -device virtio-blk-pci,drive=disk0 \
      ${iso[@]+"${iso[@]}"} \
      -netdev user,id=mgmt -device virtio-net-pci,netdev=mgmt,mac=52:54:00:bb:00:01 \
      -netdev socket,id=wire,connect=127.0.0.1:5001 -device virtio-net-pci,netdev=wire,mac=52:54:00:bb:00:02 \
      -serial tcp:127.0.0.1:4556,server=on,wait=off > "$LAB/qemu-peer.log" 2>&1 &
    echo "peer pid $!" ;;
  cap-start)
    printf 'object_add filter-dump,id=%s,netdev=wire,file=%s/cap/%s.pcap\n' "$2" "$LAB" "$2" | nc -U "$LAB/fgt.mon" -w 2 >/dev/null; echo "recording $LAB/cap/$2.pcap" ;;
  cap-stop)
    printf 'object_del %s\n' "$2" | nc -U "$LAB/fgt.mon" -w 2 >/dev/null; ls -l "$LAB/cap/$2.pcap" ;;
  stop)
    pkill -f "name peer" || true; pkill -f "name fgt" || true ;;
  *) sed -n 2,12p "$0"; exit 2 ;;
esac
