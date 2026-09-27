#!/usr/bin/env bash
# Two real strongSwan gateways for the DEC-044 live-fix end-to-end test, on one Linux host, reached
# ONLY over SSH (never docker exec, never a shared filesystem path TunnelScope knows about).
#
#   sudo testbed/live-gateway/setup.sh      # build and start office-a and office-b
#   sudo testbed/live-gateway/teardown.sh   # stop and remove everything
#
# Each gateway is its own network namespace (own interfaces, IKE ports, kernel IPsec state) and its
# own mount namespace (own /run, /tmp and /etc/swanctl), running its own charon and its own sshd.
# They are joined by a bridge on 192.168.77.0/24; the host (where TunnelScope runs) is 192.168.77.1.
# The tunnel between them starts deliberately weak (MODP-2048 IKE group, which DISA V-207193 fails),
# so there is something to fix. Lab throwaway PSK and keys only (AGENTS.md exception for testbed/).
set -euo pipefail
ROOT=${TS_GW_ROOT:-/srv/tunnelscope-gw}
KEYDIR=$ROOT/client
BR=tsbr0
declare -A IP=([office-a]=192.168.77.10 [office-b]=192.168.77.11)
declare -A PEERIP=([office-a]=192.168.77.11 [office-b]=192.168.77.10)
declare -A ME=([office-a]=gwa [office-b]=gwb)
declare -A THEM=([office-a]=gwb [office-b]=gwa)
declare -A LTS=([office-a]=10.50.1.0/24 [office-b]=10.50.2.0/24)
declare -A RTS=([office-a]=10.50.2.0/24 [office-b]=10.50.1.0/24)

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in ip unshare /usr/lib/ipsec/charon swanctl /usr/sbin/sshd ssh-keygen tcpdump; do
  command -v "$b" >/dev/null || [ -x "$b" ] || { echo "missing: $b"; exit 1; }
done

mkdir -p "$KEYDIR"
[ -f "$KEYDIR/id_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -C tunnelscope-live-test -f "$KEYDIR/id_ed25519"
: > "$KEYDIR/known_hosts"

ip link show $BR >/dev/null 2>&1 || { ip link add $BR type bridge; ip addr add 192.168.77.1/24 dev $BR; }
ip link set $BR up

for gw in office-a office-b; do
  d=$ROOT/$gw
  mkdir -p "$d/swanctl/conf.d" "$d/tmp" "$d/etc"
  chmod 1777 "$d/tmp"
  [ -f "$d/host_key" ] || ssh-keygen -q -t ed25519 -N "" -f "$d/host_key"
  cp "$KEYDIR/id_ed25519.pub" "$d/authorized_keys"; chmod 600 "$d/authorized_keys"
  cat > "$d/swanctl/swanctl.conf" <<EOF
connections {
    office-link {
        local_addrs  = ${IP[$gw]}
        remote_addrs = ${PEERIP[$gw]}
        version = 2
        proposals = aes256-sha256-modp2048
        local {
            auth = psk
            id = ${ME[$gw]}
        }
        remote {
            auth = psk
            id = ${THEM[$gw]}
        }
        children {
            office-link {
                local_ts  = ${LTS[$gw]}
                remote_ts = ${RTS[$gw]}
                esp_proposals = aes256-sha256
            }
        }
    }
}
secrets {
    ike-office {
        id-a = gwa
        id-b = gwb
        secret = "lab-only-throwaway-psk-not-a-secret"
    }
}
EOF
  # This sandbox's kernel has no ESP (xfrm "Requested type not found"), so each gateway uses
  # strongSwan's userspace ESP (kernel-libipsec, a TUN device). Only inside the gateways' own mount
  # namespaces; a real gateway uses kernel IPsec. IKE, which the fix and its verification read, is
  # unchanged either way.
  printf 'kernel-libipsec {\n    load = yes\n}\n' > "$d/etc/kernel-libipsec.conf"
  cat > "$d/sshd_config" <<EOF
ListenAddress ${IP[$gw]}
Port 22
HostKey $d/host_key
PidFile /run/sshd.pid
AuthorizedKeysFile $d/authorized_keys
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
EOF

  ip netns del "$gw" 2>/dev/null || true
  ip netns add "$gw"
  ip link del "v-$gw" 2>/dev/null || true
  ip link add "v-$gw" type veth peer name eth0 netns "$gw"
  ip link set "v-$gw" master $BR up
  ip netns exec "$gw" ip link set lo up
  ip netns exec "$gw" ip addr add "${IP[$gw]}/24" dev eth0
  ip netns exec "$gw" ip link set eth0 up

  # The gateway's own world: private /run, /tmp and /etc/swanctl, then charon and sshd.
  cat > "$d/boot.sh" <<EOF
set -e
mount -t tmpfs none /run
mkdir -p /run/sshd /run/charon
mount --bind $d/tmp /tmp
mount --bind $d/swanctl /etc/swanctl
mount --bind $d/etc/kernel-libipsec.conf /etc/strongswan.d/charon/kernel-libipsec.conf
/usr/lib/ipsec/charon > $d/charon.log 2>&1 &
i=0; until swanctl --stats >/dev/null 2>&1; do i=\$((i+1)); [ \$i -gt 100 ] && exit 1; sleep 0.1; done
swanctl --load-all > $d/load.log 2>&1
exec /usr/sbin/sshd -D -f $d/sshd_config
EOF
  setsid ip netns exec "$gw" unshare -m --propagation private sh "$d/boot.sh" > "$d/boot.log" 2>&1 < /dev/null &
done

for gw in office-a office-b; do
  i=0
  until ssh-keyscan -T 2 -t ed25519 "${IP[$gw]}" >> "$KEYDIR/known_hosts" 2>/dev/null; do
    i=$((i+1)); [ $i -gt 30 ] && { echo "$gw: sshd did not start (see $ROOT/$gw/boot.log)"; exit 1; }; sleep 0.5
  done
done
ssh -o BatchMode=yes -o UserKnownHostsFile="$KEYDIR/known_hosts" -i "$KEYDIR/id_ed25519" root@192.168.77.10 \
  swanctl --initiate --child office-link --timeout 10 >/dev/null
echo "office-a: root@192.168.77.10   office-b: root@192.168.77.11"
echo "client key: $KEYDIR/id_ed25519   known_hosts: $KEYDIR/known_hosts"
ssh -o BatchMode=yes -o UserKnownHostsFile="$KEYDIR/known_hosts" -i "$KEYDIR/id_ed25519" root@192.168.77.10 \
  swanctl --list-sas | grep -E "office-link|ESTABLISHED|INSTALLED" || true
