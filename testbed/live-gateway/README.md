# Live gateway test bed (DEC-044)

Two real strongSwan gateways, `office-a` (192.168.77.10) and `office-b` (192.168.77.11), on one Linux
host. Each is its own network namespace and mount namespace, with its own charon, sshd, `/run`, `/tmp`
and `/etc/swanctl`. TunnelScope reaches them only over SSH with a key, exactly as it reaches a real site.
The tunnel between them starts weak (MODP-2048, so DISA V-207193 fails) so there is something to fix.

```bash
sudo testbed/live-gateway/setup.sh                 # build and start both gateways (needs root)
sudo .venv/bin/python testbed/live-gateway/e2e.py  # 22 checks: gates, rollback, confirmed fix, watchdog
sudo testbed/live-gateway/teardown.sh [--purge]    # stop and remove
```

Manual use, as an operator would:

```bash
K=/srv/tunnelscope-gw/client
tunnelscope gateway add office-b --host 192.168.77.11 --connection office-link \
  --config-glob /etc/swanctl/swanctl.conf --identity-file $K/id_ed25519 --known-hosts $K/known_hosts
tunnelscope gateway add office-a --host 192.168.77.10 --connection office-link --peer office-b \
  --config-glob /etc/swanctl/swanctl.conf --identity-file $K/id_ed25519 --known-hosts $K/known_hosts
tunnelscope gateway terms
tunnelscope gateway accept office-a      # type: I ACCEPT THE RISKS FOR office-a
tunnelscope gateway accept office-b
tunnelscope fix V-207193 --target gw:office-a   # shows the diff and risks; type: APPLY V-207193 ON office-a
```

Browser test (the real dashboard against these gateways): see `fleet-dashboard/e2e/gateway.live.spec.ts`.

Needs: `openssh-server`, `strongswan-swanctl`, `charon-systemd` (for `/usr/lib/ipsec/charon`),
`libcharon-extra-plugins` (userspace ESP), `tcpdump`, `iproute2`, root.

Limits, stated plainly: this host's kernel has no ESP (`ip xfrm state add` gives "Requested type not
found"), so the gateways use strongSwan's userspace ESP (kernel-libipsec, enabled only inside their own
mount namespaces). The IKE handshake, which the fix changes and the verification reads, is the real
one. Real gateways use kernel IPsec. Keys and the PSK here are throwaway lab values.
