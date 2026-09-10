# Testbed Manifest — Reproducibility Record

Recorded after the first successful build/run of each image, 2026-09-10.

## Host environment
- Host OS: macOS (Darwin 25.6.0), arm64 (Apple Silicon)
- Docker: 29.7.2 (build a7dcaa6), Docker Compose v5.5.0
- Docker Desktop's Linux VM kernel: `7.0.12-linuxkit`, aarch64

## Images

| Image | Base | Build method | strongSwan version | Key plugins |
|---|---|---|---|---|
| `testbed-router` | `debian:bookworm-slim` | apt | n/a (no IPsec) | iproute2, tcpdump, tshark |
| `testbed-alice` / `testbed-bob` | `debian:bookworm-slim` | apt: `strongswan`, `strongswan-swanctl`, `strongswan-pki`, `libcharon-extra-plugins`, `libstrongswan-extra-plugins`, **`libstrongswan-standard-plugins`** (required for `gcm`/`openssl` — not pulled in by the others) | **5.9.8-5+deb12u5** | openssl, gcrypt, aes, sha1/2, gmp, curve25519, chapoly, ctr, ccm, gcm, hmac, xcbc, cmac |
| `testbed-strongswan-pq` (`alice-pq`/`bob-pq`) | `debian:bookworm-slim` | **built from source**, tag `6.0.2` | **6.0.2** | Explicit `--enable-*` list incl. `ml` (native ML-KEM, RFC 9370 ADDKE — no liboqs/Botan dependency needed; see NOTES.md) |

## Why two strongSwan builds
Debian bookworm's `strongswan` apt package is 5.9.8, which predates RFC 9370 (May 2023) / ML-KEM
support (strongSwan 6.0.0, Dec 2024). EXP-04 (post-quantum key exchange observability) requires
6.0+; EXP-01/02/03 do not depend on PQ support and use the faster, apt-based classical image.

## Reproducing a from-scratch build
```bash
cd testbed
docker compose build          # classical images: apt-based, ~30s
docker build -t testbed-strongswan-pq images/strongswan-pq   # source build, ~2-3 min (liboqs NOT needed — see NOTES.md)
docker compose up -d
python3 scripts/gen_swanctl_conf.py   # regenerate classical swanctl.conf from experiment_matrix.json
```

## Known non-determinism / environment sensitivity
- Docker bridge network subnets (`10.10.1.0/24`, `10.10.2.0/24`) must not collide with other
  Docker networks on the host. `docker network ls` + inspect before reusing this compose file
  alongside other projects.
- Editing a bind-mounted config file with certain editors can leave a stale inode in the container
  view (observed on macOS + Docker Desktop's virtiofs). If `swanctl --load-all` reports "failed to
  open config file" right after an edit, `docker compose restart <service>` fixes it — this is a
  host/mount artifact, not an IPsec or strongSwan issue.
