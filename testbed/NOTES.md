# Testbed Build/Debug Notes

Running log of non-obvious issues hit while building this testbed, kept because each one is a
small, real fact about strongSwan/Docker/IPsec that cost real time to find and would otherwise be
lost. Cross-referenced from Dockerfiles and scripts where relevant.

---

### 1. Docker bridge gateway collision with a static `.1` address
Symptom: `failed to set up container networking: Address already in use` when assigning `router`
the static IP `10.10.1.1`. Cause: Docker auto-assigns the bridge gateway to the subnet's first
usable address (`.1`) unless told otherwise, colliding with our own intended use of `.1` for
`router`. Fix: set an explicit `gateway:` (`.254`) in the network's IPAM config in
`docker-compose.yml`.

### 2. `--use-syslog=no` is not a valid charon flag
The entrypoint's first version passed `charon --use-syslog=no`; charon's actual flag is boolean
(`--use-syslog`, no argument). Trivial fix, but it silently exited both containers immediately with
a usage message — worth remembering that a "container exited instantly" failure is usually the
entrypoint's own argument parsing, not IPsec.

### 3. Debian's `strongswan` apt package needs a THIRD plugins package
`strongswan strongswan-swanctl strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins`
is not enough — AES-GCM (`gcm` plugin) and `openssl` fail to load with `libcharon-extra-plugins`
and `libstrongswan-extra-plugins` alone. The missing package is **`libstrongswan-standard-plugins`**.
Not obvious from the package names' apparent hierarchy (`extra` sounds like it should be a
superset).

### 4. swanctl connection selection is address/identity-based, not child-name-based
Defining N `swanctl.conf` connections between the **same** two IP addresses, differing only in
`esp_proposals`, and giving them all the same `local`/`remote` `id` (`alice`/`bob`) makes the
**responder's** connection selection ambiguous: strongSwan matches the incoming IKE_AUTH against
whichever locally-configured connection matches address+identity, which — with identical
identities across all N connections — is effectively arbitrary among the candidates, **not** the
one the initiator intended by child-SA name. Symptom: `NO_PROPOSAL_CHOSEN` on the child SA, even
though the initiator's request was correct, because the responder was evaluating the wrong
connection's `esp_proposals`.

**Fix:** give every experiment arm a **unique IKE identity** (`id = alice-<arm-name>` /
`id = bob-<arm-name>`), and a wildcard PSK secret (`id-1 = %any`, `id-2 = %any`) rather than fixed
`alice`/`bob` identities. This makes responder-side selection deterministic. Implemented in
`scripts/gen_swanctl_conf.py`.

### 5. Traffic-selector direction must be swapped per role
The `swanctl.conf` config generator initially hardcoded `local_ts`/`remote_ts` to alice's addresses
in BOTH alice's and bob's generated files (copy-paste bug in the template function, not passing the
role-specific addresses through). Symptom: `TS_UNACCEPTABLE` — bob's child-SA config claimed to
"own" alice's address as its own local traffic selector. Fixed by parameterising `local_ts`/
`remote_ts` on the function's own `local_addr`/`remote_addr` arguments instead of literals.

### 6. `tcpdump -i any` double-counts forwarded packets
See `TOPOLOGY.md` — capturing on the `any` pseudo-interface on a forwarding host shows every
forwarded packet twice (once per real interface it crosses). Fixed by capturing on a single named
interface (`eth0`) instead, verified against `swanctl`'s own sent/received packet counts.

### 7. `swanctl.conf` does not accept semicolon-separated single-line blocks
`local { auth = psk; id = foo }` on one line fails to parse (`invalid value for: auth, config
discarded`) — no explicit error points at the semicolon. The parser expects one key per line (or at
least does not accept `;` as a statement separator the way a C-like config might). All hand-written
`swanctl.conf` files in this repo use one key per line, matching the machine-generated ones.

### 8. Editing a bind-mounted config file can leave a stale inode in the container
After editing a host file that is bind-mounted into a running container (`configs/alice-pq/
swanctl.conf`), `swanctl --load-all` inside the container reported `failed to open config file`
even though the file clearly existed on the host and via `docker exec ... cat`. Observed on macOS +
Docker Desktop's virtiofs bind-mount implementation. **Not** an IPsec or strongSwan bug.
**Fix:** `docker compose restart <service>` — forces a fresh mount view. If a config edit doesn't
seem to take effect and the error is about opening/reading the file itself (not a parse error),
restart the container before debugging the config content.

### 9. `--enable-oqs` does not exist in strongSwan 6.0.2; use `--enable-ml`
Our research (07-DISCOVER-pq-and-late-findings.md) described PQ support as arriving "via Botan
3.6+ or the oqs plugin (liboqs)" — based on the strongSwan 6.0.0 release announcement's wording.
Checking `./configure --help` on the actual 6.0.2 source shows **no `--enable-oqs` flag at all**.
ML-KEM ships as a **native, dependency-free plugin** named `ml`
(`src/libstrongswan/plugins/ml/ml_kem.c` — self-contained: `ml_kem.c`, `ml_poly.c`,
`ml_bitpacker.c`, no liboqs/Botan linkage). We had already built a full liboqs + `--enable-oqs`
Docker stage (~3 min build) before discovering this; it was unnecessary. Corrected the Dockerfile to
drop liboqs entirely and just add `--enable-ml` plus the many baseline crypto plugin flags
(`--enable-aes --enable-sha1 --enable-sha2 ...`) that a plain `./configure` does not enable by
default. Recorded as a correction, not silently fixed — see the Dockerfile's own comment.

### 10. Source-built strongSwan installs EMPTY per-plugin `.conf` stub files
With `charon.load_modular = yes` (the default), charon looks for `<plugin> { load = yes }` blocks
under `strongswan.d/charon/*.conf`. Debian's packaged build ships these with real content
(`random { load = yes; ... commented options ... }`). A plain upstream `make install` from source
installs **empty** files (0 bytes) for the same plugins. `load_modular` found no explicit
`load = yes` key in any of them and loaded **nothing** beyond the built-in `charon` plugin itself —
symptom: `unmet dependency: NONCE_GEN` / `HASHER:HASH_SHA1` even though the `.so` files were present,
correctly linked (`ldd` clean), and their `.conf` files existed. Confirmed via `--debug-lib 3`,
which showed no `"loading plugin '<name>'"` lines at all before the failure.
**Fix:** replaced `load_modular` with an explicit `charon.load = <space-separated plugin list>` in
a custom `strongswan.conf` (`images/strongswan-pq/strongswan.conf`), matching strongSwan's own
documented non-modular configuration style. Also learned in the process (note 7 above) that this
file must be single-line, not backslash-continued.

### 11. ML-KEM-768's key size triggers IKEv2 message fragmentation (RFC 7383)
Not a bug — a real, useful finding. ML-KEM-768's ~1184-byte public key makes the encrypted
`IKE_INTERMEDIATE` message large enough that strongSwan fragments it (`EF(1/2)`, `EF(2/2)` in the
log) where the classical-DH-only baseline never fragments anything. See
`experiments/exp04-pq-length-asymmetry/` — this interaction was not anticipated in the original
PQ-6 hypothesis and is reported as a correction, not smoothed over.
