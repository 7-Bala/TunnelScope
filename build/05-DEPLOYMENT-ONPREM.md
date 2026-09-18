# 05 — On-premise / air-gapped deployment

**Mentor follow-up B** (`research/13-MENTOR-APPLICATION-REVIEW.md` §5). Written 2026-09-18 after the
claim was **tested**, not just argued: `build/offline/AIRGAP-TEST.md` is the run this document rests on.

**Who this is for:** an organisation (NTRO, a defence establishment, a bank) that will not let packet
captures of its own networks leave the building, and often runs analysis machines with no internet
connection at all. "Private cloud (local)" in the mentor's sense is the same thing: a VM inside the
organisation's own infrastructure is just another on-premise machine.

---

## 1. The promise, and how it was checked

| Promise | How it was verified (2026-09-18) |
|---|---|
| Installs with no network | Installed with `pip --no-index` from the bundle inside `docker run --network none` (no default route, loopback only) |
| Makes no outbound connections | `doctor`, `assess`, `serve` and a real upload all ran under `strace -f -e trace=connect`: **0 attempts beyond loopback** (7 to `127.0.0.1:8765` = the test talking to the local server; 70 to glibc's local `nscd` socket = user/host lookups on the machine itself) |
| The dashboard loads nothing from the internet | Browser load of the dashboard + sample fleet: **10 requests, all to `localhost:8765`**; all three fonts (Geist, Geist Mono, Kufica) served from the package |
| Assessment works from an installed copy | 8 verdicts across all 4 baselines on `pq-downgrade.pcap`, including the expected `DST-PQ-DOWNGRADE` FAIL |
| Nothing is stored | Uploads go to a private temp file deleted after the response (`serve`, T-059); the CLI writes only the reports you ask it to |

**What the test found and fixed first.** Before this work an *installed* TunnelScope (as opposed to a
source checkout) found **no baselines** — they were looked up relative to the source tree — and
assessed every capture against nothing, returning an empty result with exit code 0. It also could not
find the dashboard. Both now ship inside the package, zero baselines is a hard error (exit 3), and CI
installs the package outside the repo on every push so this cannot quietly come back.

## 2. What you need

- **On the air-gapped machine:** Linux with Python ≥ 3.11 and `tshark` from your own OS repository or
  mirror (`apt install tshark` / `dnf install wireshark-cli`). tshark is the one dependency we do not
  bundle: it is an OS package with its own security updates, and it is the independent parser the
  whole design leans on (ADR-001).
- **On a connected staging machine:** the **same OS, CPU architecture and Python minor version** as
  the target (numpy / scikit-learn wheels are platform-specific), plus this repository.

## 3. Build, carry across, install

On the staging machine:

```
build/offline/make_bundle.sh                 # -> build/offline/out/tunnelscope-offline-<ver>-<platform>.tar.gz (+ .sha256)
```

The bundle holds wheels for TunnelScope and every dependency (57 MB for linux-aarch64 / Python 3.11),
`SHA256SUMS` for each wheel, `INSTALL.txt`, and this document. The dashboard is already built inside
the TunnelScope wheel; no Node.js is needed on either side (only to *rebuild* the dashboard:
`REBUILD_DASHBOARD=1`).

Carry the `.tar.gz` and its `.sha256` across the air gap by your approved media process, then:

```
sha256sum -c tunnelscope-offline-*.tar.gz.sha256
tar xzf tunnelscope-offline-*.tar.gz && cd tunnelscope-offline-*
sha256sum -c SHA256SUMS
python3 -m venv /opt/tunnelscope
/opt/tunnelscope/bin/pip install --no-index --find-links wheels tunnelscope
/opt/tunnelscope/bin/tunnelscope doctor
```

`doctor` must report the tshark version, "all 29 required fields resolve", and the loaded baselines.
If a field has drifted on your tshark it refuses to run rather than under-report (exit 3).

## 4. Running it

- **CLI:** `tunnelscope analyze | assess | report | dashboard | cbom | fleet | crosstier` on capture
  files. Nothing leaves the machine; outputs go where you point them.
- **Dashboard:** `tunnelscope serve` and open `http://127.0.0.1:8765`. It binds to `127.0.0.1` only
  (not configurable). For a shared analysis server, analysts reach it through their own SSH tunnel
  (`ssh -L 8765:127.0.0.1:8765 analysis-host`), which keeps it off the LAN. This is guidance, not a
  built feature: there is no multi-user login.

## 5. Your own baselines

Baselines are versioned YAML inside the package (`tunnelscope/rules/`). To assess against an internal
policy as well, copy that folder, add your YAML, and set `TUNNELSCOPE_RULES_DIR=/path/to/rules`. An
empty or wrong path is refused, never treated as "no findings".

## 6. Limits, stated plainly

- **Tested on:** Debian 12 (arm64) in Docker with tshark 4.0.17, and macOS during development. Not yet
  tested on RHEL/Rocky, Ubuntu LTS, x86_64 servers or Windows. The bundle script works the same way on
  those; the test has not been run there.
- **Integrity, not authenticity:** `SHA256SUMS` detects corruption in transit. It does not prove who
  built the bundle. An organisation should sign the tarball with its own key (for example
  `gpg --detach-sign`) on the staging side and verify it before install.
- **tshark updates are yours.** A newer tshark is checked by `doctor` on every run; an older one is
  fine as long as `doctor` passes (4.0.17 did).
- **The dashboard assumes one analyst per machine** (127.0.0.1, no accounts). A multi-user,
  role-based deployment would be new work (the role-D API in `03-USAGE-AND-OPERATIONS-PLAN.md` §6).

## 7. Re-running the proof

```
build/offline/airgap_test.sh        # needs Docker; rewrites build/offline/AIRGAP-TEST.md, exits non-zero on any failure
```
