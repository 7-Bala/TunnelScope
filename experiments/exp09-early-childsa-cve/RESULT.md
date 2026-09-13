# EXP-09 (T-022) — Passive detection of the CVE-2026-78135 pattern (early Child SA before auth)

**Date:** 2026-09-12 (updated) · **Status:** DONE (detector shipped in the package; specificity,
plaintext-structural sensitivity, AND a genuine live fault-injected reproduction all validated) ·
**Closes:** OQ-31

## The CVE
strongSwan 6.1.0 fixed **CVE-2026-78135**: a peer could obtain a **usable Child SA from a
CREATE_CHILD_SA exchange before IKE_AUTH completed** (affects 5.9.7+). The hypothesis (doc 11,
RL-033): because IKEv2 exchange type, message ID and SPIs are **plaintext**, this pattern should be
visible to a passive observer.

## Detector
For an IKE SPI pair, fire iff **all three** hold on the wire:
1. `IKE_SA_INIT` (exchange type 34) is present — i.e. the observer saw the SA *from birth*;
2. **no** `IKE_AUTH` (type 35) exchange for it;
3. a `CREATE_CHILD_SA` (type 36) appears.
If (1) is false, the SA predates the capture → **UNKNOWN**, never a detection.

## Result — specificity
Scanned **69 legitimate captures** (all testbed captures across EXP-01…08, both implementations):

| Detector | False positives | UNKNOWN (SA predates capture) |
|---|---|---|
| Naïve ("CREATE_CHILD_SA without prior IKE_AUTH") | **2** | — |
| **Vantage-aware (requires IKE_SA_INIT present)** | **0** | 2 |

The two flagged captures under the naïve rule are the EXP-03 `rekey-*` captures, which start
**after** the tunnel is up and so never contain the IKE_AUTH. The vantage-aware detector correctly
returns UNKNOWN for them instead of a false alarm. **This is the project's vantage discipline
(DEC-003/008) catching a real error class**: "I didn't see the handshake" must not read as "the
handshake didn't happen."

## Sensitivity — validated at the plaintext-structural level (T-022, updated 2026-09-12)
The detector reads **only plaintext ISAKMP header fields** — exchange type, message id, SPIs — which
are unencrypted in *every* IKEv2 message (RFC 7296 §3.1), including the ones whose payloads are
encrypted. Its decision surface is therefore the on-wire **exchange-type / message-id sequence**, and
that sequence can be exercised faithfully with a header-only capture.

`testbed/scripts/gen_cve_positive.py` forges exactly that sequence —
`IKE_SA_INIT (msgid 0) → CREATE_CHILD_SA (msgid 1)`, no IKE_AUTH — into
`testbed/captures/synthetic/cve-2026-78135-plaintext-positive.pcap` (tracked in the manifest as
`split=excluded`, never in any ML split). tshark parses it as exchange types 34, 34, 36, 36; the
shipped extractor fires `early_childsa_cve = early-child-sa-before-auth` (OBSERVED, T1) and the
`CVE-WATCH / CVE-2026-78135` rule returns **FAIL (high)**. Confusion matrix now:

| | detector fires | not-detected / n-a | UNKNOWN (guard) |
|---|---|---|---|
| synthetic positive (1) | **1** | 0 | 0 |
| 69 legitimate captures | **0** | 67 | 2 |

Sensitivity 1/1, specificity 69/69, and the 2 UNKNOWNs are the mid-tunnel rekey captures the vantage
guard correctly refuses to judge.

## Live reproduction (2026-09-12) — genuine fault-injected exploit, not synthetic headers

Went beyond the plaintext-structural positive and reproduced the pattern with real strongSwan 6.1.0
daemons in an isolated Docker lab (`testbed/docker-compose.exploitlab.yml`, completely separate
network/images from the validated Stage 1-3 testbed — see the ISOLATION WARNING in
`testbed/images/strongswan-exploitlab/Dockerfile.*`).

**Root cause, cited exactly.** Cloned strongSwan 6.1.0 (`git b43f6bf`) and traced the real code:
`src/libcharon/sa/ikev2/task_manager_v2.c`, function `reject_request()`, lines 1736-1739:
```c
case CREATE_CHILD_SA:
case IKE_FOLLOWUP_KE:
    reject = state == IKE_CREATED || state == IKE_CONNECTING;
    break;
```
This is precisely the check RL-033 describes: a `CREATE_CHILD_SA` is rejected while the responder's
IKE_SA is still `IKE_CREATED`/`IKE_CONNECTING`, i.e. before `IKE_AUTH` moves it to
`IKE_ESTABLISHED`. `Dockerfile.vulnerable` relaxes exactly this one line (`reject = FALSE`),
build-time-asserted so a silently-unapplied patch cannot ship as validated.

**The other half — a real initiator that skips auth.** `initiate()`'s round-2 exchange-type
selection (same file, ~line 654) picks the exchange from the *first recognized task type still
queued*, independent of IKE_SA state. `Dockerfile.attacker` comments out one line — the
`activate_task(this, TASK_IKE_AUTH)` call in the `IKE_CREATED` case (line 553) — so `IKE_AUTH` is
never activated; `TASK_CHILD_CREATE` becomes the first recognized task, and charon sends a genuine,
correctly-encrypted `CREATE_CHILD_SA` request (using the real SK_ei/SK_ai keys already derived from
`IKE_SA_INIT`) with **no `IKE_AUTH` ever exchanged**.

**Result — the wire capture** (`testbed/captures/exploitlab/cve-2026-78135-live.pcap`, real traffic,
tshark-verified exchange sequence):
```
34 (IKE_SA_INIT, msgid 0)  →  34 (response)  →  36 (CREATE_CHILD_SA, msgid 1)  →  36 (response)
```
No exchange type 35 (IKE_AUTH) anywhere. TunnelScope's shipped detector fires identically to the
synthetic case: `early_childsa_cve = OBSERVED early-child-sa-before-auth`, and `CVE-WATCH /
CVE-2026-78135` returns **FAIL (high)** — now confirmed on genuine live traffic, not forged headers
(`tests/test_cve.py::test_live_exploitlab_capture_if_present`).

**Gate bypass, independently confirmed via the responder's own debug log** (`cfg=3`): the
`CREATE_CHILD_SA` request is fully parsed (proposal, TSi, TSr) with **no state-violation rejection**
— it proceeds past the exact line that fixes the CVE. It fails later for an *unrelated* reason:
`N(TS_UNACCEPT)`.

**What did NOT happen, and precisely why (T2 ground truth, `*.groundtruth.json`):** no Child SA /
kernel XFRM state was installed on either side (`swanctl --list-sas` shows empty `child-sas {}` on
both, `ip xfrm state` empty on the responder). The `cfg`-level debug log shows **zero** `[CFG]
looking for a child config...` lines before the failure — the responder's `child_create` task, given
a `CREATE_CHILD_SA` with no prior `IKE_AUTH`, has no linked `peer_cfg`/`child_cfg` to narrow traffic
selectors against, because that linkage is normally established via `IKE_AUTH`'s identity-based
peer_cfg selection, which never occurred. This is a diagnosed structural reason, not an unexplained
gap: forcing a fully kernel-installed Child SA would need a *further*, separate patch to also force
early peer_cfg selection — genuinely out of scope, since the detector's decision surface (plaintext
exchange headers) is already proven on real traffic regardless of whether the SA installs.

**Reproducibility:** `bash testbed/scripts/run_exploitlab.sh` rebuilds and reruns the whole lab from
scratch (build-time patch assertions fail loudly if a future strongSwan release moves the target
lines); `docker compose -f testbed/docker-compose.exploitlab.yml down` tears it down. Never run
alongside `testbed/docker-compose.yml` — separate subnets, separate container names, by design.

## Verdict
A **deterministic, vantage-aware** passive detector for the CVE-2026-78135 pattern exists, fires on
zero legitimate captures, degrades to UNKNOWN when it cannot see the SA's birth, and now has three
independent layers of validation: specificity (69 real captures, 0 FP), sensitivity on a synthetic
plaintext-structural positive (1/1), and sensitivity on a **genuine live fault-injected exploit
capture** with the exact root-cause gate bypass independently confirmed via the daemon's own debug
log. No AI. It is a concrete, CVE-anchored capability no surveyed tool has (doc 11). It ships
**guarded**: reported only when the SA is observed from IKE_SA_INIT, else UNKNOWN.

**Update (2026-09-13, EXP-12):** a fourth validation layer — an unrelated experiment (rekey-cadence
measurement) incidentally produced a capture with **responder-initiated** rekey activity, which
exposed a genuine false positive: the detector compared message IDs globally, but IKEv2 message IDs
are per-*originator* (RFC 7296 §2.1), so a responder-initiated exchange's own counter restarting at
0 read as "before IKE_AUTH." Fixed to compare by frame/capture order instead of message ID; the "0
FP / 69" claim now also holds against traffic that exercises bidirectional activity, which the
original 69 captures happened not to. Full writeup: `experiments/exp12-rekey-cadence/RESULT.md`.
