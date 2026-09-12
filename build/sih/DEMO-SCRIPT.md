# TunnelScope — Live Demo Script (~4 min)

Run from the repo root. Each step is one command + the point it proves. (User records the video.)

## Setup (before the room)
```bash
pip install -e .                 # tshark must be on PATH
```

## 1 · The honest evidence view (30s)
```bash
tunnelscope analyze testbed/captures/pq-mlkem768.pcap
```
**Point:** every attribute shows status + vantage + method. `mode` is **NOT-OBSERVABLE** and
`pfs` is NOT-OBSERVABLE (no rekey seen) — the tool refuses to guess. `pq_key_exchange = ML-KEM-768`.

## 2 · The headline: post-quantum downgrade (60s)
```bash
tunnelscope report testbed/captures/pq-downgrade.pcap --level exec
```
**Point:** posture **DOWNGRADED (PQ offered, classical used)**; DST-PQ-DOWNGRADE **FAIL** (high).
This is the capability nothing else has, tied to the DST 2027 mandate.

## 3 · Multi-baseline honesty (45s)
```bash
tunnelscope assess testbed/captures/cs-aes256gcm16.pcap
```
**Point:** the **same tunnel** PASSES RFC 8247 and FAILS DISA V-207193 (MODP-2048 vs group≥16),
each verdict **citing its authority**. A single score would hide this.

## 4 · The dashboard (30s)
```bash
tunnelscope dashboard testbed/captures/pq-downgrade.pcap -o dash.html && open dash.html
```
**Point:** self-contained, offline, colour-coded — grey = not observable, red = fail.

## 5 · Failure diagnosis from encrypted traffic (30s)
```bash
tunnelscope analyze testbed/captures/exp06r2/exp06r2-f01-rep1.pcap | grep negotiation_outcome
tunnelscope analyze testbed/captures/exp06r2/exp06r2-f06-rep1.pcap | grep negotiation_outcome
```
**Point:** `ike-proposal-mismatch` vs `peer-unreachable` — diagnosed from structure alone, the thing
practitioners currently do by hand-reading both configs.

## 5b · CVE-2026-78135 detection, on a real live exploit (30s)
```bash
tunnelscope assess testbed/captures/exploitlab/cve-2026-78135-live.pcap | grep -A1 CVE
```
**Point:** this is not a forged capture — it's genuine traffic from a real strongSwan pair in an
isolated Docker lab where we bypassed the actual CVE fix (`task_manager_v2.c`'s auth-completion
gate) and made a real initiator skip IKE_AUTH entirely. The detector fires **FAIL (high)** on the
exact same wire pattern it fires on synthetically, and on all 69 real captures it fires **zero**
times (returns UNKNOWN when it can't see the handshake, never a false alarm). See
`experiments/exp09-early-childsa-cve/RESULT.md` for the full reproduction and root-cause citation.

## 5c · Higher vantage changes the answer — honestly (30s)
```bash
tunnelscope crosstier testbed/captures/classical-baseline.pcap testbed/telemetry/iptfs-contradiction.t2.json
```
**Point:** feeding the endpoint's own config resolves `mode` (invisible on the wire), and surfaces a
**CONTRADICTORY** finding — the config says TFC padding is on, the wire says it's off (the real
NOTES #13 IP-TFS bug). The tool trusts the endpoint and *flags the divergence* rather than hiding it.

## 6 · Prove it's not cherry-picked (30s)
```bash
python3 build/validate_e2e.py        # 69/69 vs ground truth
python3 -m pytest tests/ -q          # 24 tests
python3 dataset/validate.py          # dataset integrity PASS
```
**Point:** every claim reproduces against causal ground truth, on two implementations.

## Close (spoken)
"Deterministic where the protocol allows it, one honest ML measurement where it helps, and
NOT-OBSERVABLE wherever the physics says we can't see — so you never act on a guess."
