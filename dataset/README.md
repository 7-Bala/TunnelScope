# TunnelScope IPsec Capture Dataset — Release

A controlled, hash-verified IPsec/IKE capture set with **causal ground truth** (the configuration we
set + the endpoint's own `swanctl`/`pluto` log — never inferred from the capture). First public
dataset labelled with IPsec cryptographic **configuration** (doc 05: none existed).

| File | What |
|---|---|
| `MANIFEST.csv` | one row per pcap: SHA-256, experiment, arm, implementation, vantage, ground-truth crypto, split |
| `DATASHEET.md` | full datasheet (provenance, splits, limitations, credit) |
| `validate.py` | strict validator — hashes, provenance, split-leakage, EXP-02 negative control (exits non-zero on any violation) |
| `build_manifest.py` | regenerates the manifest + datasheet from `testbed/captures/` |

## Contents (this release)
- **71 pcaps** across EXP-01/02 (cipher family), EXP-03 (PFS rekey), EXP-04 (post-quantum ML-KEM +
  downgrade), EXP-06r2 (failure diagnosis, 35), EXP-07 (Libreswan cross-implementation), EXP-08
  (mode), plus a TFC-padding sample.
- **52 EXP-05 leakage sessions** as per-packet tables (`testbed/captures/exp05/*.pkts.csv.gz`),
  raw pcaps hashed in `testbed/captures/exp05/manifest.csv`.
- Two implementations: strongSwan (5.9.8 classical, 6.1.0 PQ) and Libreswan 5.4.

## Splits (by session/configuration, never packet/flow — DEC-009)
`train` / `validation` / `locked_test`. The locked test set holds the rep5 families **and the entire
Libreswan set** (cross-implementation = a generalisation test, not training).

## Reproduce / verify
```bash
python3 dataset/build_manifest.py    # rebuild manifest + datasheet
python3 dataset/validate.py          # PASS required (hashes, provenance, splits, negative control)
```

## Design methodology
Covering-array / one-factor-microscope design (DEC-004): rather than a full Cartesian product, each
experiment isolates one factor with a matched contrast (e.g. EXP-03 varies only PFS; EXP-02 varies
only AES key length as a negative control). See each experiment's RESULT and the experiment register.

## Ethics / licence
Lab-generated, synthetic traffic only; no real user data; no third-party captures. Testbed PSK is a
throwaway lab key. Dataset-hygiene practices credited to `naman9271/ipsec-pcap-lab`.
