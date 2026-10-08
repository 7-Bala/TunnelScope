# TunnelScope IPsec capture dataset

Hash-verified IPsec/IKE captures with **causal ground truth**: the configuration we set, plus the
endpoint's own `swanctl` or `pluto` log. The answer for each capture never comes from the capture
itself. Built as one-factor-at-a-time arms on three IPsec implementations, with a held-out test split
and post-quantum downgrade arms.

| File | What |
|---|---|
| `MANIFEST.csv` | one row per pcap: SHA-256, experiment, arm, implementation, vantage, ground-truth crypto, split |
| `DATASHEET.md` | full datasheet: provenance, splits, contents, credit |
| `TRAFFIC-DATASHEET.md` | the traffic-session dataset used to train and test the traffic-type models |
| `validate.py` | validator: hashes, provenance, split leakage, negative control (exits non-zero on any violation) |
| `build_manifest.py` | regenerates the manifest and datasheet from `testbed/captures/` |
| `build_traffic_datasheet.py` | regenerates the traffic datasheet |

## Contents

- **103 pcaps**: cipher families, perfect forward secrecy, post-quantum ML-KEM and downgrade,
  failure diagnosis, mode, rekey cadence, cloud-VPN-style proposals, cipher suites and AH,
  encapsulation, authentication methods and a live-vulnerability lab.
- **Per-packet traffic tables** for the metadata and traffic-type work, under `testbed/captures/`.
- **Three implementations:** strongSwan (5.9.8 and 6.1.0), Libreswan 5.4 and OpenBSD `iked` 7.9.

## Splits

Splits are by session or configuration, never by packet or flow (DEC-009): `train`, `validation` and
`locked_test`. The locked test set holds the held-out repetition families and the whole Libreswan set,
so every test is on captures the models never trained on.

## Reproduce and verify

```bash
python3 dataset/build_manifest.py    # rebuild manifest + datasheet
python3 dataset/validate.py          # hashes, provenance, splits, negative control
```

## Design

Each experiment varies one factor against a matched control (for example, PFS on and off, or AES-128
and AES-256), rather than a full Cartesian product. See each experiment's `RESULT.md` and
`research/registers/EXPERIMENT-REGISTER.md`.

## Ethics and licence

Lab-generated traffic only: no real user data. The testbed pre-shared key is a throwaway lab key.
Dataset-hygiene practices are credited to `naman9271/ipsec-pcap-lab`.
