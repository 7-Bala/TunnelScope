# EXP-37 — Cross-lab test on two other teams' captures — PRE-REGISTRATION (2026-10-01, before any run on these sets)

## Why
Every accuracy number TunnelScope reports comes from captures we generated ourselves, in our lab, with our
traffic generators. `research/17-GITHUB-LANDSCAPE.md` found two public sets built by other people. This is the
first test of our classifiers and our honesty rules on someone else's lab. Neither set is used for training or
tuning: the shipped models (`tunnelscope/models/*.npz`) are untouched.

## Data (fixed here; kept outside the repository, never committed)
**Part A, `naman9271/ipsec-pcap-lab`**, commit `c0cf25647b88c1cdb0649a43049e192e269f4cc6` (2026-08-30). Ground
truth = its `metadata.csv` (SHA-256 `81234b73e338a6945af19711e1303ffa0f1b174c0b33d0f139fd5e3e145d8a8c`), written
by the generator, not read from an endpoint log: a weaker ground truth than ours, and the result says so.
Captures are taken on the outer side of one endpoint, filter `esp or udp port 4500`, so **no IKE handshake is in
the 175 known captures**. strongSwan 5.9.13, PSK only, 3 ciphers (AES-128-CBC, AES-256-CBC, AES-256-GCM-16),
4 DH groups, PFS on/off, tunnel/transport, IKEv1/IKEv2, IPv4/IPv6. Licence: none. Use is local analysis only;
nothing is redistributed. Sets used: `pcaps/known` 175, `pcaps/ood` 29 files (25 are `ood_eval`, 4 archived),
`pcaps/anomaly` 30, `pcaps/protocol_validation` 5.

**Part B, `jeevanelton/ipsec-mlkem-thesis-artifacts`** (data on the author's Google Drive, fetched 2026-10-01).
60 runs of a strongSwan 6.x pair: Classical (ECDH only) vs Hybrid (Curve25519 + ML-KEM-768), 3 WAN profiles x 10
repetitions. Ground truth = the `swanctl --list-sas` dump saved per run: every classical run reads
`AES_GCM_16-256/PRF_HMAC_SHA2_256/CURVE_25519`, every hybrid run adds `KE1_ML_KEM_768`. Five control-plane
captures could not be retrieved (Drive access refused): Classical/P2/run10, Hybrid/P1/run1, Hybrid/P1/run9,
Hybrid/P2/run1, Hybrid/P2/run2. **Used: 55 captures (29 classical, 26 hybrid)**, inventory with SHA-256 in
`pq_thesis_inventory.csv` (file SHA-256 `735e6a0f48d69b1c62c6ca61223906d08d71fdf6695528893a9054cf6c2e3e43`).
Only `*_ike_control_plane.pcap` is analysed (the data-plane UDP captures were not fetched). Licence: none.

## What has been seen before this was written (disclosure)
- `tunnelscope analyze --json` was run on **one** capture, `known/voip/voip_p01_R05.pcap`, to read the output
  schema. It returned `traffic_type` UNKNOWN, `esp_cipher_family` INFERRED with several candidates, `ike_dh_group`
  UNKNOWN, `pfs` NOT_OBSERVABLE. It was not run on any other capture of either set.
- `metadata.csv` column values and counts, and `DATASET.md`, were read (ground truth, not tool output).
- For Part B: the `swanctl` dumps (ground truth) and a plain `tshark` packet listing of two runs (Hybrid/P0/run1 has
  IKE_SA_INIT 282 B, IKE_INTERMEDIATE 1291 B / 1195 B, IKE_AUTH; Classical/P0/run1 has IKE_SA_INIT 266 B and
  IKE_AUTH only). Several control-plane captures are cut off at a 4096-byte multiple (17 of 26 hybrid files are
  4096 B), so some runs may lack part of the exchange; this is handled by the inclusion rule below.

## Method
`analyze.py` calls `build_records(path)` and the default assessment on every capture of the sets above and writes
one row per record to `results/raw.jsonl`, then `results/summary.json`. Captures are located through
`EXT_LAB_DIR` and `PQ_DIR`; nothing is copied into the repository. One ESP capture is one analysed SA-set;
where a capture yields several records, the record with the most ESP packets is scored.
Mapping to the other lab's classes: our `bulk` = their `file_transfer`; our `interactive` has no counterpart in
their seven known classes. Cipher family: metadata `cipher` containing "CBC" -> CBC, containing "GCM" -> GCM.
"Commits" means `traffic_type` is not UNKNOWN. Confident = finding confidence >= 0.8.

## Part A predictions (175 known + 29 ood + 30 anomaly + 5 protocol_validation)
| # | Prediction | Falsified if |
|---|---|---|
| P37-1 | No guessing: on the 175 known captures (ESP-only) `ike_dh_group` and `pfs` are never OBSERVED or INFERRED | any capture asserts a value |
| P37-2 | The cipher sieve never excludes the true family: whenever `esp_cipher_family` is INFERRED, its candidate set contains the metadata family | any exclusion of the true family |
| P37-3 | Cross-lab traffic type, committed answers only: accuracy >= 0.70 against the mapped label | < 0.70 |
| P37-4 | Coverage: the tool commits on >= 50% of the 175 known captures | < 50% |
| P37-5 | Confident-and-wrong: <= 10% of commits are wrong with confidence >= 0.8 | > 10% |
| P37-6 | Out-of-distribution: on the 25 `ood_eval` captures >= 60% get UNKNOWN or a finding confidence < 0.6, instead of a confident single label | < 60% |
| P37-7 | Mode: where `mode` is not UNKNOWN it matches metadata (tunnel/transport) in >= 80% of captures | < 80% |
| P37-8 | The 5 protocol-validation captures: no OBSERVED value contradicts metadata (IKE version, cipher, DH group, mode) | any contradiction |
Exploratory, not scored: what the tool says on the 30 anomaly captures (ICMP flood, UDP flood, beacon burst),
the per-class confusion matrix, the share of UNKNOWN per profile (P01-P05), and cipher-candidate set sizes.

## Part B predictions (55 control-plane captures)
Inclusion rule, fixed now: a capture is analysed for P37-9..P37-11 only if the tool reports a complete IKE_SA_INIT
exchange (`has_ike_sa_init` true). Excluded captures are counted and listed, not hidden.
| # | Prediction | Falsified if |
|---|---|---|
| P37-9 | Every included hybrid run: `pq_key_exchange` is OBSERVED and names ML-KEM-768 | any included hybrid run not OBSERVED as ML-KEM-768 |
| P37-10 | Zero false PQ claims: no included classical run has `pq_key_exchange` OBSERVED or INFERRED as present | any |
| P37-11 | For every included run the OBSERVED IKE suite equals the `swanctl` dump (AES_GCM_16-256, PRF_HMAC_SHA2_256, CURVE_25519) | any mismatch |
| P37-12 | At least 80% of the 55 captures are included (the truncation does not remove the SA_INIT) | < 80% included |

## Reading the result
Every prediction is reported whether it holds or not. A failure in P37-1, P37-2, P37-8 or P37-10 is an honesty
failure (we asserted something the wire does not show) and is a bug to fix in a separate task, not a number to
explain away. P37-3..P37-7 failing means the in-lab figures do not carry across labs, and the README wording on
traffic-type accuracy is then narrowed. Findings about the other teams' data (label errors, odd captures) are
reported as findings about their data, not corrected here. Captures are deleted from the machine after the
result is written.
