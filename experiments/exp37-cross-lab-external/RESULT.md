# EXP-37 — Cross-lab test on two other teams' captures — RESULT (2026-10-01)

Pre-registration `df26be3`, scorer `43dcd82`, both committed before the run. Run: `analyze.py` over 239 captures of
`ipsec-pcap-lab` (commit `c0cf256`) and 55 control-plane captures of the ML-KEM thesis set; raw rows in
`results/raw.jsonl`, scores in `results/summary.json`. Post-hoc re-score in `results/posthoc/` (section 3). All
captures were deleted from this machine after this file was written; nothing from either set is in the repository.

## 1. Pre-registered scores (scorer v1, as committed)

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P37-1 | ESP-only captures never assert a DH group or PFS | 0 violations in 175 | **held** |
| P37-2 | The cipher sieve never excludes the true family | 175 of 175 INFERRED, 0 exclusions (the exact cipher + integrity pair, e.g. AES-256-CBC with HMAC-SHA384, was also inside the candidate set 175 of 175; exploratory) | **held** |
| P37-3 | Traffic type, committed answers: accuracy >= 0.70 | 5 commits, **0 correct** (4 x file_transfer read as "video streaming", 1 x messaging read as "interactive shell") | **falsified** |
| P37-4 | Coverage >= 50% of 175 | **2.9%** (5 of 175; P01 0/35, P05 0/35, P02 2, P03 1, P04 2) | **falsified** |
| P37-5 | Confident-and-wrong <= 10% of commits | 0 of 5 were confident (no answer reached 0.8) | held, vacuous (5 commits) |
| P37-6 | Out-of-distribution: >= 60% UNKNOWN or low confidence | 25 of 25 | held, **but not informative**: the tool also answered UNKNOWN on 97% of the in-distribution captures, so it abstains on everything from this lab |
| P37-7 | Mode, where committed, >= 80% correct | the tool never committed to a mode on an ESP-only capture (0 of 175) | **untestable** (design-consistent: mode is negotiated inside the encrypted IKE_AUTH) |
| P37-8 | Protocol-validation: no OBSERVED value contradicts metadata | 8 OBSERVED values (IKE version x5, DH group x3), 0 contradictions (`MODP-2048` = group 14, `ECP-256` = 19, `ECP-384` = 20) | **held** |

Part B as scored by v1:

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P37-12 | >= 80% of 55 captures pass the inclusion rule | 31 of 55 (56%): **24 hybrid files could not be read** (section 2) | **falsified** |
| P37-9 | Every included hybrid run OBSERVED as ML-KEM-768 | 0 of the 2 included hybrid runs | **not meaningful** (scorer defect, section 3) |
| P37-10 | Zero false PQ claims on classical runs | 0 of 29 | **held** |
| P37-11 | OBSERVED suite equals the `swanctl` dump | 30 of 31 flagged as mismatches | **not meaningful** (scorer defect, section 3) |

Exploratory, not scored: on the 30 anomaly captures (ICMP flood, UDP flood, beacon burst) the traffic type was
UNKNOWN in all 30.

## 2. What the two honesty outcomes and the two failures mean

- **The honesty rules hold on another lab's data.** Across 175 ESP-only captures the tool never claimed a DH
  group, never claimed PFS, never excluded the true cipher family, and never contradicted a single handshake
  value it did read. That is the part of the project that matters most, and it transferred.
- **The traffic-type classifier does not transfer to this lab.** It answered 5 of 175 times and was wrong every
  time. It is safe (it abstains, and says why: "this traffic looks unlike the lab traffic ... the attacker was
  trained on") and also nearly useless here. The five wrong answers carried confidence below 0.8, so the
  abstention gate did its job on 97% of captures and leaked on 3%.
  Likely reason, not tested: this lab's generators (per its README: web objects, HLS video segments, file
  transfers, a local SMTP server, WebSocket messaging, ffmpeg RTP audio) have a different packet-size and timing
  shape from ours, and the shipped model was trained on our lab plus public tunnels.
- **The product rejects partly damaged files.** 24 of the 26 hybrid captures end in the middle of a packet at a
  4096-byte boundary (a capture buffer that was never flushed). `tshark` reads the 9 whole packets, which contain
  the complete handshake (`IKE_SA_INIT`, `IKE_INTERMEDIATE` 1291 B, `IKE_AUTH`); TunnelScope refuses the file
  outright (`tshark could not read ...`). A capture cut short by a killed `tcpdump` is common in the field.
  Rejecting it is honest, but it throws away evidence that is present.

## 3. Deviations, stated plainly

1. **Scorer defect in Part B (found after seeing the v1 numbers).** The PREREG method said that where a capture
   yields several records, the one with the most ESP packets is scored. That rule was written for Part A. A
   control-plane capture has no ESP, so it picked an arbitrary record, usually the old IKE SA being torn down
   (an `INFORMATIONAL` exchange at the start of each file), whose fields are UNKNOWN. This is why 28 of 29
   classical runs and 2 of 2 readable hybrid runs showed UNKNOWN in v1 even though their handshakes are intact.
   The v1 figures for P37-9 and P37-11 are therefore not evidence about the product. They are kept as committed.
2. **Post-hoc re-score (`posthoc_pq.py`, not pre-registered).** It keeps every record, judges each capture as a
   whole, and also scores copies trimmed to whole packets (written outside the repo, nothing else altered):

   | | read by the product as-is | after trimming to whole packets |
   |---|---|---|
   | hybrid (26) | 2 | 26 |
   | hybrid read as ML-KEM-768 | 2 of 2 | **26 of 26** |
   | hybrid suite equals `swanctl` (AES_GCM_16-256, CURVE_25519) | 2 of 2 | **26 of 26** |
   | classical (29) read | 29 | 29 |
   | classical suite equals `swanctl` | 29 of 29 | 29 of 29 |
   | classical false PQ claims | 0 | 0 |

   Read with the post-hoc caveat (the thresholds were fixed before, the scoring unit was corrected after): the
   post-quantum detection works on a different team's real strongSwan 6 hybrid handshakes, and the only failure is
   the file-reading step. The honest label for this table is "exploratory confirmation", not a passed prediction.
3. P37-8 was marked for hand adjudication in the PREREG and was adjudicated here (section 1). The IKEv1 sessions
   (P03, P04) reported OBSERVED version `IKEv1` and UNKNOWN for cipher and DH group; nothing was contradicted.

## 4. Findings about their data (reported as theirs, nothing corrected)

- `ipsec-pcap-lab`'s known captures are ESP-only by design, so DH group and PFS in its metadata cannot be checked
  from the pcaps; ground truth is the generator's declaration, not an endpoint log.
- The thesis set's hybrid control-plane captures are mostly cut short (24 of 26) and each file begins with the
  tail of a previous SA's `INFORMATIONAL` exchange. Five of the 60 control-plane files were not downloadable from
  the author's Drive (access refused) and are not in this analysis.
- Neither set has a licence. Both were used for local analysis only and deleted.

## 5. What changes

- **Product, separate tasks (not done here):** (a) read the whole packets of a capture that is cut short, analyse
  them, and say "capture cut short, N packets used" as a caveat instead of refusing the file; (b) check why IKEv1
  Main Mode sessions give UNKNOWN for cipher and DH group when the proposals are sent in the clear (a coverage gap,
  nothing here shows a wrong value); (c) decide whether the traffic-type model should be trained on, or tested
  against, more than one lab's generators before the accuracy wording is used in front of NTRO.
- **Wording (done with this result):** the README's honest-limits paragraph now states the cross-lab outcome.
- The pre-registered reading rule applies: P37-1, 2, 8 and 10 held (no honesty failure); P37-3, 4 and 12
  falsified; P37-7, 9 and 11 are not scorable as registered.
