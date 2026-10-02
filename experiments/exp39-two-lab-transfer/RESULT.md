# EXP-39 — Does training on one lab help on another? — RESULT (2026-10-01)

Pre-registration `d32724e`, scorer `66adfc3`, both committed before the run. Lab A `ipsec-pcap-lab` (`c0cf256`, 175
captures) and lab B `ashwin02-cyber/SIH_2026` (`ef0ffe9`, 180 traffic captures; 36 handshake captures excluded);
pins verified against the PREREG before the run; 0 read errors. Scores in `results/summary.json`, per-capture window
counts in `results/captures.csv`. Both authors' permission was relayed verbally by the project owner; nothing from
either set is redistributed, and the captures were deleted after this file was written.

## 1. Scores as registered

| # | Prediction | Result | Verdict |
|---|---|---|---|
| P39-1 | Shipped model on B: macro-F1 < 0.60 | 0.200 | held (see 2: it could not have been otherwise) |
| P39-2 | Training on A helps on B: M1 >= 0.60 and M0 + 0.15 | M1 0.215, M0 0.200, gain +0.015 | **falsified** (see 2: unattainable by design) |
| P39-3 | M1 through the gates on B: coverage >= 50%, accuracy >= 90% | coverage **48.6%**, accuracy among answered **100%** (35 of 35) | **falsified** (misses by 1.4 points) |
| P39-4 | Training on B helps on A: M2 >= 0.60 and 0.262 + 0.15 | M2 0.270 (gain +0.008) | **falsified** |
| P39-5 | M2 through the gates on A: coverage >= 50%, accuracy >= 90% | coverage 2.0% (3 answers, 0 correct) | **falsified** |
| P39-6 | Adding both labs costs our own CV <= 0.02 | 0.9196 -> 0.9218 (+0.002) | **held** |

## 2. A flaw in the pre-registration, found in the data

I wrote B's five classes into the metric without checking how many 2-second windows each yields. The shipped design
needs at least 3 full windows; B's captures are mostly too short for that:

| Lab B class | Captures | Windows per capture | Reach the model (>= 3) |
|---|---|---|---|
| icmp (10 pings) | 36 | 4 | 36 |
| web (30 curl GETs) | 36 | median 9 | 36 |
| video (ffmpeg, range requests) | 36 | 1 | 0 |
| file_transfer (10 MB scp) | 36 | 0 | 0 |
| voip (SIPp, signalling only) | 36 | 0 | 0 |

The 10 MB `scp` finishes inside a single window and the SIP calls are sparse. So only **two of B's five classes can
be scored at all**, and macro-F1 over five classes cannot reach 0.60 with three classes empty. P39-1 was true and
P39-2 false for structural reasons, not because of anything the models did. Lab B also contributes training windows
for those two classes (plus 36 video windows) and nothing else, so P39-4 had the same limit in the other direction.
The scores in section 1 are reported as registered; they should not be read as the answer to the question.

## 3. What the data does support (post-hoc reading of the per-class table, no new computation)

- **icmp transfers.** Every model, including the unmodified shipped one, scores F1 1.000 on B's icmp, and 35 of 36
  icmp captures are answered (100% correct) through the gates. Ping is easy to recognise whatever the lab.
- **web does not transfer, and training on A did not help.** On B's web the shipped model scores 0.000 and the
  A-trained model 0.075. In both cases the out-of-distribution gate stopped 36 captures, the same number as B's web
  captures (the stage was not recorded per class, so the match is by count): adding A's windows did not change the
  gate's verdict. B's windows are dominated by small packets
  (the share of inbound packets under 128 bytes is +2.5 training SD, outbound +1.9).
- **The other direction, same two classes:** training on B did not help A's icmp (0.000 -> 0.000) or web (0.323 ->
  0.308).
- **Our own data is safe** to combine with both labs (P39-6, +0.002), and a model trained on both fits both labs
  (A 1.000, B 0.600 over its five classes with three empty) but that model has seen the data it is scored on, so it
  proves nothing about transfer.

## 4. What changes

- The pre-registered reading rule for "neither direction holds" said two more labs do not fix it. **That does not
  follow:** this pair of labs cannot answer the question. What follows is narrower: for the two classes both labs
  have, training on the other lab did not help.
- Nothing ships. The shipped model, README wording and gates are unchanged; EXP-38's reading (the gates abstain
  correctly, training-data coverage is the gap) is neither confirmed nor refuted for classes other than icmp and web.
- **Next, not started:** a third lab we make ourselves, with sustained traffic for each class (at least 60 seconds
  each, so every class yields many windows) from generators that differ from our shipped ones and from labs A and
  B; test any retrained model only on that lab. This also needs a decision on short flows: a bulk transfer that ends
  in under 6 seconds gets "insufficient windows" from the shipped design, which is honest but means short transfers are
  never classified.
- Lesson for the next pre-registration: count scorable captures per class from the dataset's own documentation
  before choosing the metric.
