# EXP-19 — Real public traffic (MIT VNAT): does it improve the traffic classifier, and does it transfer to IPsec? — PRE-REGISTRATION (2026-09-24, before any training or metric)

Owner, 2026-09-24: "look for publicly available datasets and train the model ... we want real data
not lab grown data". Every traffic window the shipped classifier learned from so far was captured in
our Docker lab (synthetic generators, and real applications run inside the lab). This experiment adds
real traffic recorded by others, and measures what it does, before anything ships.

## Data (fixed)
- **MIT Lincoln Laboratory VNAT** (VPN / non-VPN Network Application Traffic, 2022),
  `VNAT_Dataframe_release_1.h5` (1,045,436,008 bytes, from archive.ll.mit.edu/datasets/vnat/),
  kept outside the repo in `~/Datasets/vnat/`; its sha256 is recorded in `results/` at conversion.
  Per connection: packet timestamps, sizes and directions, and the capture file it came from.
- **Only the VPN captures are used** (files named `vpn_*`): real application traffic inside an
  encrypted tunnel. The VPN is **OpenVPN, not IPsec**; that difference is what Q3 measures.
- Label mapping to our classes (by the application keyword in the capture file name; nothing else):

| VNAT keyword | Our class |
|---|---|
| netflix, youtube, vimeo | video |
| voip (Zoiper) | voip |
| skype-chat | messaging |
| ssh, rdp | interactive |
| sftp, rsync, scp | bulk |

  VNAT has no web browsing, e-mail or ping, so those three classes are not tested here.
- Packets become windows with the unchanged `window_features` (2-second windows, same 31 features).
  Direction "out" = from the VPN client. If the dataframe's sizes are frame lengths rather than IP
  lengths, 14 bytes (Ethernet) are subtracted; which one it is is decided from the schema and a
  size histogram only, before any label or metric is looked at, and recorded in `results/`.
- A connection contributes windows only if it has at least 3 complete windows (the tool's own
  `MIN_WINDOWS`); at most 60 windows per connection (seeded random choice) so that long streams do
  not dominate. Seed 19.

## Questions and measurements (macro-F1 over the classes present; Wilson/fold spread reported)
- **Q1, today's model on real traffic:** the shipped classifier (lab-trained) on all VNAT VPN windows.
  A prediction outside the 5 VNAT classes counts as wrong.
- **Q2, real-only model:** Random Forest (the shipped settings) trained on VNAT VPN windows,
  5-fold cross-validation **grouped by capture file** (a file is never in train and test at once).
- **Q3, does real OpenVPN traffic transfer to IPsec?** The Q2 model trained on all VNAT VPN windows,
  tested on our IPsec real-application sessions (EXP-16 `real`, EXP-17 `wan-real`, `lossy-real`)
  for the 5 overlapping classes.
- **Q4, combined model (the shipping candidate):** today's training set plus the VNAT VPN windows.
  (a) VNAT grouped 5-fold with all lab data always in training; (b) our lab evaluation (leave one
  repetition out on the EXP-16 real-application sessions, as in EXP-16) with all VNAT always in
  training, compared with the same procedure without VNAT, run in the same script.

## Ship bar (fixed now)
The combined model replaces the shipped `traffic_windows.npz` only if **all** hold:
1. Q4a macro-F1 **>= 0.80** on held-out VNAT capture files;
2. Q4a is at least **0.10 higher** than Q1 (the real data materially helps on real traffic);
3. Q4b is **no more than 0.02 below** the same procedure without VNAT (our IPsec lab cases are not harmed);
4. the file stays under the repo's 5 MB limit.
Otherwise nothing ships, and the result is still reported. The mixed-traffic detector, the abstain
rule (TAU 0.60, consistency 0.70) and the out-of-distribution gate are not changed in this experiment.

## Rules
- No threshold, class mapping, cap or seed is changed after this commit. Whatever fails is reported.
- Q3 is reported whatever it shows; a low number is a finding about OpenVPN vs IPsec, not a failure to hide.
- `analyze.py` writes `results/summary.json`; `RESULT.md` quotes only that and is not edited after.
