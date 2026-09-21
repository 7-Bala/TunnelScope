# Task 03: datasheet for our labelled traffic dataset

Purpose: we found no public labelled IPsec traffic dataset. Ours (about 216 sessions, 8 classes) is worth
publishing, and a dataset needs a datasheet: what is in it, how it was made, its limits.

- Branch: `task/traffic-datasheet`
- You may edit / create: `dataset/build_traffic_datasheet.py`, `dataset/TRAFFIC-DATASHEET.md`,
  `tests/test_traffic_datasheet.py`, `TODO.md`
- Run checks as: `ALLOW="dataset/build_traffic_datasheet.py dataset/TRAFFIC-DATASHEET.md tests/test_traffic_datasheet.py" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md` and `.agents/rules/10-python-package.md` first.

Goal: a script that generates `dataset/TRAFFIC-DATASHEET.md` from the three manifests, plus a test.
Create branch `task/traffic-datasheet` from `main`. Do NOT edit `dataset/MANIFEST.csv`,
`dataset/build_manifest.py` or `dataset/validate.py`.

INPUTS (read-only). Each has NO header row; columns are
`tag,arm,class,rep,seed,packets,sha256`. Some manifests contain duplicate `tag` rows (a re-run appended
them): keep only the FIRST row for each tag.
  - `testbed/captures/exp05/manifest.csv`         (arms: base, tfc, mux)
  - `testbed/captures/exp15/traffic/manifest.csv`  (arms: tun, tfc, tra, mux, cbc)
  - `testbed/captures/exp16/manifest.csv`          (arms: real, lsw)
The per-packet tables are next to them: `<tag>.pkts.csv.gz` with columns `t,dir,len`.

STEP 1. Write `dataset/build_traffic_datasheet.py` (standard library only: csv, gzip, hashlib, pathlib,
collections). It must:
  a. load the three manifests, dedupe by tag, and record for each session: source (EXP-05/EXP-15/EXP-16),
     arm, class, rep, packets;
  b. verify that `testbed/captures/<dir>/<tag>.pkts.csv.gz` exists for every session and count the rows in
     each one; if a table is missing or its row count differs from `packets`, print a WARNING line and
     list it under a "Discrepancies" heading in the output (do not hide or fix it);
  c. write `dataset/TRAFFIC-DATASHEET.md` containing, in this order:
     1. "Contents": total sessions, total packets, and tables of counts by source, by arm, by class,
        and by repetition. A class x arm table with session counts.
     2. "How it was made": copy the paragraph below verbatim.
     3. "Files and format": each session is one `<tag>.pkts.csv.gz` (columns `t` seconds since first packet,
        `dir` out|in, `len` outer IP length in bytes) plus a row in the source's `manifest.csv` with the
        SHA-256 of the original capture. The original `.pcap` files are not committed (large); they are hashed.
     4. "Known limits": copy the paragraph below verbatim.
     5. "Licence": write exactly `TBD (owner decision)` and "Citation": exactly `TBD (owner decision)`.
        Do not choose a licence yourself.
     6. "Discrepancies": the list from step b, or the sentence "none".
  The script must be deterministic: running it twice gives byte-identical output (sort everything, no timestamps).

HOW IT WAS MADE (copy verbatim):
Sessions were recorded at a keyless router between two IPsec gateways, headers only, so what the file
holds is what a passive observer sees. EXP-05 and EXP-15 use a seeded traffic generator (`testbed/scripts/tgen.py`)
that imitates eight traffic shapes: voip, web, bulk (file transfer), interactive (SSH-like), video,
email (SMTP-like), messaging (WhatsApp-like) and icmp. EXP-16 adds real software (headless Chromium,
OpenSSH and SFTP, Postfix with swaks, an XMPP client and server, ffmpeg RTP, ping) talking to lab servers
through the tunnel, and the generator's traffic carried by Libreswan instead of strongSwan. Arms: `tun`/`base`
tunnel mode AES-GCM-256; `tfc` traffic-flow-confidentiality padding to the MTU; `tra` transport mode;
`cbc` AES-CBC-128 with HMAC-SHA-256; `mux` two traffic types at once; `real` real applications; `lsw` Libreswan.

KNOWN LIMITS (copy verbatim):
One lab network with no internet delay or packet loss. Two IPsec implementations. Traffic is generated
against our own servers, so it is not representative of any organisation's real traffic. A classifier
trained only on the synthetic sessions scored 0.461 on the real-application sessions (EXP-16), so
synthetic and real sessions should not be treated as interchangeable. Class labels describe traffic shapes,
not the applications named in them.

STEP 2. Write `tests/test_traffic_datasheet.py` with these tests (new file; import the script's functions):
  a. running the builder twice gives identical text;
  b. the "total sessions" number in the output equals the number of distinct `tag`s across the three
     manifests, computed independently in the test with `csv` and a `set`;
  c. the sum of the per-class counts equals the total;
  d. the words `TBD (owner decision)` appear twice in the output (licence and citation).

STEP 3. Run `.venv/bin/python dataset/build_traffic_datasheet.py`, read the generated file, and confirm
every number in it against a manual command, for example
`.venv/bin/python -c "..."` or `gzip -dc <one table> | wc -l`. Paste those confirmations.

STEP 4. `ALLOW="dataset/build_traffic_datasheet.py dataset/TRAFFIC-DATASHEET.md tests/test_traffic_datasheet.py" build/check_all.sh --fast`
must be `RESULT: PASS`. Add one line to `TODO.md`. Commit: `T-089: traffic dataset datasheet generator`, with no Co-Authored-By line.

REPORT: check table; the "Contents" tables pasted; the discrepancies list; your manual confirmations.

## DONE WHEN
- `RESULT: PASS`; only the listed files changed; licence and citation say `TBD (owner decision)`.
- Output is byte-identical on a second run; totals match the independent count in the test.
