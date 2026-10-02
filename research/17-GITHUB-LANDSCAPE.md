# 17 — GitHub landscape and dataset sweep (2026-10-01)

Asked for: find every public repository built for our problem statement, judge how each is built and
whether it beats ours, and find any dataset worth using, ranked, without relying on keywords alone.

The problem-statement ID is written `SIH-xxxxx` below, and repo names that contain it are masked the
same way (owner rule of 2026-10-01: the ID must not be searchable in the public repo). The unmasked
list is in the session transcript only.

Machine-readable list of all 61 entries: [`data/github_landscape_2026-10-01.csv`](data/github_landscape_2026-10-01.csv).

## 1. How the search was done (and where it is weak)

| Route | What | Pool after |
|---|---|---|
| Keyword | 20 repository queries (the ID, "ipsec analyzer", "ikev2 pcap", "ESP traffic classification", "pq readiness", ...) | 62 |
| Topic | `topic:ipsec`, `ikev2`, `isakmp`, `strongswan`, `vpn-detection`, `encrypted-traffic-classification`, ... | 672 |
| Date window | the same words restricted to repos created since 2026-06 | 1,536 |
| Exhaustive name/description paging | `ipsec in:name`, `ikev2 in:name,description`, ... up to GitHub's 1,000-result cap | 4,611 |
| Code content | 11 code searches for things only an IPsec analyser contains (`esp.spi tshark`, `isakmp.exch_type`, our own words `NOT_OBSERVABLE`, `RFC 8247`, ...) | included |
| README-body recovery | every SIH-season repo with an empty or short description, README read for the ID or "ipsec" | +62 repos |
| Independent check | web search for the same topic, compared against the pool | recall 9 of 10 |

The README-body pass mattered: the filter on description alone had dropped `naman9271/SIH-xxxxx-Alchemist`
(empty description) and 10 more. Final: **526 repositories profiled** (README, full file tree, languages),
of which **61 are submissions to this problem statement**.

**Limits, stated plainly.** No rival code was executed and no pcap was downloaded (only text files:
READMEs, docs, metadata CSVs, read into memory). Test counts, accuracies and "verified" ticks below are
the rivals' own README claims unless marked *(checked)*. The ranking score (section 3) is my own rubric
and rewards scale, tests, real captures, a testbed and a held-out evaluation; it is a triage tool, not a
verdict. Zenodo's API refused direct requests from this machine (HTTP 403), so Zenodo was read through
WebFetch and web search only. Search results are capped by GitHub, so a repo with no description,
no topics and a README that never says "ipsec" could still be missing.

## 2. Headline findings

1. **61 submissions, about 57 independent.** 2 exact copies (`palla-mahesh`/`psryogeshwar-14`,
   `ShravyaRHegde`/`sharancode3` TunnelTrace-AI) and 2 near-copies (>85% of paths shared). 55 were created
   in September 2026, 6 in August. Only 17 carry any licence. 31 have 5 or more test files, 26 ship 5 or
   more pcaps, 25 ship a trained model file.
2. **Our central idea is no longer rare.** At least six other teams state the same stance in their README:
   findings tagged observed/inferred/unknown, "cannot assess", score capped by how complete the evidence
   is (`ashwin02-cyber/SIH_2026`, `VaLence_IPSec`, `CipherGuard`, `ipsec-lens` "UNKNOWN is not SECURE",
   `rakshak-vyuh`, `IPsec-Analyzer`). One (`CipherGuard`) uses our method of excluding impossible ciphers
   with RFC 4303 framing rules, and three (`CipherGuard`, `rakshak-vyuh`, `Piyush800x/ipsec-analyzer`)
   check against third-party Wireshark captures, as our T-085 does.
3. **What still looks unique to us** (searched across all 526 repos; README/tree text only, so strong
   signal and not proof of absence): pre-registered experiments (`PREREG`) — ours only; negative controls
   and mutation checks — ours only; an entire second implementation held out as a locked generalisation
   test, and a third implementation (OpenBSD `iked`) — ours only; a decision log is shared with 3 others.
4. **Our "first dataset" wording is out of date** (section 5, action A).
5. **The established open-source tools are mostly active scanners** (`iker`, `ikebuster`, `IKESS`,
   `OIPsecX`) and decapsulators (`ipdecap`). They are complements, not rivals, as research/15 concluded.
   The one ML outlier, `vverky/IPSec-VPN-Classification` (MIT, 69 stars), predicts plaintext lengths with a
   Transformer from CSVs of a few MB; no raw captures.

## 3. The closest rivals, how they are built, and whether they beat ours

Ours, measured the same way: 605 tests collected, 17 rules in 5 YAML files, 71 pcaps plus 52 leakage
sessions in the release set (693 capture files in the testbed), two IKE implementations plus OpenBSD
`iked`, 32 experiment folders.

| Repo | Built as | Claims worth taking seriously | Beats us on | We beat it on |
|---|---|---|---|---|
| `PrashamJ17/SIH_PS…` | Python, `src/ipsec_sentinel`, 119 test files, Docker strongSwan testbed | 2,618 tests + `mypy --strict`; 26 cited rules; change packages for six vendors; grouped splits: 99.2% held-out captures, **95.5% held-out configurations**, 96.7% held-out DH groups, on 637 windows / 276 captures / 48 configs; reports the leaky-split inflation too | Claimed test volume, vendor breadth of remediation, evaluation write-up | Cross-implementation test, pre-registration, negative controls; its data is manifests only (no pcaps), no licence |
| `Piyush800x/ipsec-analyzer` | FastAPI + Postgres + React, LightGBM and CNN | 248 labelled sessions (DVC, not public); configuration-disjoint splits; scores of 1.0 with the footnote that they "measure how distinct the generators are" | Production-style stack | Public data, cross-implementation |
| `shivansh193/vaultscope` | Python core, 1D-CNN + XGBoost, WebSocket live mode | `dumpcap` live ingest, session diff, `/simulate` what-if, Cypress end-to-end, 300 ground-truth JSONs | Live ingest, what-if API | Evidence discipline; its pcaps are not published |
| `ashwin02-cyber/SIH_2026` | Python, 243 tests, strongSwan Docker | Every finding observed/inferred/declared/unknown; score capped by completeness; ESP/AH sequence, replay and rekey analysis; defence what-if; **216 real pcaps in git** | Public real dataset; candid about its own PFS-label bug | Held-out evaluation, second implementation |
| `newone-ss/VaLence_IPSec` | Python `tunneltwin`, MIT, CI + mypy + ruff | PARSED/OBSERVED/INFERRED provenance, "CANNOT ASSESS"; parses Cisco/strongSwan/FortiOS configs and adds consent-gated active IKE probing | Config parsing + active probe (we exclude active probing, DEC-005) | Evidence base (45 pcaps, no held-out) |
| `Muneerali199/rakshak-vyuh` | Rust single binary, from-scratch IKE dissector | 15 cited rules; **SHA-256 hash-chained evidence ledger**; CycloneDX 1.6 crypto inventory; HNDL score; 39 real captures | Tamper-evident ledger; single-binary distribution | ML, held-out evaluation, test depth (2 test files) |
| `Git-huber2007/CipherGuard` | Python, 23 test files | RFC-4303 plausibility mask with no learned model; validated on five real Wireshark captures; PQ exposure ranking; rollback playbooks for four vendors | Rollback in remediation | Experimental design |
| `naman9271/SIH-xxxxx-Alchemist` | Go backend + Python ML worker + Next.js, live site | Random Forest trained on the team's own lab data (section 4); PDF reports | Polish, deployed demo | Evidence rigour, cross-implementation |
| `POKEDB10/Janus` | React + RAG + XGBoost/SHAP | MITRE ATT&CK matrices, CISO and technical PDFs, swanctl snippets | Report variety | Evidence labels (none found) |
| `ShravyaRHegde/tunneltraceai` (2 copies) | Python, 130 test files, 398 `.py` | 589 tests, heavy architecture docs, "specification baseline frozen" | Documentation volume | Real evidence runs |

**Verdict.** On *evidence and experimental method* nothing found matches us. On *breadth and polish* no
single rival dominates, but five (`SIH_PS…`, `vaultscope`, `CipherGuard`, `ashwin02`, `rakshak-vyuh`)
beat us on at least one visible axis, and `SIH_PS…` is a genuine peer on evaluation honesty. We should not
claim a lead on "honest about uncertainty"; we can claim it on pre-registration, negative controls and
holding out a whole implementation.

Low end, for context: of the 61, 26 have two or fewer test files (17 have none), `Prayas536/sih-ipsec`
describes "synthetic testbed PCAP generators" and ships scapy generation scripts next to its 157 captures
(so those are probably forged, not captured; I did not confirm), and `Samarth2357-hacker/ipsec-analyzer` trains on
`np.random.normal` vectors (already in the research log, 2026-09-07). One repo, `shivanshu1512/TunnelScope-SIH-xxxxx`,
shares our project name; it was created a week after ours, is a notebook project on a synthetic CSV, and
shares no code with ours as far as the file tree shows. Treat it as a name clash only.

Ideas worth taking, in order of value: (1) the hash-chained ledger from `rakshak-vyuh`, cheap and in the
spirit of "never claim more than the evidence"; (2) printing the leaky-split versus grouped-split gap as
`SIH_PS…` does; (3) one external-lab test of our classifiers (section 5, action C).

## 4. Datasets

The prior survey (research/15, 2026-09-20) said no public labelled IPsec set existed. That is no longer
true, and was already doubtful on that date: the repos holding two of the sets below were created on
2026-08-26/27 (when the data itself landed was not checked).

Rubric (my judgement, 0–5 each, max 30): real stack, label strength, scale and diversity, reuse licence,
provenance and splits, fit for TunnelScope. Depth: **A** = docs and metadata read; **B** = README and
tree only; **C** = third-party summary only.

| # | Dataset | Contents | Licence | Real? | Score | Depth |
|---|---|---|---|---|---|---|
| 1 | `naman9271/ipsec-pcap-lab` | 239 pcaps: 175 known (7 classes x 5 profiles x 5 runs, 989 MB), 25 out-of-distribution evaluation (29 files in the folder, 4 archived), 30 anomaly, 5 protocol-validation; metadata has cipher, integrity, DH group, PFS, mode, IKE version, IPv4/6, SHA-256, versions, run-level split R01-03/R04/R05 | **none** (the team's app repo is MIT) | strongSwan 5.9.13 in Docker, PSK only | **25** | A |
| 2 | `newone-ss/VaLence_IPSec` | 45 pcaps (28.6 MB), lab folders by profile and traffic | MIT | lab scripts, strongSwan configs | 20 | B |
| 2 | `corelight/zeek-spicy-ipsec` traces | 8 test traces: IKEv1 main and aggressive, ESP/AH tunnel, certs | BSD-3 | third-party captures (source not checked; likely the Wireshark wiki samples we already use) | 20 | B |
| 4 | `ashwin02-cyber/SIH_2026` `real_captures` | 216 pcaps, 36 configs (3 ciphers x 3 DH x 2 modes x 2 PFS) x 5 classes + a handshake each; `manifest.csv`. Own README: 1 run per config, VoIP is SIP only, and an earlier set had PFS on/off identical | none | strongSwan in Docker | 19 | A |
| 4 | `Muneerali199/rakshak-vyuh` corpus | 39 handshake-heavy captures (IKEv1 aggressive 3DES, DH 1536, x25519, legacy integrity), `packets.csv` | not stated | "real strongSwan gateway" | 19 | B |
| 4 | `jeevanelton/ipsec-mlkem-thesis-artifacts` | 60 accepted runs: classical vs hybrid ECDH+ML-KEM, 3 WAN profiles x 10 reps; the captures are zips on Google Drive, only summary CSVs in the repo | none | GNS3 + VMware | 19 | C |
| 7 | `lpefferkorn/ipdecap` unit tests | one ESP capture per algorithm pair (used by its decryption tests) | GPL-3.0 | other people's captures | 18 | B |
| 8 | `pandagod-001/SIH-xxxxx--…` | 294 pcaps + 293 per-session JSON, 5,482 flow windows, GroupKFold on 157 groups; the capture method is "Linux XFRM", handshake coverage unclear | none | partly verified | 16 | B |
| 9 | `tishanbrijesh-rgb/IPsec-Analyzer` | 44 small sample pcaps (one-host synthetic pilot) | none | namespaces + strongSwan, small | 14 | B |
| 10 | `Soham792/ipsec-vpn-analyzer` | 14 pcaps + `labels.csv` | none | strongSwan Docker | 13 | B |

Not scored: `POKEDB10/Janus` `labeled_flows.csv` (13 MB, MIT; mixes public Wireshark samples with generated
scenarios, sources not verified).

**Outside the IPsec family** (useful for method only): the WireGuard flow set by Razooqi and Pekar
(Zenodo 18700746, CC BY 4.0, 226,454 flows, 1.33 GB; labels come from deep-packet inspection of the inner
side of a paired capture) — a good model for getting ground truth by pairing both ends; an OpenVPN set
for a 2026 SBSEG paper (Kaggle, 94 GB raw captures, CC BY-SA 4.0); ISCXVPN2016 and mirrors (OpenVPN).

**Rejected, with reasons.** Kaggle "Internet Traffic Data Set" (ISP customer traffic with a payload
column, "Other" licence; the `ipsec-esp` it mentions is only a pasted list of possible protocol names,
not evidence the data contains ESP). Kaggle "Encrypted SDN Traffic Flow" and "VPN Traffic Dataset"
(10,000 and 50,000 *simulated* rows) and "Quantum Vulnerability Crypto Protocol" (synthetic text for
language-model training): training or testing on these would break the rule that evidence must be real.
HuggingFace `FYPDataset-IPSEC` (instruction-tuning text of Cisco router configs, no packets).
Zenodo's top 17 results for "ipsec": papers and posters, no captures (read via WebFetch, moderate
confidence). Kaggle search for `ikev2` returns nothing.

**Which would help us.** None should be *trained on*: that mixes labs and would hide the cross-lab
question. The valuable use is as an **external test set**, which is the thing our evaluation lacks: every
number we report comes from captures we generated ourselves. Dataset 1 fits best: its 25-file
out-of-distribution folder tests our UNKNOWN abstention, its 30 anomaly captures test mixed-traffic
detection, and its per-file cipher/DH/PFS labels test our parameter inference on another lab's generator.
Dataset 4 (`ashwin02`) adds handshake-per-config and full-factorial crypto; the PQ thesis set would fill
our thinnest area if its captures are usable. Their weaknesses are the ones the earlier survey noted for
dataset 1: each profile fixes cipher, IKE version, mode and encapsulation together, one application per
capture, endpoint vantage only.

## 5. Actions (none taken without your say-so)

- **A. Reword the "first dataset" claim.** `dataset/README.md` lines 4-5 and `build/sih/PITCH-DECK.md`
  line 65 say first dataset labelled with cryptographic configuration. Two datasets published
  2026-08-26/27 label cipher, DH group, PFS and mode per file, so the claim fails on date and content.
  What stays true and is checkable: one-factor-at-a-time arms, ground truth from the endpoint's own
  `swanctl`/`pluto` log rather than the capture, two implementations plus a locked cross-implementation
  test, and PQ downgrade arms. research/15 section 1 ("no public labelled IPsec/ESP traffic dataset")
  also needs a dated correction.
- **B. The GitHub "About" line still contains the ID.** The tracked files and commit messages are clean
  (0 matches on `origin/main`, 0 commit messages), but the repository description still starts with the ID,
  which is exactly how the first search found us. Fix is one command, shown in the chat.
- **C. Cross-lab test.** With your approval: download `pcaps/known` from `ipsec-pcap-lab` (175 files,
  989 MB; or a 25-file subset first), write a PREREG, run our traffic-type and cipher/DH inference on it,
  report the result whatever it is, and delete the captures afterward (they must not enter the repo).
  Needs a licence first: ask the authors (an outward message, so it needs your OK), because no licence
  means all rights reserved.
- **D. Pull the PQ thesis zips** only if you approve a download from Google Drive (size unknown).

## 6. Status update, 2026-10-02 (what became of section 5)

- **A, done.** The "first dataset" claim is reworded in `dataset/README.md` and the pitch deck; `research/15` carries a dated correction.
- **B, done.** The repository's About line no longer carries the problem-statement ID.
- **C, done, with a result that was not the one hoped for.** Both lab owners gave permission (relayed verbally). EXP-37: honesty held on
  another lab's data, the traffic-type model did not transfer. EXP-38: the gates are not the cause, the model underneath scores
  macro-F1 0.26 while our features can separate that lab's classes. EXP-39: the two public labs cannot settle whether training on
  one helps on the other, because lab B has no scorable window for three of its five classes (a flaw in that pre-registration,
  stated in its RESULT). Nothing was retrained or shipped.
- **D, done.** The ML-KEM thesis captures were re-fetched in part and used in EXP-37; a cut-short-file problem it exposed is fixed
  (DEC-050, T-150). A second gap it exposed, unreadable IKEv1 suites, is fixed and verified (DEC-051, EXP-40, T-151).
- **Still open, owner decision:** the shipped traffic model was trained partly on MIT Lincoln Laboratory's VNAT dataset (README,
  DEC-036). Its web page, re-read 2026-10-02, still states no licence and says to contact the Technology Transfer Office; our
  own survey (`research/15`, 2026-09-20) marked it "not used" for that reason. The shipped `tunnelscope/models/traffic_windows.npz`
  holds feature windows derived from it. Someone needs to ask MIT LL whether that use and that redistribution are allowed.
- **Not started:** lab C (our own lab with sustained traffic per class and new generators), the hash-chained evidence ledger
  idea, printing the random-versus-grouped split gap.

**Update 2026-10-02:** the VNAT question above is closed: the owner reports approval from MIT Lincoln Laboratory's Technology Transfer Office (DEC-052). Lab C was built (EXP-41).
