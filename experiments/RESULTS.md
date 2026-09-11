# Experimentation Phase — Consolidated Results (Round 1)

**Date:** 2026-09-10 · **Status:** 4 of 8 registered experiments complete (EXP-01, EXP-02, EXP-03,
EXP-04). EXP-05/06/07/08 remain — see `registers/EXPERIMENT-REGISTER.md`.

**Sequencing note (deviation from the original plan, as authorized):** the register's original
order was EXP-04 → EXP-01 → EXP-02 → others. EXP-04 required a from-source strongSwan build (ML-KEM
support is not in Debian's apt package); rather than block on that build, EXP-02 and EXP-01 were run
first on the already-working classical (apt-based) testbed while the PQ image built in the
background, then EXP-03, then EXP-04 once the PQ image was ready. All four completed in one session.
Recorded per the instruction to log sequencing deviations rather than follow the plan blindly.

---

## Result summary table

| # | Experiment | Hypothesis | Result | Confidence pre→post |
|---|---|---|---|---|
| EXP-02 | AES-128/256 negative control (integrity gate) | Near-chance discrimination | **PASS.** Exact ESP-length sets identical between key-length pairs; best-possible classifier ≤ chance | `[FACT]` confirmed |
| EXP-01 | ESP cipher-family sieve (F-04) | Narrows to ≤2 candidates | **PARTIAL.** Never eliminates the true family (0 false eliminations) but converges to a **5–6-member** ambiguity class, not ≤2 — falsification criterion in the register was met | `[STRONG]`→`[STRONG, weaker claim]` |
| EXP-03 | PFS length signature (A10) | CREATE_CHILD_SA size differs with/without PFS | **CONFIRMED**, cleanly, with a 256-byte gap, reproduced byte-for-byte across runs | `[HYP]`→`[FACT]` |
| EXP-04 | PQ key-exchange observability (PQ-6) | KE-payload length asymmetry distinguishes ML-KEM from DH | **CONFIRMED, and exceeded** — 4 independent deterministic signals found, the strongest of which (message presence) doesn't need the length-asymmetry mechanism at all | `[HYP]`→`[FACT]`, stronger than hypothesized |

---

## WHAT WORKED

- **EXP-02 (the critical gate) passed cleanly on the first rigorous run.** Exact ESP-content-length
  sets are byte-for-byte identical between AES-128 and AES-256 variants of both GCM and CBC+HMAC
  families; a majority-vote lookup classifier (the strongest classifier possible for a feature this
  coarse) scored *below* chance due to symmetric tie-breaking, not above it. No leakage found. This
  licenses trusting the rest of the pipeline's length-based measurements.
- **EXP-03 is a clean, strong, fully deterministic result.** A 256-byte gap between PFS-on and
  PFS-off `CREATE_CHILD_SA` messages, identical across two independent rekey events. No ML needed;
  a single length threshold suffices.
- **EXP-04 found MORE than it looked for.** The original hypothesis (KE-payload length asymmetry)
  is confirmed in principle, but three *stronger, simpler* signals were found in the process — see
  "What was surprising" below.
- **The full testbed pipeline works end-to-end**, including a genuine third-party passive vantage
  point (the `router` container has no IPsec config and captures only forwarded traffic — see
  `testbed/TOPOLOGY.md`), T2 ground truth pulled directly from `swanctl`/`ip xfrm state`, and a
  from-source strongSwan 6.0.2 build with native ML-KEM support.

## WHAT FAILED

- **EXP-01's strong form failed its own falsification criterion.** The register said: *"if candidate
  set fails to narrow below 4+ suites even at 1000 packets, F-04 is too weak to be a headline
  finding — demote to a supporting signal only."* It converged to 5–6 candidates at packet 1 (not
  1000 — see "surprising" below) and **stayed there** for all 132 packets across all seven tested
  configurations. By the register's own pre-registered bar, **this is a failure of the strong claim**
  and is reported as such, not reframed as a success.

## WHAT WAS INCONCLUSIVE

- EXP-04 Signal 4 (clean KE-payload length asymmetry) is confirmed *in principle* but the specific
  numeric comparison is complicated by IKE fragmentation on the initiator's message only (see
  below) — a clean per-packet asymmetry number needs fragment reassembly, which was not built this
  round. The *qualitative* result (fragmentation itself differs) stands; the *quantitative* one
  (exact byte asymmetry) is deferred.
- No generalization testing yet (EXP-07: Libreswan as a second implementation) — all four results
  above are strongSwan-only and must be labelled as such until that runs.

## WHAT WAS SURPRISING

1. **EXP-01's convergence speed vs. its convergence quality moved in opposite directions from what
   was hypothesized.** The register predicted convergence somewhere in "~50–200 packets." The real
   sieve converges **at packet 1** — it is a hard per-packet constraint, not a statistical pattern,
   so more packets add nothing. But the *asymptote it converges to* is worse than hoped: not ≤2
   candidates, but 5–6. Both directions of the surprise are recorded (see mathematical explanation
   below — this is not noise, it is a previously-undocumented structural property of the catalog).
2. **EXP-04 turned up three signals nobody had hypothesized**, layered by how early they appear on
   the wire:
   - The `INTERMEDIATE_EXCHANGE_SUPPORTED` notify (RFC 9242, type 16438) inside `IKE_SA_INIT` — the
     very first packet — differs between arms in this strongSwan build.
   - The `IKE_SA_INIT` SA payload itself grows by exactly 16 bytes when an ADDKE transform is
     proposed, before any key material is exchanged.
   - **The presence of any `IKE_INTERMEDIATE`-type message at all** is a clean, zero/non-zero signal
     requiring no length arithmetic whatsoever — it needs only the plaintext ISAKMP exchange-type
     field, which every surveyed tool including the "broken" dissector already renders correctly.
     This is a stronger, simpler result than the one originally proposed.
3. **ML-KEM-768's key size pushed the exchange over the IKEv2 fragmentation threshold**, something
   nobody anticipated when writing the PQ-6 hypothesis. This is itself informative: a passive
   observer could plausibly use "did this IKE_INTERMEDIATE exchange fragment?" as a corroborating,
   independent signal.

## WHAT ASSUMPTION WAS INVALIDATED

- **`research/07-DISCOVER-pq-and-late-findings.md`'s claim that strongSwan's PQ support requires
  "Botan 3.6+ or the oqs plugin (liboqs)."** False for strongSwan 6.0.2: ML-KEM ships as a native,
  dependency-free plugin (`ml`). A full liboqs build stage was written and successfully compiled
  before this was discovered by reading the actual `./configure --help` output; it was then removed
  as unnecessary. Corrected in `testbed/NOTES.md` #9, not silently fixed.
- **The implicit assumption in F-04's original statement (01-DISCOVER-domain.md) that alignment is
  an independent discriminating axis alongside IV/ICV length.** It is not, in general — see the
  mathematical note below. This changes F-04 from "the sieve narrows sharply" to "the sieve narrows
  sharply **only along the (IV, ICV) axis**; alignment differences are frequently absorbed."

## WHAT BECAME MORE LIKELY

- That the project's **strongest, most defensible single capability is PQ/downgrade observability**
  (EXP-04), not the ESP cipher-family sieve. EXP-04 produced a *stronger* result than hypothesized;
  EXP-01 produced a *weaker* one. The relative priority these two capabilities should get in
  DEVELOP/DELIVER should shift accordingly.
- That "evidence is at the exchange-type / notify-type level, not just packet-length level" is a
  generally underused signal class. Signal 1 and Signal 3 in EXP-04 did not require any length
  arithmetic — they are closer to the deterministic-parsing end of the AI Necessity Matrix than the
  statistical-inference end, reinforcing DEC-006's general direction (deterministic-first).

## WHAT BECAME LESS LIKELY

- That the ESP cipher-family sieve alone is sufficient to satisfy PS requirement R5 (identify
  encryption algorithm family) at T0/T1 with confidence. It still rules out CBC-mode suites when the
  true suite is AEAD/CTR/stream (asymmetric containment property, below) — a real, useful,
  one-directional result — but does not cleanly separate the AEAD/CTR/stream cluster from itself.
  09-DEFINE.md's disposition for R5 ("family-level sieve at T0/T1") should be annotated with this
  more precise, weaker claim rather than left as originally stated.

## WHAT SHOULD CHANGE

1. **09-DEFINE.md R5 disposition** needs an update: the sieve reliably answers *"is this CBC-mode
   or AEAD/stream-mode?"* (one bit, strongly), not *"which specific AEAD/stream suite?"* (weak,
   5–6-way ambiguous). This is still useful — CBC-mode detection alone flags legacy/weaker
   configurations — but the framing in the requirement disposition table overstated it.
2. **The AI Necessity Matrix entry for "ESP cipher-suite family (T0/T1)"** should note the revised,
   narrower claim.
3. **Concept seed CS-05 (PQ-readiness/downgrade observability) should be promoted** in DEVELOP's
   concept generation — it now has the strongest experimental backing of anything tested, is fully
   deterministic (AI Necessity Matrix: "no AI required" — confirmed, not just claimed), and ties
   directly to the DST National Quantum Mission policy alignment found in Discover.
4. **EXP-07 (Libreswan cross-implementation) should be prioritized next**, specifically to test
   whether EXP-04's Signal 1 (notify presence tracking configured intent, not just capability) is a
   strongSwan-specific behavior or a general RFC 9242 pattern — the current caveat in the EXP-04
   analysis code flags this as unverified across implementations.

---

## Mathematical note: why the EXP-01 sieve's asymptote is 5–6, not ≤2

For candidate suites A (params `iv_A, icv_A, align_A`) and B (`iv_B, icv_B, align_B`), if
`iv_A − iv_B` is a multiple of `align_B` and `align_A` is itself a multiple of `align_B`, then
**every** packet consistent with A is automatically consistent with B — B can never be eliminated by
evidence generated under A. This holds for `AES-CBC+HMAC-SHA256` (iv=16, icv=16, align=16) against
the whole `{AES-GCM-16, AES-CCM-16, AES-CTR+HMAC-SHA256, ChaCha20-Poly1305}` cluster (all iv=8,
icv=16, align=4): `16−8=8` is a multiple of 4, and 16 is a multiple of 4, so the containment is
total in that direction. The reverse is not true — AEAD/CTR/stream evidence *does* cleanly eliminate
CBC-mode hypotheses (verified: CBC suites never appeared in the candidate sets for GCM/CTR/ChaCha
captures). The sieve is a **one-directional filter on block-alignment strength**, not a general
cipher-family classifier. Full data: `experiments/exp01-cipher-sieve/results/exp01_results.json`.

---

## Raw results

- `experiments/exp01-cipher-sieve/results/exp01_results.json`
- `experiments/exp02-negative-control/results/exp02_results.json`
- `experiments/exp03-pfs-signature/results/exp03_results.json`
- `experiments/exp04-pq-length-asymmetry/results/exp04_results.json`
- Raw captures + T2 ground truth: `testbed/captures/*.pcap`, `*.groundtruth.json`

---

# Round 2 (2026-09-12) — every registered experiment now has a result

| # | Experiment | Result | Detail |
|---|---|---|---|
| EXP-04 (re-run) | PQ signals on strongSwan **6.1.0** | ✅ byte-for-byte identical to 6.0.2 | `exp04-pq-length-asymmetry/results/exp04_6.1.0_confirmation.md` |
| EXP-06 r2 | Failure-mode diagnosis | ✅ **all 6 pre-registered predictions held**; rules = decision tree (macro-F1 1.000, proposal/TS mismatch merged); **no ML needed** | `exp06-failure-diagnosis/RESULT_R2.md` |
| EXP-05 | Metadata leakage | ✅ **all 5 held**; TFC padding zeroes size leakage (+54% bytes) and **leaves class inference at F1 0.995**; ML justified *only* as a measuring instrument | `exp05-metadata-leakage/RESULT.md` |
| EXP-07 | Libreswan 5.4 generalisation | ✅ **7/7 held**; every "protocol fact" holds on a second implementation; notify + fragmentation are implementation-dependent | `exp07-libreswan-generalization/RESULT.md` |
| EXP-08 | Dataset leakage audit | **Applied inside every experiment rather than run separately:** session-level (leave-one-repetition-out) splits throughout, the EXP-02 negative control, and EXP-05's permutation null | — |
| EXP-09 | CVE-2026-78135 pattern detection | **Deferred** (T-022): needs a crafted CREATE_CHILD_SA before IKE_AUTH, which no stock implementation will send | `TODO.md` |

## Honest round-2 summary

**Worked:** 18 of 18 pre-registered predictions across EXP-05/06/07 held, and in two cases the data
matched protocol arithmetic written down beforehand (the 112-byte error-only response; the 256-byte
PFS gap on both implementations).

**Failed or weakened:** nothing against a pre-registration. But four **analysis bugs** were caught
before final numbers (EXP-05 size-MI keyed on direction; EXP-05 partial final window; EXP-07
address-keyed comparison; EXP-06 round 1's shared traffic selectors). Each is documented in the code
and the RESULT file, not quietly fixed.

**Surprising:** padding bought zero protection; mixtures produced confident wrong labels; a PQ
detector keyed on the notify would have false-positived on Libreswan; Docker's kernel silently
black-holes IP-TFS while strongSwan reports it installed.

**Invalidated:** "failure diagnosis needs ML", "PFS needs ML", and "vendor fingerprinting needs ML".
All three turned out to be exact structural signatures.

**Became more likely:** a deterministic evidence engine is the core, with exactly one justified ML
component (leakage measurement).

**Became less likely:** any claim that a tool can name the application inside an IPsec tunnel as a
fact.

**Still untested:** tunnel/transport mode inference (A7), constant-rate IP-TFS (kernel), vendor
stacks (Cisco/Palo Alto/Fortinet), real WAN conditions.
