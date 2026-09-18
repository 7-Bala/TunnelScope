# TunnelScope — Usage & Operations Plan (T-049)

**Date:** 2026-09-14 · **Status:** PLAN, being executed against immediately (see §5) · Grounded in
`research/03-DISCOVER-stakeholders.md`'s 4 roles, `build/00-ARCHITECTURE.md`'s invariants (I9:
offline by default), and an audit of what actually ships today vs. what real use requires.

This is not a redesign. TunnelScope's evidence engine, baselines and score are done and validated
(T-030–T-048). What's missing is the layer between "a correct pipeline exists" and "a named user can
actually run this day to day" — that's what this document plans, and what §5 starts building now.

---

## 1. Who actually uses this, and how (per role, concretely)

Reusing the 4 roles `research/03` already identified by **access level**, not job title — because
access decides what's even askable, and TunnelScope's vantage tiers (T0–T4) are built around exactly
that split.

| Role | What they actually do, day to day | Vantage | TunnelScope surface |
|---|---|---|---|
| **B — Auditor / compliance assessor** | Given a batch of capture files (or read-only config exports) from an estate they don't operate; must produce a dated compliance report citing DISA/NIST/RFC/DST, across possibly dozens of tunnels | T1, sometimes T3/T5 | **Fleet mode** (new, §5): point at a directory, get one aggregated report + CBOM across every tunnel, each verdict still citing its own baseline |
| **D — SOC analyst / incident responder** | Watching a live tap or a rolling capture buffer; needs "is this ESP flow authorized, has its posture changed" fast, not a report they read later | T0, sometimes T1 | `tunnelscope analyze --json` piped into their own SIEM/alerting; the **local-only API** (planned, §6) is for this role specifically — not for a public network |
| **A — Network/VPN engineer** | Owns both endpoints; wants "why is this tunnel down" fast, then confirmation the fix worked | T2–T4 | `tunnelscope analyze` + `crosstier` (T2 telemetry cross-check, already built) — this role is already the best served today |
| **C — Pentester / red team** | External only, authorized target list; wants exposure/weakness findings from outside | T0, T5 (active probe — out of scope, DEC-005) | `tunnelscope analyze`/`assess` on their own capture — no change needed; V5 active probing stays explicitly out of scope per the research phase's own decision |

**The gap that matters most:** role B (auditor) and role D (SOC analyst) are the two roles
`research/03`'s own Finding S-01 named as under-served by every other tool, and they are also the two
roles for whom "run it once on one pcap and read the HTML" (today's actual UX) does not match how
they work. B needs **many tunnels, one report**. D needs **machine-readable output on a stream**,
not a report to open later. Both are addressed below.

---

## 2. Deployment model (per I9: offline by default, no cloud dependency)

- **Default and only supported mode: local CLI, air-gapped-capable.** A single `pip install
  tunnelscope`, or the offline bundle for NTRO's context (`build/offline/make_bundle.sh`), plus
  `tshark` on PATH. No network calls: **tested, not just read** (2026-09-18) — installed from the
  bundle in a `--network none` container, `doctor`/`assess`/`serve`/upload all run under
  `strace -f -e connect`, zero attempts beyond loopback (`build/offline/AIRGAP-TEST.md`,
  `build/05-DEPLOYMENT-ONPREM.md`).
- **Fleet mode is still local** — a directory of pcaps in, one aggregated HTML/JSON out. No new
  network surface.
- **`tunnelscope serve` (T-059, built) is a local upload dashboard, not the §6 API below.** It is a
  human-facing page for the same one-shot, offline analysis every other command does — no persistent
  role, no streaming, no polling. Explicitly narrow, since this is the one command that opens a
  socket at all: binds to `127.0.0.1` only (not a flag — can't be pointed at a LAN or `0.0.0.0`),
  every upload is checked against pcap/pcapng magic bytes before it reaches `tshark`, uploads are
  written to a private temp path and deleted right after the response (nothing persists), and a
  parse failure on one file is its own error card, never a crash of the server. Stdlib `http.server`
  only — no new dependency, and the fastapi/uvicorn removal (T-049) stands.
  Since T-060 it serves the React dashboard (`fleet-dashboard/dist`) at `/`, which uploads to a
  structured `POST /api/analyze`; static files are served only from inside that build directory
  (resolved-path check, tested against `..` and encoded traversal).
- **The local-only API (§6) is a separate, still-open item** — opt-in, off by default, binds to
  localhost only. It exists for role D's integration need (a SIEM polling TunnelScope on a schedule),
  which `serve` does not address. Shipping it still needs its own security review before it's turned
  on by default anywhere — not assumed safe just because `serve` already exists.

---

## 3. How we manage and build it going forward

### 3.1 Team ownership (real, from the actual team roster — `build/sih/PITCH-DECK.md`)

| Area | Owner | Why (matches their existing contribution) |
|---|---|---|
| Core pipeline & assessment engine, releases | Balachandran R | Already owns pipeline/assessment-engine architecture |
| Testbed, experiments, CI | Ajay R | Already owns Docker testbed + EXP-01..12 design/execution |
| Compliance baselines, CVE detector, fleet mode | Akilan M | Already owns rule baselines + the CVE detector this session found a real bug in |
| Dataset, documentation, this plan's usage docs | Agalya R | Already owns dataset curation/validation/docs |
| Leakage/ML module, local API (if built) | Jayavanadhi V | Already owns the one ML component |
| Coordination, external comms, SIH submission | Kishore K | Team lead |

### 3.2 CI (built now, §5) — the concrete lesson from this session

Three real bugs (EXP-10's failure-diagnosis misdiagnosis, EXP-10's TFC false-positive, EXP-12's CVE
false-positive) were found by **manually** stress-testing against real, unusual traffic — not by the
existing 48-test suite or the 69-capture e2e check, which all passed the whole time. That is a
finding about the *test corpus's coverage*, not about test rigor: automated CI cannot invent a new
OpenBSD VM or a responder-initiated rekey by itself. What CI *does* buy: every one of those bugs,
once found and fixed, is now a permanent regression test — CI's job is making sure the **next**
regression of any of those three specific bugs is caught in seconds, not in a future manual stress
test. That is the honest scope of what's being added, not a claim that CI would have found them
first.

### 3.3 Versioning and releases

- `pyproject.toml` bumps on every merged change to `tunnelscope/`; `CHANGELOG.md` (new, §5) records
  what changed, referencing the EXP/T-ID that drove it — the project already has this discipline in
  `TODO.md`, this just makes it visible to someone who isn't reading the task tracker.
- Rule baselines (`tunnelscope/rules/*.yaml`, shipped inside the package) are already versioned data (DEC-011) — new baselines or amendments
  ship as a new file or a dated header change, never a silent edit to existing verdicts' meaning.

### 3.4 What is explicitly NOT being built, and why

- **No cloud/SaaS mode.** Contradicts I9 and the NTRO deployment context outright.
- **No public-network API.** The local-only API (§6) is the ceiling; anything beyond that is a new
  threat model this plan does not cover.
- **No GUI beyond the existing dashboard.** The dashboard already serves the "look at one tunnel's
  posture" job; fleet mode (§5) extends it to "look at many," which covers roles A/B/D's actual asks
  without a new UI framework.

---

## 4. Fleet mode — the design (built in §5)

- `tunnelscope fleet <directory> [-o report.html]`: runs `analyze` + `assess` + `score` over every
  `*.pcap`/`*.pcapng` under the directory, keeping every existing per-SA guarantee (status, vantage,
  evidence, cited baseline) intact per tunnel.
- Output: one dashboard showing **every tunnel as its own row/card** (never averaged into a single
  number — a fleet-wide "87/100" would repeat exactly the mistake DEC-007 already rejected at the
  single-tunnel level) plus a **fleet-level rollup**: how many tunnels FAIL each baseline, by rule —
  the thing an auditor actually reports upward.
- A tunnel that fails to parse (corrupt pcap, no IKE at all) is reported as its own row with the
  error, never silently dropped — a fleet scan that quietly skips bad files is a worse failure mode
  than a slow one.

---

## 5. Executing now

1. `tunnelscope fleet` command + fleet dashboard (role B/D's actual workflow) — **built in this
   session, see commit**.
2. GitHub Actions CI (pytest + e2e + dataset validate on every push) — **built in this session**.
3. `CHANGELOG.md` — **started in this session**.
4. Local-only API — **planned above, not built this session**: needs its own short security review
   (input validation, no unintended network exposure) before implementation, which is a distinct,
   scoped follow-up rather than something to rush alongside a broad planning pass.
