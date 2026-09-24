// Engine answers for the mocked browser tests. Every object is typed with the dashboard's own API
// types (src/lib/api.ts), and this file is part of `tsc -b` (tsconfig.e2e.json): if the API shapes
// change, the build fails here instead of the tests silently testing an old shape.
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import type {
  AnalyzeResult,
  GenerateResult,
  GeneratedPlan,
  RemediationApplyResult,
  RemediationCapabilities,
  RemediationPlan,
  RemediationPreview,
} from "../src/lib/api.ts"

const read = (name: string) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"))

/** real engine output for testbed/captures/exp15/s-modp1024.pcap (V-207193 and others FAIL) */
export const ANALYZE: AnalyzeResult = read("analyze-s-modp1024.json")
/** real plan_for("V-207193", detailed=True) */
export const PLAN: RemediationPlan = read("plan-V-207193.json")
export const CAPTURE = fileURLToPath(new URL("../../testbed/captures/exp15/s-modp1024.pcap", import.meta.url))

export const TARGETS = {
  ok: true,
  targets: [
    { name: "sih26-alice-pq", running: true },
    { name: "sih26-bob-pq", running: true },
  ],
  recommended: "sih26-alice-pq",
}

export const CAPS_ON: RemediationCapabilities = { local_model: true, generator_enabled: true }
export const CAPS_OFF: RemediationCapabilities = { local_model: true, generator_enabled: false }
export const CAPS_NO_MODEL: RemediationCapabilities = { local_model: false, generator_enabled: true }

const DIFF_HAND =
  "--- /tmp/exp15-alice.conf\n+++ /tmp/exp15-alice.conf (after)\n@@ -14,7 +14,7 @@\n         version = 2\n-        proposals = aes128-sha1-modp1024\n+        proposals = aes128-sha1-modp4096\n         children {\n"
const DIFF_DRAFT = DIFF_HAND.replace("modp4096", "ecp384")
const CLONE = {
  ok: true,
  reason: null,
  files: { "/tmp/exp15-alice.conf": { before: { loaded: 19, failed: 0 }, after: { loaded: 19, failed: 0 } } },
  rejected_keywords: [],
  seconds: 0.28,
}

export const PREVIEW_HAND: RemediationPreview = {
  ok: true,
  diff: { "/tmp/exp15-alice.conf": DIFF_HAND },
  peer: { container: "sih26-bob-pq", diff: { "/tmp/exp15-bob.conf": DIFF_HAND.replaceAll("alice", "bob") }, why: "both ends of a tunnel must agree on a proposal, so the other end gets the same change", clone_check: CLONE },
  clone_check: CLONE,
  digest: "a".repeat(64),
  source: "hand-written",
  plan_id: null,
}
export const PREVIEW_DRAFT: RemediationPreview = {
  ...PREVIEW_HAND,
  diff: { "/tmp/exp15-alice.conf": DIFF_DRAFT },
  peer: { ...PREVIEW_HAND.peer!, diff: { "/tmp/exp15-bob.conf": DIFF_DRAFT.replaceAll("alice", "bob") } },
  digest: "b".repeat(64),
  source: "generated",
  plan_id: "c".repeat(64),
}
export const PREVIEW_REFUSED: RemediationPreview = {
  ok: false,
  stage: "dry_run",
  error: "Dry run failed: the changed configuration does not load in a clone of sih26-alice-pq (strongSwan did not recognise: modp3076)",
}

export const APPLY_CONFIRMED: RemediationApplyResult = {
  ok: true,
  decision: "applied",
  rule_id: "V-207193",
  target: "sih26-alice-pq",
  commands_run: ["sed -i -E '...' /tmp/exp15-*.conf"],
  verdict_before: "FAIL",
  verdict_after: "PASS",
  confirmed_fixed: true,
  reason: "V-207193 now PASS on a fresh capture, tunnel negotiated, no rule newly failing",
  regressions: [],
  rolled_back: false,
  rollback_verified: null,
  service_restored: null,
  source: "hand-written",
}
export const APPLY_ROLLED_BACK: RemediationApplyResult = {
  ...APPLY_CONFIRMED,
  verdict_after: "FAIL",
  confirmed_fixed: false,
  reason: "V-207193 is still FAIL on a fresh capture",
  regressions: ["RFC8247-DH-MUST"],
  rolled_back: true,
  rollback_verified: true,
  service_restored: { tunnel_up: true, matches_baseline: true, worse_than_baseline: [] },
}
export const APPLY_STALE: RemediationApplyResult = {
  ok: false,
  decision: "refused",
  stage: "stale_preview",
  error: "the configuration (or the change) is not what you previewed; preview again before applying. Nothing was changed.",
}

const CHECK_NAMES: [string, string][] = [
  ["V1", "answer is one JSON object of the expected shape"],
  ["V2", "the line is allowed for this rule and exists in the lab connection"],
  ["V3", "each edit is allowed for that line and matches what is on it"],
  ["V4", "every new algorithm keyword is one the lab's strongSwan accepts, of the same kind"],
  ["V5", "the edits produce exactly the line the draft claims"],
  ["V7", "the change is not empty and repeats no keyword"],
  ["V6", "the rule itself passes on what TunnelScope observed for the new algorithms"],
  ["V8", "the compiled command passes the command allowlist"],
  ["DRY", "dry run on copies, and strongSwan loads the result in a clone (both ends)"],
  ["V5b", "the real dry-run line equals the predicted line"],
]
const ALL_PASSED = CHECK_NAMES.map(([id, name]) => ({ id, name, ok: true, reason: null }))
const RAW_GOOD =
  '{"line_key": "proposals", "edits": [{"op": "replace", "from": "modp1024", "to": "ecp384"}], "problem": "p", "why": "w", "expected_line_after": "proposals = aes128-sha1-ecp384"}'

const DRAFT_PLAN: GeneratedPlan = {
  ...PLAN,
  source: "generated",
  change: "proposals = aes128-sha1-ecp384 (in t-tun)",
  line_key: "proposals",
  new_value: "aes128-sha1-ecp384",
  diff: { "/tmp/exp15-alice.conf": DIFF_DRAFT },
  checks: ALL_PASSED,
  revisions: [{ round: 0, raw_output: RAW_GOOD, checks: ALL_PASSED }],
  raw_output: RAW_GOOD,
  model_id: "openbmb/MiniCPM5-2B-MLX",
  model_revision: "8a9ad7539ac86281d0ac2b017ba04a5de53fe9a3",
  self_review: { verdict: "no concerns", reason: "it replaces the weak group" },
  agrees_with_handwritten: false,
  handwritten_diff: { "/tmp/exp15-alice.conf": DIFF_HAND },
  latency_s: 3.1,
}

export const DRAFT_DIFFERS_CONCERN: GenerateResult = {
  ok: true,
  plan_id: "c".repeat(64),
  plan: { ...DRAFT_PLAN, self_review: { verdict: "concerns", reason: "ecp384 may not be offered by the peer" } },
}
export const DRAFT_AGREES: GenerateResult = {
  ok: true,
  plan_id: "d".repeat(64),
  plan: { ...DRAFT_PLAN, diff: { "/tmp/exp15-alice.conf": DIFF_HAND }, agrees_with_handwritten: true },
}
const RAW_BAD =
  '{"line_key": "proposals", "edits": [{"op": "replace", "from": "modp1024", "to": "modp3076"}], "problem": "p", "why": "w", "expected_line_after": "proposals = aes128-sha1-modp3076"}'
const FAILED_V4 = [
  ...ALL_PASSED.slice(0, 3),
  { id: "V4", name: CHECK_NAMES[3][1], ok: false, reason: "'modp3076' is not a keyword the lab's strongSwan accepts on a proposals line" },
]
export const DRAFT_REFUSED_V4: GenerateResult = {
  ok: false,
  stage: "V4",
  reason: "'modp3076' is not a keyword the lab's strongSwan accepts on a proposals line",
  checks: FAILED_V4,
  revisions: [
    { round: 0, raw_output: RAW_BAD, checks: FAILED_V4 },
    { round: 1, raw_output: RAW_BAD, checks: FAILED_V4 },
    { round: 2, raw_output: RAW_BAD + " ".repeat(10) + "x".repeat(3000), checks: FAILED_V4 },
  ],
}
