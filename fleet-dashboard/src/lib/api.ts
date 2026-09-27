// Client for the local TunnelScope engine (`tunnelscope serve`, 127.0.0.1 only).
// Shapes mirror tunnelscope/api/server.py:analysis_json — one source of truth.

export type FindingStatus = "OBSERVED" | "MEASURED" | "INFERRED" | "UNKNOWN" | "NOT_OBSERVABLE" | "CONTRADICTORY"
export type VerdictResult = "PASS" | "FAIL" | "UNKNOWN" | "NOT_OBSERVABLE" | "CONTRADICTORY"

export interface VerdictRow {
  verdict: VerdictResult
  baseline: string
  authority: string
  rule_id: string
  title: string
  severity: "high" | "medium" | "low" | "informational"
  attribute: string
  observed: unknown
  message: string
}

export interface FindingRow {
  attribute: string
  /** plain name (handshake vs data cipher etc.), from tunnelscope/report/labels.py */
  label?: string
  confidence?: number | null
  status: FindingStatus
  value: unknown
  vantage: string
  method: string
  note: string
}

export interface ScoreRow {
  score: number | null
  coverage: number
  counts: { pass: number; fail: number; unknown: number; not_observable: number }
  note: string
}

export interface AnalyzedSA {
  id: string
  source: string
  src: string
  dst: string
  ike_spi: string
  posture: string
  fails: { baseline: string; rule_id: string; severity: "high" | "medium" | "informational"; title: string; message: string }[]
  verdicts: VerdictRow[]
  findings: FindingRow[]
  scores: Record<string, ScoreRow>
  score_stability: "stable" | "fragile"
  gaps: { attribute: string; status?: string; note?: string }[]
  /** per-tunnel anomaly result; null when the engine runs without --history */
  anomaly: AnomalyResult | null
  /** plain-English explanation, always built from the verdicts (template) */
  explanation: Explanation
  /** threat matrix, overall risk score and evidence confidence (tunnelscope/risk/risk.py) */
  risk: RiskResult
}

export interface Threat {
  id: string
  name: string
  impact: 1 | 2 | 3
  likelihood: 0 | 1 | 2 | 3
  impact_label: string
  likelihood_label: string
  description: string
  status: "present" | "not_seen" | "mitigated" | "not_assessable"
  evidence: string[]
  reason: string
  /** MITRE ATT&CK / CAPEC names for this threat (tunnelscope/risk/refs.py); never changes a score */
  refs?: { id: string; name: string; catalogue: "ATT&CK" | "CAPEC" }[]
}

export interface RiskResult {
  threats: Threat[]
  risk: {
    score: number
    band: "critical" | "high" | "medium" | "low" | "none observed"
    present: number
    assessable: number
    total: number
    coverage: number
    top: { id: string; name: string; likelihood: number; impact: number }[]
    note: string
  }
  confidence: { score: number; observed: number; inferred: number; not_visible: number; attributes: number; note: string }
  /** real risks no capture can decide, with where they can be checked (T-122 / DEC-039) */
  out_of_scope?: { name: string; why: string; check_with: string }[]
}

export interface LiveWindow {
  file: string
  at: number
  ok: boolean
  error?: string
  n_sas?: number
  seconds?: number
  sas?: AnalyzedSA[]
}

export interface LiveStatus {
  ok: boolean
  enabled: boolean
  source?: string
  window_s?: number
  started?: number
  last_at?: number | null
  windows?: LiveWindow[]
  errors?: LiveWindow[]
  capturing?: boolean | null
}

export async function liveStatus(): Promise<LiveStatus | null> {
  try {
    const res = await fetch("/api/live", { cache: "no-store" })
    if (!res.ok) return null
    return (await res.json()) as LiveStatus
  } catch {
    return null
  }
}

export interface SiteTunnel {
  src: string
  dst: string
  posture: string
  fails: string[]
  risk?: string | null
  last_handshake?: { posture: string; observed_at?: number | null; age_s: number; fails: string[] } | null
}

export interface SiteAlert {
  kind: string
  attribute: string
  usual?: unknown
  now?: unknown
  tunnel: string
  received: number
  age_s: number
}

export interface SiteStatus {
  site: string
  status: "reporting" | "stale"
  last_seen?: number
  age_s: number
  window_s?: number
  reports?: number
  missing_reports: number
  last_window_ok?: boolean | null
  tunnels: SiteTunnel[]
  recent_alerts?: SiteAlert[]
  note?: string | null
}

export interface SitesResult {
  ok: boolean
  enabled: boolean
  stale_after_windows?: number
  sites?: SiteStatus[]
}

export async function sitesStatus(): Promise<SitesResult | null> {
  try {
    const res = await fetch("/api/sites", { cache: "no-store" })
    if (!res.ok) return null
    return (await res.json()) as SitesResult
  } catch {
    return null
  }
}

export interface Anomaly {
  layer: "posture" | "traffic" | "model"
  kind: "downgrade" | "upgrade" | "change" | "new_failure" | "shift" | "outlier" | "fleet_outlier"
  severity: "high" | "medium" | "informational"
  attribute: string
  usual: unknown
  now: unknown
  message: string
}

export interface AnomalyResult {
  tunnel: string
  status: "learning" | "normal" | "anomalous"
  observations: number
  needed?: number
  anomalies: Anomaly[]
  layers?: string[]
}

export interface Explanation {
  summary: string
  points: { kind: "fail" | "ok" | "exposure" | "anomaly"; text: string; rule_id?: string; severity?: string }[]
  unseen: string[]
  source: string
}

export interface EngineInfo {
  ok: boolean
  history: boolean
  live: boolean
}

export async function engineInfo(): Promise<EngineInfo | null> {
  try {
    const res = await fetch("/health", { cache: "no-store" })
    if (!res.ok) return null
    const b = await res.json()
    return b?.ok ? { ok: true, history: !!b.history, live: !!b.live } : null
  } catch {
    return null
  }
}


export type AnalyzeResult =
  | { ok: true; filename: string; n_sas: number; sas: AnalyzedSA[] }
  | { ok: false; filename?: string; error: string }

export const ENGINE_OFFLINE =
  "Can't reach the TunnelScope engine. Start it with `tunnelscope serve`, then try again."

export async function analyzeCapture(file: File): Promise<AnalyzeResult> {
  let res: Response
  try {
    res = await fetch(`/api/analyze?name=${encodeURIComponent(file.name)}`, { method: "POST", body: file })
  } catch {
    return { ok: false, filename: file.name, error: ENGINE_OFFLINE }
  }
  try {
    return (await res.json()) as AnalyzeResult
  } catch {
    return { ok: false, filename: file.name, error: ENGINE_OFFLINE }
  }
}

export async function engineHealth(): Promise<boolean> {
  try {
    const res = await fetch("/health", { cache: "no-store" })
    if (!res.ok) return false
    const body = await res.json()
    return body?.ok === true
  } catch {
    return false
  }
}

export function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—"
  if (Array.isArray(v)) return v.map(formatValue).join(", ")
  if (typeof v === "object") {
    return Object.entries(v as Record<string, unknown>)
      .map(([k, x]) => `${k} ${formatValue(x)}`)
      .join(" · ")
  }
  return String(v)
}

export type RemediationPlan = {
  rule_id: string
  change: string
  commands: string[]
  auto_applicable: boolean
  observed: unknown
  problem_analysis?: string
  cryptographic_risk?: string
  proposed_strategy?: string
  config_diff?: string
  rollback_strategy?: string
  is_software_patch?: boolean
  runbook?: string[]
  /** config_diff is a hand-written illustration, not read from any configuration */
  config_diff_is_example?: boolean
  /** false when the rule has no safe automated fix yet (a manual change is needed) */
  automated_fix_available?: boolean
}

export async function remediationPlan(
  ruleId: string,
  observed?: unknown,
  detailed: boolean = true,
): Promise<RemediationPlan | null> {
  try {
    const res = await fetch("/api/remediate/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: ruleId, observed: observed ?? null, detailed }),
    })
    if (!res.ok) return null
    return (await res.json()) as RemediationPlan
  } catch {
    return null
  }
}

export type RemediationApplyResult = {
  ok: boolean
  /** "unknown": the engine's answer was lost or unreadable, or it failed unexpectedly: the lab may
   * or may not have been changed (the in-container watchdog restores an unconfirmed change). */
  decision?: "applied" | "refused" | "failed" | "unknown"
  stage?: string
  error?: string
  rule_id?: string
  target?: string
  token?: string
  commands_run?: string[]
  /** measured on a baseline capture taken just before the change */
  verdict_before?: string
  verdict_after?: string
  confirmed_fixed?: boolean
  reason?: string
  /** rules that were not failing before the change and are failing after it */
  regressions?: string[]
  rolled_back?: boolean
  /** restored files compared byte for byte with the originals; null when nothing was rolled back */
  rollback_verified?: boolean | null
  /** after a rollback: tunnel re-negotiated on the restored settings, and no rule worse than the baseline */
  service_restored?: { tunnel_up: boolean; matches_baseline: boolean; worse_than_baseline?: string[]; detail?: string } | null
  dry_run_diff?: Record<string, string>
  clone_check?: CloneCheck | null
  peer?: { container: string; commands_run: string[]; dry_run_diff: Record<string, string>; clone_check?: CloneCheck | null } | null
  watchdog_timeout_s?: number
  source?: "hand-written" | "generated"
  plan_id?: string | null
  /** after a confirmed fix the tunnel is forced to rekey (T-107); null when no rekey was tried */
  rekey?: {
    passive: "NOT_OBSERVABLE"
    note: string
    tunnel_after_rekey: boolean | null
    rekeyed: boolean | null
    endpoint_reported: { algorithms: string[]; rule_verdict: "PASS" | "FAIL" | "UNKNOWN" } | null
    error?: string
  } | null
}

export type CloneCheck = {
  ok: boolean
  reason?: string | null
  files?: Record<string, { before: { loaded: number; failed: number }; after: { loaded: number; failed: number } }>
  rejected_keywords?: string[]
  seconds?: number
  note?: string
}

export type RemediationPreview = {
  ok: boolean
  stage?: string
  error?: string
  /** real unified diff per config file, from a dry run on copies inside the container */
  diff?: Record<string, string>
  peer?: { container: string; diff: Record<string, string>; why: string; clone_check?: CloneCheck | null } | null
  /** strongSwan loaded the changed config in a throwaway, network-less clone (T-100) */
  clone_check?: CloneCheck | null
  /** what was previewed; Apply must send it back, and is refused if the dry run now differs (T-104) */
  digest?: string
  source?: "hand-written" | "generated"
  plan_id?: string | null
  /** DEC-044: present only for a real gateway. Apply needs `ack_phrase` typed back exactly. */
  live?: {
    gateway: string
    host: string
    connection: string
    peer: string | null
    risks: string[]
    ack_phrase: string
    watchdog_timeout_s: number
  }
}

export type RemediationCapabilities = {
  /** the pinned local model can run on this machine (Apple Silicon, model on disk) */
  local_model: boolean
  /** DEC-038: the optional cloud drafting backend has an API key and its package is installed */
  cloud_model: boolean
  /** which backend the operator has selected (server-side setting only, never client-chosen) */
  backend: "local" | "cloud"
  /** local-model drafts are switched on (off until EXP-18 passes, DEC-034) */
  generator_enabled: boolean
}

const NO_CAPS: RemediationCapabilities = { local_model: false, cloud_model: false, backend: "local", generator_enabled: false }

export async function remediationCapabilities(): Promise<RemediationCapabilities> {
  try {
    const res = await fetch("/api/remediate/capabilities", { cache: "no-store" })
    if (!res.ok) return NO_CAPS
    const b = await res.json()
    return {
      local_model: b?.local_model === true,
      cloud_model: b?.cloud_model === true,
      backend: b?.backend === "cloud" ? "cloud" : "local",
      generator_enabled: b?.generator_enabled === true,
    }
  } catch {
    return NO_CAPS
  }
}

export type DraftCheck = { id: string; name: string; ok: boolean; reason: string | null }

export type GeneratedPlan = RemediationPlan & {
  source: "generated"
  line_key: string
  new_value: string
  diff: Record<string, string>
  checks: DraftCheck[]
  revisions: { round: number; raw_output: string; checks: DraftCheck[] }[]
  raw_output: string
  model_id: string
  model_revision: string
  /** DEC-038: which backend actually produced this draft (may differ from the operator's current
   * setting if it was rechecked later) */
  backend?: "local" | "cloud"
  self_review: { verdict: "no concerns" | "concerns" | "unavailable"; reason: string | null } | null
  agrees_with_handwritten?: boolean
  handwritten_diff?: Record<string, string> | null
  latency_s: number
}

export type GenerateResult =
  | { ok: true; plan_id: string; plan: GeneratedPlan }
  | { ok: false; stage?: string; reason?: string; error?: string; checks?: DraftCheck[]; revisions?: GeneratedPlan["revisions"] }

export async function generateRemediation(ruleId: string, target: string, observed?: unknown): Promise<GenerateResult> {
  try {
    const res = await fetch("/api/remediate/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: ruleId, target, observed: observed ?? null }),
    })
    return (await res.json()) as GenerateResult
  } catch (e) {
    return { ok: false, error: String(e) }
  }
}

export type LabTarget = {
  name: string
  running: boolean
  /** DEC-044: a real gateway reached over SSH, not a lab container */
  live?: boolean
  host?: string
  connection?: string
  /** the terms and risks are accepted for this gateway (and still valid) */
  accepted?: boolean
  accept_phrase?: string
  consent_reason?: string | null
}

type GatewayRow = {
  name: string
  host: string
  connection: string
  accepted: boolean
  accept_phrase: string
  consent: { accepted: boolean; reason: string | null }
}

export async function remediationTargets(): Promise<{ targets: LabTarget[]; recommended: string } | null> {
  try {
    const res = await fetch("/api/remediate/targets", { cache: "no-store" })
    if (!res.ok) return null
    const b = (await res.json()) as { targets: LabTarget[]; recommended: string; gateways?: GatewayRow[] }
    const gws: LabTarget[] = (b.gateways ?? []).map((g) => ({
      name: g.name,
      running: true,
      live: true,
      host: g.host,
      connection: g.connection,
      accepted: g.accepted,
      accept_phrase: g.accept_phrase,
      consent_reason: g.consent?.reason ?? null,
    }))
    return { targets: [...b.targets, ...gws], recommended: b.recommended }
  } catch {
    return null
  }
}

export type GatewayTerms = { version: string; title: string; clauses: string[]; sha256: string }

export async function gatewayTerms(): Promise<GatewayTerms | null> {
  try {
    const res = await fetch("/api/remediate/terms", { cache: "no-store" })
    if (!res.ok) return null
    return (await res.json()) as GatewayTerms
  } catch {
    return null
  }
}

export async function acceptGatewayTerms(
  target: string,
  typed: string,
  acceptedBy: string,
  termsSha256: string,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch("/api/remediate/terms/accept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, typed, accepted_by: acceptedBy, terms_sha256: termsSha256 }),
    })
    return (await res.json()) as { ok: boolean; error?: string }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
}

export async function previewRemediation(ruleId: string, target: string, planId?: string | null): Promise<RemediationPreview> {
  try {
    const res = await fetch("/api/remediate/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: ruleId, target, plan_id: planId ?? null }),
    })
    return (await res.json()) as RemediationPreview
  } catch (e) {
    return { ok: false, error: String(e) }
  }
}

export async function applyRemediation(
  ruleId: string,
  target: string,
  confirm: boolean = true,
  opts: { digest?: string; planId?: string | null; riskAck?: string | null } = {},
): Promise<RemediationApplyResult> {
  let res: Response
  try {
    res = await fetch("/api/remediate/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rule_id: ruleId,
        target,
        confirm,
        digest: opts.digest ?? null,
        plan_id: opts.planId ?? null,
        risk_ack: opts.riskAck ?? null,
      }),
    })
  } catch (e) {
    // The request may already have reached the engine and changed the lab before the connection
    // failed; the browser cannot tell. Never report this as "nothing was changed".
    return { ok: false, decision: "unknown", error: `the connection to the engine was lost (${String(e)})` }
  }
  try {
    return (await res.json()) as RemediationApplyResult
  } catch {
    return { ok: false, decision: "unknown", error: `the engine's reply could not be read (HTTP ${res.status})` }
  }
}



// ---- T-130 part 2: known vulnerabilities for a fingerprinted implementation (tunnelscope/intel/lookup.py)
export interface IntelCve {
  id: string
  description: string | null
  published: string | null
  cvss: number | string | null
  severity: string | null
  kev: boolean
  kev_added?: string
  kev_due?: string
  ransomware?: string
  epss: string | null
  sources: string[]
  /** cpe: NVD lists the product as vulnerable; vendor: EUVD/CISA list it under the vendor; keyword: only mentioned */
  match: "cpe" | "vendor" | "keyword"
  ipsec_related: boolean
}

export interface IntelResult {
  ok: boolean
  error?: string
  implementation: string
  status?: string
  cves: IntelCve[]
  sources: Record<string, { status: string; fetched_at: number | null; reason: string | null }>
  counts?: { total: number; kev: number; product_listed: number; ipsec_related: number }
  note?: string
}

export async function intelLookup(implementation: string): Promise<IntelResult | null> {
  try {
    const res = await fetch(`/api/intel?implementation=${encodeURIComponent(implementation)}`, { cache: "no-store" })
    return (await res.json()) as IntelResult
  } catch {
    return null
  }
}
