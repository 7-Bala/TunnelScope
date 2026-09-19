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
}

export async function engineInfo(): Promise<EngineInfo | null> {
  try {
    const res = await fetch("/health", { cache: "no-store" })
    if (!res.ok) return null
    const b = await res.json()
    return b?.ok ? { ok: true, history: !!b.history } : null
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
