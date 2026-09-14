import gatewaysData from "@/gateways.json"

export interface Finding {
  baseline: string
  rule_id: string
  severity: "high" | "medium" | "informational"
}

export interface Gateway {
  id: string
  city: string
  src: string
  dst: string
  posture: string
  fails: Finding[]
}

export const GATEWAYS: Gateway[] = gatewaysData as Gateway[]

export type PostureKind = "classical" | "downgraded" | "pq"

export function postureKind(posture: string): PostureKind {
  if (posture.includes("DOWNGRADED")) return "downgraded"
  if (posture.includes("post-quantum")) return "pq"
  return "classical"
}

export const POSTURE_META: Record<PostureKind, { label: string; color: string }> = {
  classical: { label: "Classical", color: "var(--steel)" },
  downgraded: { label: "Downgraded", color: "var(--neg)" },
  pq: { label: "Post-quantum", color: "var(--pos)" },
}

export function worstSeverity(fails: Finding[]): Finding["severity"] | null {
  if (fails.some((f) => f.severity === "high")) return "high"
  if (fails.some((f) => f.severity === "medium")) return "medium"
  if (fails.length) return "informational"
  return null
}

export function fleetStats(gateways: Gateway[]) {
  const counts: Record<PostureKind, number> = { classical: 0, downgraded: 0, pq: 0 }
  let high = 0, medium = 0, informational = 0, cve = 0
  gateways.forEach((g) => {
    counts[postureKind(g.posture)]++
    g.fails.forEach((f) => {
      if (f.severity === "high") high++
      else if (f.severity === "medium") medium++
      else informational++
      if (f.baseline === "CVE-WATCH") cve++
    })
  })
  // quantum-vulnerable = classical + silently-downgraded (both negotiated classical KE)
  const vulnerable = counts.classical + counts.downgraded
  return { counts, high, medium, informational, cve, vulnerable, total: gateways.length }
}
