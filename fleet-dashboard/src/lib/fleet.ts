import gatewaysData from "@/gateways.json"
import type { AnalyzedSA } from "@/lib/api"

export interface Finding {
  baseline: string
  rule_id: string
  severity: "high" | "medium" | "informational"
  title?: string
  message?: string
}

export interface Gateway {
  id: string
  /** Display name: the gateway label for the sample fleet, the file name for uploads. */
  city: string
  src: string
  dst: string
  posture: string
  fails: Finding[]
  origin: "sample" | "upload"
  /** Full evidence for an uploaded capture; the sample fleet carries verdicts only. */
  detail?: AnalyzedSA
}

export const GATEWAYS: Gateway[] = (gatewaysData as Omit<Gateway, "origin">[]).map((g) => ({ ...g, origin: "sample" }))

export function toGateway(sa: AnalyzedSA, index: number, total: number): Gateway {
  return {
    id: sa.id,
    city: total > 1 ? `${sa.source} · SA ${index + 1}` : sa.source,
    src: sa.src,
    dst: sa.dst,
    posture: sa.posture,
    fails: sa.fails,
    origin: "upload",
    detail: sa,
  }
}

export type PostureKind = "classical" | "downgraded" | "pq" | "unknown"

/** Only what the engine actually established: a posture it could not tell (ESP-only capture, or a
 * handshake that was not in the capture) is "unknown", never counted as classical (DEC-008). */
export function postureKind(posture: string): PostureKind {
  if (posture.includes("DOWNGRADED")) return "downgraded"
  if (posture.startsWith("post-quantum")) return "pq"
  if (posture.startsWith("classical")) return "classical"
  return "unknown"
}

export const POSTURE_META: Record<PostureKind, { label: string; color: string }> = {
  classical: { label: "Classical", color: "var(--warn)" },
  downgraded: { label: "PQ not selected", color: "var(--neg)" },
  pq: { label: "Post-quantum", color: "var(--pos)" },
  unknown: { label: "Not seen", color: "var(--chart-5)" },
}

export function worstSeverity(fails: Finding[]): Finding["severity"] | null {
  if (fails.some((f) => f.severity === "high")) return "high"
  if (fails.some((f) => f.severity === "medium")) return "medium"
  if (fails.length) return "informational"
  return null
}

export function fleetStats(gateways: Gateway[]) {
  const counts: Record<PostureKind, number> = { classical: 0, downgraded: 0, pq: 0, unknown: 0 }
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
  // quantum-vulnerable = classical + PQ-offered-but-classical-selected (both negotiated classical KE)
  const vulnerable = counts.classical + counts.downgraded
  return { counts, high, medium, informational, cve, vulnerable, total: gateways.length }
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many)

/** The headline, computed from the data shown — never hard-coded to one dataset. */
export function headline(s: ReturnType<typeof fleetStats>): { title: string; detail: string } {
  const { total, vulnerable, counts, cve } = s
  const seen = total - counts.unknown
  const title =
    seen === 0
      ? `The key exchange of ${plural(total, "this tunnel", `these ${total} tunnels`)} is not in the capture.`
      : vulnerable === 0
        ? counts.pq === total
          ? total === 1
            ? "This tunnel negotiates hybrid post-quantum key exchange."
            : `All ${total} tunnels negotiate hybrid post-quantum key exchange.`
          : seen === 1
            ? "The one tunnel whose key exchange was seen negotiates hybrid post-quantum."
            : `All ${seen} tunnels whose key exchange was seen negotiate hybrid post-quantum.`
        : `${vulnerable} of ${total} ${plural(total, "tunnel", "tunnels")} still ${plural(vulnerable, "negotiates", "negotiate")} classical key exchange.`
  const parts: string[] = []
  if (counts.downgraded)
    parts.push(`${counts.downgraded} offered post-quantum but negotiated classical`)
  if (cve) parts.push(`${cve} ${plural(cve, "carries", "carry")} the CVE-2026-78135 pre-auth pattern`)
  parts.push(
    counts.pq
      ? `${counts.pq} ${plural(counts.pq, "is", "are")} hardened with hybrid ML-KEM`
      : "none are hardened with hybrid ML-KEM",
  )
  if (counts.unknown)
    parts.push(`for ${counts.unknown} the key exchange is not in the capture, so ${plural(counts.unknown, "its", "their")} posture is not known`)
  const detail = parts.join("; ")
  return { title, detail: detail.charAt(0).toUpperCase() + detail.slice(1) + "." }
}
