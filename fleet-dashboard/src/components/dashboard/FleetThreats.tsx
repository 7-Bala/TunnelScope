import { MatrixGrid } from "@/components/dashboard/ThreatMatrix"
import type { Gateway } from "@/lib/fleet"

/** Fleet threat matrix: how many tunnels have each threat, placed by likelihood x impact. */
export function FleetThreats({ gateways }: { gateways: Gateway[] }) {
  const sas = gateways.flatMap((g) => (g.detail?.risk ? [g.detail] : []))
  if (!sas.length) return null
  const cells: Record<string, string[]> = {}
  const byThreat: Record<string, { name: string; n: number }> = {}
  sas.forEach((sa) =>
    sa.risk.threats
      .filter((t) => t.status === "present")
      .forEach((t) => {
        ;(cells[`${t.likelihood}-${t.impact}`] ??= []).push(`${t.id} · ${sa.source}`)
        byThreat[t.id] = { name: t.name, n: (byThreat[t.id]?.n ?? 0) + 1 }
      }),
  )
  const top = Object.entries(byThreat).sort((a, b) => b[1].n - a[1].n).slice(0, 5)
  return (
    <div className="glass rounded-2xl">
      <div className="border-b border-border px-5 py-3.5">
        <h2 className="text-[14px] font-semibold tracking-tight">Threat matrix</h2>
        <p className="mt-0.5 text-[11.5px] text-faint">threats present across {sas.length} tunnel{sas.length === 1 ? "" : "s"}</p>
      </div>
      <div className="px-4 py-4">
        <MatrixGrid cells={cells} compact />
        <ul className="mt-4 space-y-1.5 text-[12px]">
          {top.map(([id, t]) => (
            <li key={id} className="flex items-baseline justify-between gap-3">
              <span className="text-muted-foreground"><span className="font-mono text-[10.5px] text-faint">{id}</span> {t.name}</span>
              <span className="font-mono text-foreground/85 tnum">{t.n}</span>
            </li>
          ))}
          {!top.length && <li className="text-faint">no threat present in what could be assessed</li>}
        </ul>
      </div>
    </div>
  )
}
