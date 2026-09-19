import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { type EngineInfo, engineInfo } from "@/lib/api"
import type { Gateway } from "@/lib/fleet"

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-2.5 text-[12.5px]">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  )
}

/** Fleet-level summary of the three AI features, for uploaded captures. */
export function Insights({ gateways }: { gateways: Gateway[] }) {
  const [info, setInfo] = useState<EngineInfo | null>(null)
  useEffect(() => {
    engineInfo().then(setInfo)
  }, [])
  const sas = gateways.flatMap((g) => (g.detail ? [g.detail] : []))
  if (!sas.length) return null

  const anom = { anomalous: 0, learning: 0, normal: 0 }
  sas.forEach((s) => s.anomaly && anom[s.anomaly.status]++)
  const exp = { high: 0, medium: 0, low: 0, none: 0 }
  sas.forEach((s) => {
    const f = s.findings.find((x) => x.attribute === "attacker_exposure")
    const lvl = f?.status === "MEASURED" ? (f.value as { level: "high" | "medium" | "low" }).level : "none"
    exp[lvl]++
  })

  const n = (v: number, cls: string, t: string) =>
    v > 0 && (
      <span className={cn("ml-2 whitespace-nowrap", cls)}>
        <span className="font-mono tnum">{v}</span> {t}
      </span>
    )

  return (
    <div className="glass rounded-2xl">
      <div className="border-b border-border px-5 py-3.5">
        <h2 className="text-[14px] font-semibold tracking-tight">AI insights</h2>
      </div>
      <div className="divide-y divide-border/60 px-5 py-1">
        <Row label="Changes from normal">
          {info && !info.history ? (
            <span className="text-faint">off</span>
          ) : (
            <>
              {n(anom.anomalous, "text-neg", "changed")}
              {n(anom.normal, "text-pos", "normal")}
              {n(anom.learning, "text-faint", "learning")}
            </>
          )}
        </Row>
        <Row label="Attacker exposure">
          {n(exp.high, "text-neg", "high")}
          {n(exp.medium, "text-warn", "med")}
          {n(exp.low, "text-pos", "low")}
          {n(exp.none, "text-faint", "not measurable")}
        </Row>
        <Row label="Explanations">
          <span className="text-faint">{!info || info.llm === "none" ? "from the verdicts" : `+ ${info.llm} rewrite`}</span>
        </Row>
      </div>
      <p className="px-5 pb-3.5 text-[11.5px] leading-relaxed text-faint">Open a tunnel for the explanation, attacker view and changes.</p>
    </div>
  )
}
