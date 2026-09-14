import { cn } from "@/lib/utils"

interface Readout {
  label: string
  value: number
  tone?: "violet" | "pos" | "warn" | "neg"
  foot: string
}

const TONE: Record<string, string> = {
  violet: "text-violet",
  pos: "text-pos",
  warn: "text-warn",
  neg: "text-neg",
}

export function KpiStrip({ readouts }: { readouts: Readout[] }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {readouts.map((r, i) => (
        <div
          key={r.label}
          className="rise min-w-0 rounded-2xl border border-border bg-card p-4"
          style={{ animationDelay: `${i * 55}ms` }}
        >
          <div className="truncate text-[12.5px] font-medium text-muted-foreground" title={r.label}>{r.label}</div>
          <div className={cn("mt-2.5 truncate text-[32px] font-semibold leading-none tracking-tight tnum", r.tone ? TONE[r.tone] : "text-foreground")}>
            {r.value}
          </div>
          <div className="mt-2 truncate text-[12px] text-muted-foreground" title={r.foot}>{r.foot}</div>
        </div>
      ))}
    </div>
  )
}
