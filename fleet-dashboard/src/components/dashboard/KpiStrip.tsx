import { cn } from "@/lib/utils"

interface Readout {
  label: string
  value: number
  tone?: "teal" | "pos" | "neg" | "steel"
  foot: string
}

const TONE: Record<string, string> = {
  teal: "text-teal",
  pos: "text-pos",
  neg: "text-neg",
  steel: "text-steel",
}

export function KpiStrip({ readouts }: { readouts: Readout[] }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {readouts.map((r, i) => (
        <div
          key={r.label}
          className="rise rounded-lg border border-border bg-card p-4"
          style={{ animationDelay: `${i * 55}ms` }}
        >
          <div className="text-[12.5px] font-medium text-muted-foreground">{r.label}</div>
          <div className={cn("mt-2.5 text-[32px] font-semibold leading-none tracking-tight tnum", r.tone ? TONE[r.tone] : "text-foreground")}>
            {r.value}
          </div>
          <div className="mt-2 text-[12px] text-muted-foreground">{r.foot}</div>
        </div>
      ))}
    </div>
  )
}
