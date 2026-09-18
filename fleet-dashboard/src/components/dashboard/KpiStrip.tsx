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
  neg: "text-neg",
  warn: "text-warn",
}

// One instrument bar with hairline dividers, not a row of identical cards.
export function KpiStrip({ readouts }: { readouts: Readout[] }) {
  return (
    <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-border bg-border sm:grid-cols-6 lg:grid-cols-5">
      {readouts.map((r, i) => (
        <div
          key={r.label}
          className={cn(
            "min-w-0 bg-card px-5 py-4",
            // mobile 2+2+1, tablet 3+2, desktop 5 across: the last row always fills
            i < 3 ? "sm:col-span-2 lg:col-span-1" : "sm:col-span-3 lg:col-span-1",
            i === readouts.length - 1 && readouts.length % 2 === 1 && "col-span-2",
          )}
        >
          <dt className="truncate text-[12.5px] font-medium text-muted-foreground" title={r.label}>{r.label}</dt>
          <dd className={cn("mt-2 truncate text-[28px] font-semibold leading-none tracking-tight tnum", r.tone ? TONE[r.tone] : "text-foreground")}>
            {r.value}
          </dd>
          <dd className="mt-2 text-[12px] leading-snug text-faint">{r.foot}</dd>
        </div>
      ))}
    </dl>
  )
}
