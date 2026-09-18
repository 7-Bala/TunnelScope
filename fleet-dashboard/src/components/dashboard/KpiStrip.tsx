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
    <dl className="glass grid grid-cols-2 overflow-hidden rounded-2xl sm:grid-cols-6 lg:grid-cols-5">
      {readouts.map((r, i) => (
        <div
          key={r.label}
          className={cn(
            // hairline light dividers on each cell's right and bottom edge (the old 1px-gap
            // trick needs opaque cells, which glass is not)
            "min-w-0 px-5 py-4 shadow-[inset_-1px_0_0_rgb(255_255_255/0.06),inset_0_-1px_0_rgb(255_255_255/0.06)]",
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
