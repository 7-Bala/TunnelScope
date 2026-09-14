import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"
import { ChartContainer, ChartTooltip, type ChartConfig } from "@/components/ui/chart"
import { type Gateway, postureKind, POSTURE_META } from "@/lib/fleet"
import { usePrefersReducedMotion } from "@/lib/use-reduced-motion"

const DRAW_MS = 1800

const SEV_WEIGHT = { high: 3, medium: 2, informational: 1 } as const
const KIND_COLOR: Record<string, string> = {
  classical: "var(--warn)",
  pq: "var(--pos)",
  downgraded: "var(--neg)",
}

const config = { load: { label: "Finding load", color: "var(--violet)" } } satisfies ChartConfig

// shadcn/Recharts step-area: the fleet posture as a waveform, each gateway a
// point whose height = weighted finding load, dot colored by posture.
export function SignalTrace({ gateways, height = 150 }: { gateways: Gateway[]; height?: number }) {
  const reduced = usePrefersReducedMotion()
  const data = gateways.map((g) => ({
    city: g.city,
    id: g.id,
    load: g.fails.reduce((s, f) => s + (SEV_WEIGHT[f.severity] ?? 0), 0),
    kind: postureKind(g.posture),
  }))

  return (
    <ChartContainer config={config} className="w-full" style={{ height }}>
      <AreaChart data={data} margin={{ top: 12, right: 10, left: 46, bottom: 8 }}>
        <defs>
          <linearGradient id="fillLoad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--violet)" stopOpacity={0.22} />
            <stop offset="95%" stopColor="var(--violet)" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="var(--border)" strokeOpacity={0.6} />
        <XAxis
          dataKey="city"
          tickLine={false}
          axisLine={false}
          interval={0}
          tickMargin={8}
          angle={-38}
          textAnchor="end"
          height={40}
          tick={{ fill: "var(--muted-foreground)", fontSize: 9.5 }}
        />
        <YAxis hide domain={[0, (max: number) => max + 1]} />
        <ChartTooltip
          cursor={{ stroke: "var(--border)" }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const d = payload[0].payload as (typeof data)[number]
            return (
              <div className="rounded-md border border-border bg-popover px-3 py-2 text-[12px] shadow-md">
                <div className="font-medium text-foreground">{d.city}</div>
                <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{d.id}</div>
                <div className="mt-1.5 flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full" style={{ background: KIND_COLOR[d.kind] }} />
                  <span className="text-muted-foreground">{POSTURE_META[d.kind].label}</span>
                  <span className="ml-auto tabular-nums text-foreground">load {d.load}</span>
                </div>
              </div>
            )
          }}
        />
        <Area
          dataKey="load"
          type="monotone"
          stroke="var(--violet)"
          strokeWidth={1.75}
          fill="url(#fillLoad)"
          isAnimationActive={!reduced}
          animationDuration={DRAW_MS}
          animationEasing="ease-out"
          activeDot={{ r: 4, stroke: "var(--violet)", fill: "var(--background)" }}
          dot={(props: { cx?: number; cy?: number; index?: number; payload?: (typeof data)[number] }) => {
            const { cx, cy, index, payload } = props
            if (cx == null || cy == null) return <g key={index} />
            // Each dot pops in exactly when the step-line reaches it, so the
            // reveal reads as one continuous draw, not a line then a dot pass.
            const delay = reduced ? 0 : ((index ?? 0) / Math.max(data.length - 1, 1)) * DRAW_MS
            return (
              <circle
                key={index}
                cx={cx}
                cy={cy}
                r={3.4}
                fill="var(--background)"
                stroke={KIND_COLOR[payload?.kind ?? "classical"]}
                strokeWidth={1.6}
                style={{
                  transformOrigin: `${cx}px ${cy}px`,
                  animation: reduced ? "none" : `chart-dot-in .32s cubic-bezier(.34,1.56,.64,1) ${delay}ms both`,
                }}
              />
            )
          }}
        />
      </AreaChart>
    </ChartContainer>
  )
}
