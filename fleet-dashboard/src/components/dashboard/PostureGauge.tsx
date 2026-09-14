import { Cell, Label, Pie, PieChart } from "recharts"
import { ChartContainer, ChartTooltip, type ChartConfig } from "@/components/ui/chart"
import type { PostureKind } from "@/lib/fleet"
import { POSTURE_META } from "@/lib/fleet"

const ORDER: PostureKind[] = ["classical", "downgraded", "pq"]
const config = {} satisfies ChartConfig

// shadcn/Recharts donut: fleet posture composition.
export function PostureGauge({ counts, total }: { counts: Record<PostureKind, number>; total: number }) {
  const data = ORDER.filter((k) => counts[k]).map((k) => ({
    kind: k,
    name: POSTURE_META[k].label,
    value: counts[k],
    fill: POSTURE_META[k].color,
  }))
  const pctClassical = Math.round((counts.classical / total) * 100)

  return (
    <div className="flex items-center gap-5 px-5 py-5">
      <ChartContainer config={config} className="h-[150px] w-[150px] shrink-0">
        <PieChart>
          <ChartTooltip
            content={({ active, payload }) => {
              if (!active || !payload?.length) return null
              const d = payload[0].payload as (typeof data)[number]
              return (
                <div className="rounded-md border border-border bg-popover px-3 py-1.5 text-[12px] shadow-md">
                  <span className="inline-flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full" style={{ background: d.fill }} />
                    {d.name}
                    <span className="ml-1 tabular-nums text-muted-foreground">
                      {d.value} · {Math.round((d.value / total) * 100)}%
                    </span>
                  </span>
                </div>
              )
            }}
          />
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={48}
            outerRadius={66}
            paddingAngle={3}
            cornerRadius={4}
            strokeWidth={0}
            startAngle={90}
            endAngle={-270}
            isAnimationActive={false}
          >
            {data.map((d) => (
              <Cell key={d.kind} fill={d.fill} />
            ))}
            <Label
              content={({ viewBox }) => {
                if (!viewBox || !("cx" in viewBox)) return null
                const { cx, cy } = viewBox as { cx: number; cy: number }
                return (
                  <text x={cx} y={cy} textAnchor="middle" dominantBaseline="middle">
                    <tspan x={cx} y={cy - 4} className="fill-foreground text-[26px] font-semibold tabular-nums">
                      {pctClassical}%
                    </tspan>
                    <tspan x={cx} y={cy + 16} className="fill-muted-foreground text-[11px]">
                      classical
                    </tspan>
                  </text>
                )
              }}
            />
          </Pie>
        </PieChart>
      </ChartContainer>

      <div className="flex flex-1 flex-col gap-2.5">
        {data.map((d) => (
          <div key={d.kind} className="flex items-center gap-2.5 text-[13px]">
            <span className="h-2 w-2 rounded-full" style={{ background: d.fill }} />
            <span className="flex-1 text-foreground/85">{d.name}</span>
            <span className="font-mono text-[13px] text-muted-foreground tabular-nums">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
