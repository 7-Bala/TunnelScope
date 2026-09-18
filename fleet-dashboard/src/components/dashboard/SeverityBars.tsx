import { Bar, BarChart, Cell, LabelList, XAxis, YAxis } from "recharts"
import type { Props as LabelContentProps } from "recharts/types/component/Label"
import { ChartContainer, type ChartConfig } from "@/components/ui/chart"
import { usePrefersReducedMotion } from "@/lib/use-reduced-motion"

const config = { n: { label: "Findings" } } satisfies ChartConfig
const GROW_MS = 650

// shadcn/Recharts horizontal bar chart: findings by severity.
export function SeverityBars({ high, medium, informational }: { high: number; medium: number; informational: number }) {
  const reduced = usePrefersReducedMotion()
  const data = [
    { sev: "High", n: high, fill: "var(--neg)" },
    { sev: "Medium", n: medium, fill: "var(--warn)" },
    { sev: "Info", n: informational, fill: "var(--faint)" },
  ]

  return (
    <ChartContainer config={config} className="h-[132px] w-full px-2 py-4">
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 30, left: 6, bottom: 4 }} barCategoryGap={12}>
        {/* Proportional headroom (not a flat +1): the longest bar always stops at
            ~80% of the plot width, so the label's fixed-size text has guaranteed
            room after it at any container width, not just the one this was
            eyeballed at. */}
        <XAxis type="number" hide domain={[0, (max: number) => Math.ceil(max * 1.25)]} />
        <YAxis
          type="category"
          dataKey="sev"
          tickLine={false}
          axisLine={false}
          width={58}
          tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
        />
        <Bar
          dataKey="n"
          radius={4}
          barSize={12}
          isAnimationActive={!reduced}
          animationDuration={GROW_MS}
          animationEasing="ease-out"
        >
          {data.map((d) => (
            <Cell key={d.sev} fill={d.fill} />
          ))}
          <LabelList
            dataKey="n"
            position="right"
            offset={8}
            content={(props: LabelContentProps) => {
              const x = Number(props.x ?? 0)
              const y = Number(props.y ?? 0)
              const w = Number(props.width ?? 0)
              const h = Number(props.height ?? 0)
              // lands right as its own bar finishes growing, not all at once
              const delay = reduced ? 0 : GROW_MS * 0.75
              return (
                <text
                  x={x + w + 8}
                  y={y + h / 2}
                  dominantBaseline="middle"
                  className="fill-foreground/80"
                  style={{
                    fontSize: 12,
                    fontVariantNumeric: "tabular-nums",
                    opacity: reduced ? 1 : 0,
                    animation: reduced ? "none" : `chart-label-in .3s ease-out ${delay}ms both`,
                  }}
                >
                  {props.value}
                </text>
              )
            }}
          />
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}
