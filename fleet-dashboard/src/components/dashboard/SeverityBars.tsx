import { Bar, BarChart, Cell, LabelList, XAxis, YAxis } from "recharts"
import { ChartContainer, type ChartConfig } from "@/components/ui/chart"

const config = { n: { label: "Findings" } } satisfies ChartConfig

// shadcn/Recharts horizontal bar chart: findings by severity.
export function SeverityBars({ high, medium, informational }: { high: number; medium: number; informational: number }) {
  const data = [
    { sev: "High", n: high, fill: "var(--neg)" },
    { sev: "Medium", n: medium, fill: "var(--steel)" },
    { sev: "Info", n: informational, fill: "var(--faint)" },
  ]

  return (
    <ChartContainer config={config} className="h-[132px] w-full px-2 py-4">
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 22, left: 6, bottom: 4 }} barCategoryGap={12}>
        <XAxis type="number" hide domain={[0, "dataMax + 1"]} />
        <YAxis
          type="category"
          dataKey="sev"
          tickLine={false}
          axisLine={false}
          width={58}
          tick={{ fill: "var(--muted-foreground)", fontSize: 12 }}
        />
        <Bar dataKey="n" radius={4} barSize={12} isAnimationActive={false}>
          {data.map((d) => (
            <Cell key={d.sev} fill={d.fill} />
          ))}
          <LabelList
            dataKey="n"
            position="right"
            offset={8}
            className="fill-foreground/80"
            style={{ fontSize: 12, fontVariantNumeric: "tabular-nums" }}
          />
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}
