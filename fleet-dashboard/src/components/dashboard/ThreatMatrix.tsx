import { cn } from "@/lib/utils"
import type { RiskResult, Threat } from "@/lib/api"

const BAND: Record<string, string> = {
  critical: "text-neg",
  high: "text-neg",
  medium: "text-warn",
  low: "text-pos",
  "none observed": "text-faint",
}
// cell colour by likelihood x impact (1..9)
function cellTone(l: number, i: number, n: number) {
  if (!n) return "bg-secondary/30 text-faint"
  const s = l * i
  return s >= 6 ? "bg-neg-bg text-neg" : s >= 3 ? "bg-warn-bg text-warn" : "bg-pos-bg text-pos"
}

/** 3x3 likelihood x impact grid. `cells` maps "l-i" to the threats in it. */
export function MatrixGrid({ cells, compact = false }: { cells: Record<string, string[]>; compact?: boolean }) {
  const L = [3, 2, 1]
  const I = [1, 2, 3]
  const name = ["", "low", "medium", "high"]
  return (
    <div className="inline-grid grid-cols-[auto_repeat(3,minmax(0,1fr))] gap-1 text-[11px]" role="table" aria-label="Threat matrix: likelihood by impact">
      <span />
      {I.map((i) => (
        <span key={i} className="px-1 text-center text-faint" role="columnheader">impact {name[i]}</span>
      ))}
      {L.map((l) => (
        <div key={l} className="contents" role="row">
          <span className="self-center pr-2 text-right text-faint" role="rowheader">{name[l]}</span>
          {I.map((i) => {
            const ids = cells[`${l}-${i}`] ?? []
            return (
              <div
                key={i}
                role="cell"
                title={ids.join(", ")}
                className={cn("flex min-h-[44px] flex-col items-center justify-center rounded-md px-1.5 py-1", compact ? "min-w-[56px]" : "min-w-[72px]", cellTone(l, i, ids.length))}
              >
                {compact ? (
                  <span className="font-mono text-[15px] font-semibold tnum">{ids.length || ""}</span>
                ) : (
                  ids.map((x) => <span key={x} className="font-mono text-[10.5px] leading-tight">{x}</span>)
                )}
              </div>
            )
          })}
        </div>
      ))}
      <span />
      <span className="col-span-3 pt-0.5 text-center text-faint">rows: likelihood · columns: impact</span>
    </div>
  )
}

const STATUS: Record<Threat["status"], { t: string; c: string }> = {
  present: { t: "present", c: "bg-neg-bg text-neg" },
  not_seen: { t: "not seen", c: "bg-secondary text-silver" },
  mitigated: { t: "mitigated", c: "bg-pos-bg text-pos" },
  not_assessable: { t: "not assessable", c: "border border-border text-faint" },
}

export function RiskBadge({ risk }: { risk: RiskResult["risk"] }) {
  return (
    <span className={cn("font-mono text-[12px] font-semibold tnum", BAND[risk.band])} title={`risk ${risk.score}/100 (${risk.band})`}>
      {risk.score}
    </span>
  )
}

/** Per-tunnel pane: score, grid, every threat with its evidence. */
export function ThreatPane({ risk }: { risk: RiskResult }) {
  const cells: Record<string, string[]> = {}
  risk.threats.filter((t) => t.status === "present").forEach((t) => (cells[`${t.likelihood}-${t.impact}`] ??= []).push(t.id))
  const order: Threat["status"][] = ["present", "not_seen", "not_assessable", "mitigated"]
  const ts = [...risk.threats].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || b.likelihood * b.impact - a.likelihood * a.impact)
  const r = risk.risk
  const c = risk.confidence
  return (
    <div className="max-w-[92ch]">
      <div className="flex flex-wrap items-start gap-x-10 gap-y-5">
        <div>
          <div className="text-[12px] text-faint">Risk score</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={cn("font-mono text-[34px] font-semibold leading-none tnum", BAND[r.band])}>{r.score}</span>
            <span className="text-[12px] text-faint">/ 100</span>
            <span className={cn("text-[14px] font-semibold capitalize", BAND[r.band])}>{r.band}</span>
          </div>
          <p className="mt-2 max-w-[36ch] text-[12px] leading-relaxed text-muted-foreground">
            {r.note}. {r.assessable} of {r.total} threats could be assessed from this capture.
          </p>
          <div className="mt-4 text-[12px] text-faint">Evidence confidence</div>
          <div className="mt-1 font-mono text-[20px] font-semibold text-foreground/90 tnum">{c.score}%</div>
          <p className="mt-1 max-w-[36ch] text-[12px] leading-relaxed text-muted-foreground">
            {c.observed} attributes observed, {c.inferred} inferred, {c.not_visible} not visible from here.
          </p>
        </div>
        <MatrixGrid cells={cells} />
      </div>

      <div className="mt-5 overflow-x-auto">
        <table className="w-full min-w-[620px] text-left text-[12.5px]">
          <thead>
            <tr className="text-[11.5px] text-faint">
              <th className="py-1.5 pr-3 font-medium">Threat</th>
              <th className="py-1.5 pr-3 font-medium">Status</th>
              <th className="py-1.5 pr-3 font-medium">L × I</th>
              <th className="py-1.5 font-medium">Why</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {ts.map((t) => (
              <tr key={t.id} className="align-top">
                <td className="py-2 pr-3">
                  <span className="font-mono text-[11px] text-faint">{t.id}</span>{" "}
                  <span className="text-foreground/90">{t.name}</span>
                </td>
                <td className="py-2 pr-3">
                  <span className={cn("whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium", STATUS[t.status].c)}>{STATUS[t.status].t}</span>
                </td>
                <td className="whitespace-nowrap py-2 pr-3 font-mono text-[11.5px] text-muted-foreground">
                  {t.status === "present" || t.status === "not_seen" ? `${t.likelihood_label[0]}·${t.impact_label[0]}` : "—"}
                </td>
                <td className="py-2 leading-snug text-muted-foreground">
                  {t.reason}
                  {t.evidence.length > 0 && <span className="ml-1 font-mono text-[11px] text-faint">[{t.evidence.join(", ")}]</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
