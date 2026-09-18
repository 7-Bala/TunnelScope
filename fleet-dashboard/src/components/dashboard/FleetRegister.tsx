import { useMemo, useState } from "react"
import { ChevronDown } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { cn } from "@/lib/utils"
import { type Gateway, type Finding, postureKind } from "@/lib/fleet"
import { type AnalyzedSA, type FindingStatus, type VerdictResult, formatValue } from "@/lib/api"

const FILTERS = [
  { key: "all", label: "All" },
  { key: "attn", label: "Needs attention" },
  { key: "downgraded", label: "PQ not selected" },
  { key: "pq", label: "Post-quantum" },
  { key: "classical", label: "Classical" },
] as const

const RULE_DESC: Record<string, string> = {
  "V-207193": "DH group below 16 for IKE SA",
  "V-207223": "IKE integrity below SHA2-384",
  "V-207205": "IKEv2 required",
  "RFC8247-DH-MUST": "MODP-2048 minimum",
  "RFC8247-ENCR": "approved ESP cipher",
  "DST-PQ-KE": "no post-quantum key exchange",
  "DST-PQ-DOWNGRADE": "PQ offered, classical selected",
  "CVE-2026-78135": "CREATE_CHILD_SA attempted before IKE_AUTH",
}

const STATUS: Record<FindingStatus, { t: string; cls: string }> = {
  OBSERVED: { t: "observed", cls: "bg-violet-bg text-violet" },
  MEASURED: { t: "measured", cls: "bg-violet-bg text-violet" },
  INFERRED: { t: "inferred", cls: "bg-secondary text-silver" },
  UNKNOWN: { t: "unknown", cls: "border border-border text-faint" },
  NOT_OBSERVABLE: { t: "not observable", cls: "border border-border text-faint" },
  CONTRADICTORY: { t: "contradictory", cls: "bg-neg-bg text-neg" },
}

const RESULT: Record<VerdictResult, { t: string; cls: string; order: number }> = {
  FAIL: { t: "Fail", cls: "text-neg", order: 0 },
  CONTRADICTORY: { t: "Conflict", cls: "text-neg", order: 1 },
  UNKNOWN: { t: "Unknown", cls: "text-faint", order: 2 },
  NOT_OBSERVABLE: { t: "Not obs.", cls: "text-faint", order: 3 },
  PASS: { t: "Pass", cls: "text-pos", order: 4 },
}

type Pane = "verdicts" | "evidence" | "blind"

function Detail({ sa }: { sa: AnalyzedSA }) {
  const [pane, setPane] = useState<Pane>("verdicts")
  const verdicts = [...sa.verdicts].sort((a, b) => RESULT[a.verdict].order - RESULT[b.verdict].order)
  const blind = sa.findings.filter((f) => f.status === "NOT_OBSERVABLE" || f.status === "UNKNOWN")
  const panes: { key: Pane; label: string; n: number }[] = [
    { key: "verdicts", label: "Verdicts", n: verdicts.length },
    { key: "evidence", label: "Evidence", n: sa.findings.length },
    { key: "blind", label: "Not visible from here", n: blind.length },
  ]

  return (
    <div className="px-5 pb-5 sm:pl-[76px]">
      <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-[11.5px] text-muted-foreground">
        <span>IKE SPI <span className="text-foreground/85">{sa.ike_spi}</span></span>
        {Object.entries(sa.scores).map(([b, sc]) => (
          <span key={b} className="tnum">
            {b} <span className="text-foreground/85">{sc.score ?? "n/a"}</span>
          </span>
        ))}
        {sa.score_stability === "fragile" && (
          <span className="font-sans text-faint">scores rest on few rules; read the verdicts, not the number</span>
        )}
      </div>

      <div role="tablist" aria-label="Capture detail" className="mb-3 flex flex-wrap gap-1 border-b border-border">
        {panes.map((p) => (
          <button
            key={p.key}
            role="tab"
            type="button"
            aria-selected={pane === p.key}
            onClick={() => setPane(p.key)}
            className={cn(
              "-mb-px border-b-2 px-2.5 pb-2 pt-1 text-[12.5px] font-medium transition-colors",
              pane === p.key ? "border-violet text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {p.label} <span className="font-mono text-[11px] text-faint tnum">{p.n}</span>
          </button>
        ))}
      </div>

      {pane === "verdicts" && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-[12.5px]">
            <thead>
              <tr className="text-[11.5px] text-faint">
                <th className="py-1.5 pr-3 font-medium">Result</th>
                <th className="py-1.5 pr-3 font-medium">Rule</th>
                <th className="py-1.5 pr-3 font-medium">Baseline</th>
                <th className="py-1.5 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {verdicts.map((v, k) => (
                <tr key={k} className="align-top">
                  <td className={cn("py-2 pr-3 font-medium", RESULT[v.verdict].cls)}>{RESULT[v.verdict].t}</td>
                  <td className="py-2 pr-3 font-mono text-[12px] text-foreground/90">{v.rule_id}</td>
                  <td className="py-2 pr-3 text-muted-foreground">{v.baseline}</td>
                  <td className="py-2 leading-snug text-muted-foreground">
                    {v.verdict === "FAIL" ? v.message || v.title : v.observed != null ? `observed ${formatValue(v.observed)}` : v.title}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pane === "evidence" && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[560px] text-left text-[12.5px]">
            <thead>
              <tr className="text-[11.5px] text-faint">
                <th className="py-1.5 pr-3 font-medium">Attribute</th>
                <th className="py-1.5 pr-3 font-medium">Status</th>
                <th className="py-1.5 pr-3 font-medium">Value</th>
                <th className="py-1.5 font-medium">Vantage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {sa.findings.map((f) => (
                <tr key={f.attribute} className="align-top">
                  <td className="py-2 pr-3 font-mono text-[12px] text-foreground/90">{f.attribute}</td>
                  <td className="py-2 pr-3">
                    <span className={cn("whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium", STATUS[f.status].cls)}>
                      {STATUS[f.status].t}
                    </span>
                  </td>
                  <td className="max-w-[420px] break-words py-2 pr-3 font-mono text-[12px] text-muted-foreground">{formatValue(f.value)}</td>
                  <td className="py-2 font-mono text-[12px] text-faint" title={f.method}>{f.vantage}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {pane === "blind" && (
        <ul className="divide-y divide-border/60">
          {blind.length === 0 && <li className="py-2 text-[12.5px] text-muted-foreground">Every attribute was visible from this capture.</li>}
          {blind.map((f) => (
            <li key={f.attribute} className="py-2.5">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[12px] text-foreground/90">{f.attribute}</span>
                <span className={cn("rounded-full px-2 py-0.5 text-[11px] font-medium", STATUS[f.status].cls)}>{STATUS[f.status].t}</span>
              </div>
              {f.note && <p className="mt-1 max-w-[80ch] text-[12.5px] leading-relaxed text-muted-foreground">{f.note}</p>}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

const SEV: Record<Finding["severity"], { t: string; c: string }> = {
  high: { t: "High", c: "text-neg" },
  medium: { t: "Med", c: "text-warn" },
  informational: { t: "Info", c: "text-faint" },
}

function stateChip(g: Gateway): { t: string; cls: string } {
  const cve = g.fails.some((f) => f.baseline === "CVE-WATCH")
  if (cve) return { t: "CVE", cls: "bg-neg-bg text-neg" }
  const k = postureKind(g.posture)
  if (k === "downgraded") return { t: "PQ not selected", cls: "bg-neg-bg text-neg" }
  if (k === "pq") return { t: "PQ hybrid", cls: "bg-pos-bg text-pos" }
  return { t: "Classical", cls: "bg-warn-bg text-warn" }
}

function Row({ g }: { g: Gateway }) {
  const [open, setOpen] = useState(false)
  const chip = stateChip(g)
  const high = g.fails.filter((f) => f.severity === "high").length
  const counts = g.fails.length ? (
    <>
      {high > 0 && <span className="text-neg">{high} high</span>}
      <span className={cn("text-faint", high > 0 && "ml-2")}>{g.fails.length} failed</span>
    </>
  ) : (
    <span className="text-pos">no failed checks</span>
  )

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div className={cn("border-b border-border/60 transition-colors last:border-0", open ? "bg-secondary/40" : "hover:bg-secondary/25")}>
        <CollapsibleTrigger className="flex w-full items-start gap-3 px-4 py-3.5 text-left sm:items-center sm:gap-4 sm:px-5">
          <span className={cn("mt-0.5 w-[112px] shrink-0 rounded-full px-2.5 py-1 text-center text-[11px] font-medium sm:mt-0", chip.cls)}>
            {chip.t}
          </span>

          <span className="min-w-0 flex-1">
            <span className="flex min-w-0 items-baseline gap-2">
              <span className="truncate text-[14px] font-medium text-foreground">{g.city}</span>
              {g.origin === "sample" && <span className="hidden shrink-0 font-mono text-[11px] text-faint sm:inline">{g.id}</span>}
            </span>
            <span className="mt-0.5 block truncate font-mono text-[11.5px] text-muted-foreground">
              {g.src} → {g.dst}
            </span>
            <span className="mt-1 block text-[12px] sm:hidden">{counts}</span>
          </span>

          <span className="hidden shrink-0 text-[12px] sm:block">{counts}</span>
          <ChevronDown className={cn("mt-1 h-4 w-4 shrink-0 text-faint transition-transform duration-200 sm:mt-0", open && "rotate-180 text-violet")} />
        </CollapsibleTrigger>

        <CollapsibleContent>
          {g.detail ? (
            <Detail sa={g.detail} />
          ) : (
            <div className="px-5 pb-4 sm:pl-[76px]">
              <div className="mb-2 text-[12px] text-faint">Failed checks, each cited to its standard ({g.fails.length})</div>
              {g.fails.length ? (
                <div className="font-mono text-[12px]">
                  {g.fails.map((f, k) => {
                    const last = k === g.fails.length - 1
                    return (
                      <div key={k} className="flex items-baseline gap-2.5 py-[3px]">
                        <span className="text-faint">{last ? "└" : "├"}</span>
                        <span className={cn("w-10 shrink-0 font-medium", SEV[f.severity].c)}>{SEV[f.severity].t}</span>
                        <span className="w-[136px] shrink-0 text-foreground/90">{f.rule_id}</span>
                        <span className="hidden w-[150px] shrink-0 text-muted-foreground/70 sm:inline">{f.baseline}</span>
                        <span className="text-muted-foreground">{RULE_DESC[f.rule_id] ?? f.title ?? ""}</span>
                      </div>
                    )
                  })}
                </div>
              ) : (
                <div className="font-mono text-[12px] text-muted-foreground">└ no failed checks against the loaded baselines</div>
              )}
            </div>
          )}
        </CollapsibleContent>
      </div>
    </Collapsible>
  )
}

export function FleetRegister({ gateways, title = "Fleet register" }: { gateways: Gateway[]; title?: string }) {
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["key"]>("all")

  const filtered = useMemo(
    () =>
      gateways.filter((g) => {
        if (filter === "all") return true
        if (filter === "attn") return g.fails.some((f) => f.severity === "high")
        return postureKind(g.posture) === filter
      }),
    [gateways, filter],
  )

  return (
    <section className="overflow-hidden rounded-2xl border border-border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div>
          <h2 className="text-[15px] font-semibold tracking-tight">{title}</h2>
          <p className="mt-0.5 text-[12px] text-muted-foreground">
            {filtered.length} of {gateways.length} security associations
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={cn(
                "rounded-full px-3 py-1.5 text-[12px] font-medium transition-colors",
                filter === f.key ? "bg-violet text-primary-foreground" : "text-muted-foreground hover:bg-secondary hover:text-foreground",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>
      <div>
        {filtered.map((g) => (
          <Row key={g.id} g={g} />
        ))}
        {filtered.length === 0 && (
          <p className="px-5 py-8 text-center text-[13px] text-muted-foreground">No security associations match this filter.</p>
        )}
      </div>
    </section>
  )
}
