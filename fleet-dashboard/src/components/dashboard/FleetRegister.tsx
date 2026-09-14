import { useMemo, useState } from "react"
import { ChevronDown } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { cn } from "@/lib/utils"
import { type Gateway, type Finding, postureKind } from "@/lib/fleet"

const FILTERS = [
  { key: "all", label: "All" },
  { key: "attn", label: "Needs attention" },
  { key: "downgraded", label: "Downgraded" },
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
  "CVE-2026-78135": "Child SA before IKE_AUTH",
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
  if (k === "downgraded") return { t: "Downgraded", cls: "bg-neg-bg text-neg" }
  if (k === "pq") return { t: "PQ hybrid", cls: "bg-pos-bg text-pos" }
  return { t: "Classical", cls: "bg-warn-bg text-warn" }
}

function Row({ g }: { g: Gateway }) {
  const [open, setOpen] = useState(false)
  const chip = stateChip(g)
  const high = g.fails.filter((f) => f.severity === "high").length

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div className={cn("border-b border-border/60 transition-colors last:border-0", open ? "bg-secondary/40" : "hover:bg-secondary/25")}>
        <CollapsibleTrigger className="flex w-full items-center gap-4 px-5 py-3.5 text-left">
          <span className={cn("shrink-0 rounded-full px-2.5 py-1 text-[11px] font-medium", chip.cls)}>{chip.t}</span>

          <span className="min-w-0 flex-1">
            <span className="text-[14px] font-medium text-foreground">{g.city}</span>
            <span className="ml-2 font-mono text-[11px] text-faint">{g.id}</span>
            <span className="mt-0.5 block truncate font-mono text-[11.5px] text-muted-foreground">
              {g.src} → {g.dst}
            </span>
          </span>

          <span className="shrink-0 text-[12px] text-muted-foreground">
            {g.fails.length ? (
              <>
                {high > 0 && <span className="text-neg">{high} high</span>}
                <span className="ml-2 text-faint">{g.fails.length} checks</span>
              </>
            ) : (
              <span className="text-pos">clean</span>
            )}
          </span>
          <ChevronDown className={cn("h-4 w-4 shrink-0 text-faint transition-transform duration-200", open && "rotate-180 text-violet")} />
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="px-5 pb-4 sm:pl-[76px]">
            <div className="mb-2 text-[12px] text-faint">Verdicts, each cited to its standard ({g.fails.length})</div>
            {g.fails.length ? (
              <div className="font-mono text-[12px]">
                {g.fails.map((f, k) => {
                  const last = k === g.fails.length - 1
                  return (
                    <div key={k} className="flex items-start gap-2.5 py-[3px]">
                      <span className="shrink-0 text-faint">{last ? "└" : "├"}</span>
                      <span className={cn("w-9 shrink-0 font-medium", SEV[f.severity].c)}>{SEV[f.severity].t}</span>
                      <span className="w-[140px] shrink-0 truncate text-foreground/90" title={f.rule_id}>{f.rule_id}</span>
                      <span className="hidden w-[150px] shrink-0 truncate text-muted-foreground/70 sm:inline" title={f.baseline}>{f.baseline}</span>
                      <span className="min-w-0 flex-1 text-muted-foreground">{RULE_DESC[f.rule_id] ?? ""}</span>
                    </div>
                  )
                })}
              </div>
            ) : (
              <div className="font-mono text-[12px] text-muted-foreground">└ no cited findings against the loaded baselines</div>
            )}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  )
}

export function FleetRegister({ gateways }: { gateways: Gateway[] }) {
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
    <section className="rise overflow-hidden rounded-2xl border border-border bg-card" style={{ animationDelay: "180ms" }}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold tracking-tight">Fleet register</h2>
          <p className="mt-0.5 truncate text-[12px] text-muted-foreground">
            {filtered.length} of {gateways.length} security associations
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={cn(
                "rounded-full px-3 py-1.5 text-[12px] font-medium whitespace-nowrap transition-colors",
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
      </div>
    </section>
  )
}
