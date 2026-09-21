import { useState } from "react"
import { ChevronDown } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { cn } from "@/lib/utils"
import { type AnalyzedSA, formatValue } from "@/lib/api"

/** Plain-English explanation, built by the engine from the verdicts and a
 *  fixed glossary. No language model is involved. */
export function ExplainedPane({ sa }: { sa: AnalyzedSA }) {
  const e = sa.explanation
  return (
    <div className="max-w-[86ch]">
      <p className="text-[13.5px] leading-relaxed text-foreground/90">{e.summary}</p>
      <ul className="mt-3 space-y-2.5">
        {e.points.map((p, i) => (
          <li key={i} className="flex gap-2.5 text-[13px] leading-relaxed text-muted-foreground">
            <span
              aria-hidden
              className={cn(
                "mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full",
                p.kind === "fail" && p.severity === "high" ? "bg-neg" : p.kind === "fail" ? "bg-warn" : p.kind === "ok" ? "bg-pos" : "bg-violet",
              )}
            />
            <span>{p.text}</span>
          </li>
        ))}
      </ul>
      {e.unseen.length > 0 && (
        <p className="mt-3 text-[12.5px] leading-relaxed text-faint">Not visible in this capture: {e.unseen.join("; ")}.</p>
      )}
      <p className="mt-4 border-t border-border pt-3 text-[11.5px] text-faint">
        Written directly from the verdicts above. Nothing here comes from a language model.
      </p>
    </div>
  )
}

const LEVEL = {
  high: { t: "High exposure", c: "text-neg", bar: "bg-neg" },
  medium: { t: "Medium exposure", c: "text-warn", bar: "bg-warn" },
  low: { t: "Low exposure", c: "text-pos", bar: "bg-pos" },
} as const

type TrafficValue = {
  class: string
  label: string
  probability: number
  alternatives: { class: string; label: string; probability: number }[]
}

const MEASURED_POINTS = [
  "What is scored: the model looks at 2-second slices of the tunnel's packet sizes, timing and direction and guesses the traffic type. It never sees the content, which is encrypted.",
  "The accuracy score is macro-F1, averaged over the 8 traffic types so a rare type counts as much as a common one. 1.0 is perfect; guessing at random scores about 0.12.",
  "How it was tested: every setup was recorded several times. The model is trained without one repetition and scored on that one, so it is never scored on data it trained on.",
  "Result on runs it had not seen: 0.986, from 1,964 two-second windows across 216 sessions (synthetic traffic shapes, real applications, and a second IPsec implementation).",
  "Different VPN software: trained on strongSwan traffic, it scored 1.000 on Libreswan traffic.",
  "The warning that matters: a model trained only on synthetic traffic scored 0.461 on real applications. A model is only as good as how closely its training traffic resembles yours.",
  "Mixed traffic: a second check flags tunnels carrying several kinds of traffic at once. It catches 92.9% of mixed sessions and wrongly flags 8.3% of single-type sessions.",
  "Lab only: one lab network, no internet delay or packet loss, our own servers. Read these scores as evidence that the method works, not as accuracy in the field.",
] as const

/** Traffic type (PS c) and attacker exposure, both from the Random Forest the
 *  engine trains on our own lab traffic (EXP-05, EXP-15). */
export function AttackerPane({ sa }: { sa: AnalyzedSA }) {
  const [open, setOpen] = useState(false)
  const f = sa.findings.find((x) => x.attribute === "attacker_exposure")
  const tt = sa.findings.find((x) => x.attribute === "traffic_type")
  const mx = sa.findings.find((x) => x.attribute === "metadata_exposure")
  const v = (f?.status === "MEASURED" ? f.value : null) as
    | { level: keyof typeof LEVEL; score: number; confidence: number; consistency: number; windows: number }
    | null
  const t = (tt?.status === "INFERRED" ? tt.value : null) as TrafficValue | null

  return (
    <div className="max-w-[86ch]">
      <h3 className="text-[12px] font-medium text-faint">Traffic inside the tunnel</h3>
      {t ? (
        <div className="mt-2">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-[20px] font-semibold text-foreground">{t.label}</span>
            <span className="font-mono text-[13px] text-violet tnum">{Math.round(t.probability * 100)}% model confidence</span>
          </div>
          <ul className="mt-3 max-w-[460px] space-y-1.5">
            {t.alternatives.map((a) => (
              <li key={a.class} className="grid grid-cols-[170px_1fr_44px] items-center gap-3 text-[12px]">
                <span className="truncate text-muted-foreground">{a.label}</span>
                <span className="h-1.5 rounded-full bg-secondary">
                  <span className="block h-1.5 rounded-full bg-violet" style={{ width: `${Math.round(a.probability * 100)}%` }} />
                </span>
                <span className="text-right font-mono text-faint tnum">{Math.round(a.probability * 100)}%</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-[12.5px] leading-relaxed text-muted-foreground">{tt?.note}</p>
        </div>
      ) : (
        <p className="mt-2 rounded-xl border border-border px-4 py-3 text-[12.5px] leading-relaxed text-muted-foreground">
          <span className="font-medium text-foreground/85">Uncertain. </span>
          {tt?.note?.replace(/^uncertain: /, "") ?? "This capture has no ESP traffic."}
        </p>
      )}

      <h3 className="mt-6 text-[12px] font-medium text-faint">How exposed is the traffic's shape?</h3>
      <p className="mt-1 text-[12.5px] leading-relaxed text-muted-foreground">
        A passive eavesdropper can't read encrypted traffic, but it sees packet sizes, timing and direction. The same model plays
        that eavesdropper: the score is how sure and how consistent it is about this tunnel.
      </p>
      {v ? (
        <div className="mt-4">
          <div className="flex items-baseline gap-3">
            <span className={cn("font-mono text-[34px] font-semibold leading-none tnum", LEVEL[v.level].c)}>{v.score}</span>
            <span className="text-[12px] text-faint">/ 100</span>
            <span className={cn("ml-1 text-[14px] font-semibold", LEVEL[v.level].c)}>{LEVEL[v.level].t}</span>
          </div>
          <div className="relative mt-3 h-2 w-full max-w-[420px] rounded-full bg-secondary" role="img" aria-label={`Exposure ${v.score} of 100`}>
            <div className={cn("h-2 rounded-full", LEVEL[v.level].bar)} style={{ width: `${v.score}%` }} />
            {/* guessing at random among 8 traffic types would sit around 12 */}
            <div className="absolute -top-1 h-4 w-px bg-foreground/50" style={{ left: "12.5%" }} title="chance level (1 in 8)" />
          </div>
          <dl className="mt-4 grid max-w-[520px] grid-cols-3 gap-3 text-[12px]">
            <div><dt className="text-faint">Average confidence</dt><dd className="font-mono tnum text-foreground/90">{Math.round(v.confidence * 100)}%</dd></div>
            <div><dt className="text-faint">Same guess in</dt><dd className="font-mono tnum text-foreground/90">{Math.round(v.consistency * 100)}% of windows</dd></div>
            <div><dt className="text-faint">Windows seen</dt><dd className="font-mono tnum text-foreground/90">{v.windows} × 2 s</dd></div>
          </dl>
        </div>
      ) : (
        <p className="mt-3 text-[12.5px] text-muted-foreground">Not measured: {f?.note ?? "no ESP traffic."}</p>
      )}

      {mx?.status === "MEASURED" && (
        <p className="mt-3 text-[12px] text-faint">Channel leakage measured directly: {formatValue(mx.value)}.</p>
      )}

      <div className="mt-6 border-t border-border pt-4">
        <Collapsible open={open} onOpenChange={setOpen}>
          <CollapsibleTrigger
            aria-label="How these numbers were measured"
            className="flex w-full cursor-pointer items-center justify-between gap-2 text-left text-[12px] font-medium text-faint transition-colors hover:text-muted-foreground"
          >
            <span>How these numbers were measured</span>
            <ChevronDown className={cn("h-4 w-4 shrink-0 text-faint transition-transform duration-200", open && "rotate-180 text-violet")} />
          </CollapsibleTrigger>
          <CollapsibleContent className="pt-3">
            <ol className="space-y-2 pl-4 list-decimal text-[12.5px] leading-relaxed text-muted-foreground">
              {MEASURED_POINTS.map((point, i) => (
                <li key={i}>{point}</li>
              ))}
            </ol>
            <p className="mt-3 text-[11.5px] text-faint">
              Sources: experiments/exp15-traffic-classes-suites-ah and experiments/exp16-real-apps-cross-impl (RESULT.md).
            </p>
          </CollapsibleContent>
        </Collapsible>
      </div>
    </div>
  )
}

const SEV_DOT = { high: "bg-neg", medium: "bg-warn", informational: "bg-pos" } as const

/** What changed from this tunnel's learned normal (engine --history). */
export function ChangesPane({ sa }: { sa: AnalyzedSA }) {
  const a = sa.anomaly
  if (!a)
    return (
      <p className="max-w-[80ch] text-[12.5px] leading-relaxed text-muted-foreground">
        Anomaly detection is off. Start the engine with <code className="font-mono">--history DIR</code> (./start.sh does this)
        and it learns each tunnel's usual crypto and traffic, then flags downgrades and sudden changes on later captures.
      </p>
    )
  return (
    <div className="max-w-[86ch]">
      <p className="text-[13px] text-foreground/90">
        {a.status === "learning" && `Learning this tunnel's normal: ${a.observations} of ${a.needed} earlier observations so far. Upload more captures of it.`}
        {a.status === "normal" && `Matches this tunnel's usual behaviour across ${a.observations} earlier observations.`}
        {a.status === "anomalous" && `Different from this tunnel's usual behaviour (${a.observations} earlier observations).`}
      </p>
      {a.layers && (
        <p className="mt-1 text-[11.5px] text-faint">
          Checks run: {a.layers.join(", ")}. Traffic statistics start at 5 observations, the Isolation Forest model at 8.
        </p>
      )}
      {a.anomalies.length > 0 && (
        <ul className="mt-3 space-y-2">
          {a.anomalies.map((x, i) => (
            <li key={i} className="flex gap-2.5 text-[13px] leading-relaxed text-muted-foreground">
              <span aria-hidden className={cn("mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full", SEV_DOT[x.severity])} />
              <span>
                <span className="mr-1.5 rounded bg-secondary px-1.5 py-px font-mono text-[10.5px] uppercase text-silver">{x.layer}</span>
                {x.message}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
