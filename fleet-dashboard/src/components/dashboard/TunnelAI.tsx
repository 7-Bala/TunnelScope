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

/** The EXP-05 Random Forest attacker, run on this capture by the engine. */
export function AttackerPane({ sa }: { sa: AnalyzedSA }) {
  const f = sa.findings.find((x) => x.attribute === "attacker_exposure")
  const mx = sa.findings.find((x) => x.attribute === "metadata_exposure")
  const v = (f?.status === "MEASURED" ? f.value : null) as
    | { level: keyof typeof LEVEL; score: number; confidence: number; consistency: number; windows: number }
    | null

  return (
    <div className="max-w-[86ch]">
      <p className="text-[12.5px] leading-relaxed text-muted-foreground">
        A passive eavesdropper can't read encrypted traffic, but it can see packet sizes, timing and direction. We trained a
        Random Forest on our own lab traffic to play that eavesdropper (EXP-05: right 99.5–100% of the time on lab data). Here
        it tries this tunnel. The score is how sure and how consistent it is; the traffic type it guesses is deliberately not
        shown (on mixed traffic it can be confidently wrong).
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
            {/* a coin-flip attacker over 5 traffic types would sit around 20 */}
            <div className="absolute -top-1 h-4 w-px bg-foreground/50" style={{ left: "20%" }} title="chance level (1 in 5)" />
          </div>
          <div className="mt-1 flex max-w-[420px] justify-between text-[11px] text-faint">
            <span>0</span>
            <span style={{ marginLeft: "calc(20% - 24px)" }}>chance</span>
            <span className="ml-auto">100</span>
          </div>
          <dl className="mt-4 grid max-w-[520px] grid-cols-3 gap-3 text-[12px]">
            <div><dt className="text-faint">Average confidence</dt><dd className="font-mono tnum text-foreground/90">{Math.round(v.confidence * 100)}%</dd></div>
            <div><dt className="text-faint">Same guess in</dt><dd className="font-mono tnum text-foreground/90">{Math.round(v.consistency * 100)}% of windows</dd></div>
            <div><dt className="text-faint">Windows seen</dt><dd className="font-mono tnum text-foreground/90">{v.windows} × 2 s</dd></div>
          </dl>
          <p className="mt-3 text-[12.5px] leading-relaxed text-muted-foreground">{f?.note}</p>
        </div>
      ) : (
        <p className="mt-4 rounded-xl border border-border px-4 py-3 text-[12.5px] leading-relaxed text-muted-foreground">
          <span className="font-medium text-foreground/85">Not measured. </span>
          {f?.note ?? "This capture has no ESP traffic."}
        </p>
      )}

      {mx?.status === "MEASURED" && (
        <p className="mt-3 text-[12px] text-faint">Channel leakage measured directly: {formatValue(mx.value)}.</p>
      )}
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
