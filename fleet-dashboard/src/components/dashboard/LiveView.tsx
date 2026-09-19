import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { type LiveStatus, liveStatus } from "@/lib/api"
import { RiskBadge } from "@/components/dashboard/ThreatMatrix"

function ago(now: number, t?: number | null) {
  if (!t) return "never"
  const s = Math.max(0, Math.round(now / 1000 - t))
  return s < 60 ? `${s}s ago` : `${Math.round(s / 60)} min ago`
}

/** Live stream: the engine analyses each capture window as it closes. Polls /api/live. */
export function LiveView() {
  const [st, setSt] = useState<LiveStatus | null>(null)
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    let on = true
    const poll = async () => {
      const s = await liveStatus()
      if (on) setSt(s)
    }
    poll()
    const a = setInterval(poll, 3000)
    const b = setInterval(() => setNow(Date.now()), 1000)
    return () => {
      on = false
      clearInterval(a)
      clearInterval(b)
    }
  }, [])

  if (!st) return <p className="text-[13px] text-muted-foreground">Checking the engine…</p>
  if (!st.enabled)
    return (
      <section className="glass rounded-2xl px-6 py-8">
        <h2 className="text-[16px] font-semibold">Live analysis is off</h2>
        <p className="mt-2 max-w-[70ch] text-[13px] leading-relaxed text-muted-foreground">
          Start the engine on a live source and each capture window is analysed as it closes, compared with that tunnel's
          own past, and shown here:
        </p>
        <pre className="mt-3 overflow-x-auto rounded-lg bg-background/60 px-4 py-3 font-mono text-[12px] text-foreground/85">
{`./start.sh --live-follow /path/to/sensor/files     # files a tap rotates (tcpdump -G 30)
./start.sh --live-interface en0                    # capture here (needs capture permission)`}
        </pre>
      </section>
    )

  const windows = st.windows ?? []
  // latest state per tunnel, and each tunnel's risk over time (oldest -> newest)
  const tunnels: Record<string, { risk: number[]; last: NonNullable<(typeof windows)[number]["sas"]>[number] }> = {}
  ;[...windows].reverse().forEach((w) =>
    (w.sas ?? []).forEach((sa) => {
      const key = [sa.src, sa.dst].sort().join(" ↔ ")
      const t = (tunnels[key] ??= { risk: [], last: sa })
      t.risk.push(sa.risk.risk.score)
      t.last = sa
    }),
  )
  const stale = st.last_at && now / 1000 - st.last_at > 3 * (st.window_s ?? 30)

  return (
    <div className="space-y-4">
      <section className="glass flex flex-wrap items-center gap-x-8 gap-y-2 rounded-2xl px-5 py-4 text-[12.5px]">
        <span className="flex items-center gap-2">
          <span className={cn("h-2 w-2 rounded-full", stale ? "bg-warn" : "animate-pulse bg-pos")} />
          <span className="font-medium text-foreground">{stale ? "Waiting for traffic" : "Live"}</span>
        </span>
        <span className="text-muted-foreground">Source: <span className="text-foreground/85">{st.source}</span></span>
        <span className="text-muted-foreground">Window: <span className="font-mono text-foreground/85">{st.window_s}s</span></span>
        <span className="text-muted-foreground">Windows analysed: <span className="font-mono text-foreground/85 tnum">{windows.length}</span></span>
        <span className="text-muted-foreground">Last window: <span className="text-foreground/85">{ago(now, st.last_at)}</span></span>
      </section>

      <section className="glass rounded-2xl">
        <div className="border-b border-border px-5 py-3.5">
          <h2 className="text-[14px] font-semibold tracking-tight">Tunnels on the wire</h2>
        </div>
        {Object.keys(tunnels).length === 0 ? (
          <p className="px-5 py-6 text-[13px] text-muted-foreground">No IPsec traffic in the windows so far.</p>
        ) : (
          <ul className="divide-y divide-border/60">
            {Object.entries(tunnels).map(([k, t]) => {
              const an = t.last.anomaly
              const bad = an?.anomalies.filter((a) => a.severity !== "informational") ?? []
              const max = Math.max(...t.risk, 1)
              return (
                <li key={k} className="px-5 py-3.5">
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                    <span className="font-mono text-[12.5px] text-foreground/90">{k}</span>
                    {an?.status === "anomalous" && <span className="rounded-full bg-neg-bg px-2 py-px text-[10.5px] font-medium text-neg">changed</span>}
                    {an?.status === "learning" && <span className="rounded-full bg-secondary px-2 py-px text-[10.5px] text-faint">learning</span>}
                    <span className="ml-auto flex items-center gap-2 text-[12px] text-faint">
                      risk <RiskBadge risk={t.last.risk.risk} />
                    </span>
                  </div>
                  {/* risk per window, oldest to newest */}
                  <div className="mt-2 flex h-8 items-end gap-[3px]" aria-label="risk per window">
                    {t.risk.slice(-40).map((r, i) => (
                      <span
                        key={i}
                        className={cn("w-[6px] rounded-sm", r >= 70 ? "bg-neg" : r >= 45 ? "bg-neg/70" : r >= 20 ? "bg-warn" : "bg-pos")}
                        style={{ height: `${Math.max(8, (r / max) * 100)}%` }}
                        title={`risk ${r}`}
                      />
                    ))}
                  </div>
                  {bad.length > 0 && (
                    <ul className="mt-2 space-y-1 text-[12.5px] text-muted-foreground">
                      {bad.map((a, i) => (
                        <li key={i}><span className={a.severity === "high" ? "text-neg" : "text-warn"}>●</span> {a.message}</li>
                      ))}
                    </ul>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <section className="glass rounded-2xl">
        <div className="border-b border-border px-5 py-3.5">
          <h2 className="text-[14px] font-semibold tracking-tight">Windows</h2>
        </div>
        <ul className="max-h-[320px] divide-y divide-border/60 overflow-y-auto font-mono text-[12px]">
          {windows.map((w) => (
            <li key={w.file} className="flex flex-wrap items-center gap-x-4 px-5 py-2">
              <span className="text-foreground/85">{w.file}</span>
              <span className="text-faint">{ago(now, w.at)}</span>
              {w.ok ? (
                <span className="text-muted-foreground">{w.n_sas} tunnel{w.n_sas === 1 ? "" : "s"} · {w.seconds}s</span>
              ) : (
                <span className="text-neg">{w.error}</span>
              )}
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
