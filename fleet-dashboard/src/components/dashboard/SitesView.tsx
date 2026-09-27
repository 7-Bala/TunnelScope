import { useEffect, useState } from "react"
import { cn } from "@/lib/utils"
import { type SitesResult, sitesStatus } from "@/lib/api"

function fmt(v: unknown) {
  if (v === null || v === undefined) return "none"
  return Array.isArray(v) ? v.join(", ") : String(v)
}

function ago(s: number) {
  const r = Math.max(0, Math.round(s))
  return r < 60 ? `${r}s ago` : r < 3600 ? `${Math.round(r / 60)} min ago` : `${Math.round(r / 3600)} h ago`
}

/** Sites (T-139): each site's sensor sends signed findings, never captures. A site that stops reporting is shown
 * as stale with posture UNKNOWN, never with its last posture. Polls /api/sites. */
export function SitesView() {
  const [st, setSt] = useState<SitesResult | null>(null)
  useEffect(() => {
    let on = true
    const poll = async () => {
      const s = await sitesStatus()
      if (on) setSt(s)
    }
    poll()
    const a = setInterval(poll, 5000)
    return () => {
      on = false
      clearInterval(a)
    }
  }, [])

  if (!st) return <p className="text-[13px] text-muted-foreground">Checking the engine…</p>
  if (!st.enabled)
    return (
      <section className="glass rounded-2xl px-6 py-8">
        <h2 className="text-[16px] font-semibold">No site collector configured</h2>
        <p className="mt-2 max-w-[70ch] text-[13px] leading-relaxed text-muted-foreground">
          A sensor at each site analyses its own traffic and sends only signed findings (never captures) as files. The
          collector here checks each report and keeps every site's latest state:
        </p>
        <pre className="mt-3 overflow-x-auto rounded-lg bg-background/60 px-4 py-3 font-mono text-[12px] text-foreground/85">
{`tunnelscope sensor-key --site delhi-dc1 --out keys/          # once per site; copy the key to that site
tunnelscope sensor --site delhi-dc1 --key delhi-dc1.key --interface eth1 --outbox out/ --state st/   # at the site
tunnelscope collect --inbox inbox/ --state collector/ --keys keys/ --alerts alerts.jsonl           # here
TUNNELSCOPE_COLLECTOR_STATE=collector/ ./start.sh`}
        </pre>
      </section>
    )

  const sites = st.sites ?? []
  const stale = sites.filter((s) => s.status === "stale").length
  return (
    <div className="space-y-4">
      <section className="glass flex flex-wrap items-center gap-x-8 gap-y-2 rounded-2xl px-5 py-4 text-[12.5px]">
        <span className="font-medium text-foreground">{sites.length} site{sites.length === 1 ? "" : "s"}</span>
        <span className="text-muted-foreground">
          Reporting: <span className="font-mono text-foreground/85 tnum">{sites.length - stale}</span>
        </span>
        <span className={cn("text-muted-foreground", stale && "text-warn")}>
          Stale: <span className="font-mono tnum">{stale}</span>
        </span>
        <span className="text-faint">
          stale = no report for {st.stale_after_windows ?? 3} of the site's windows; its posture is then unknown
        </span>
      </section>

      {sites.length === 0 ? (
        <p className="glass rounded-2xl px-5 py-6 text-[13px] text-muted-foreground">No site has reported yet.</p>
      ) : (
        sites.map((s) => (
          <section key={s.site} className="glass rounded-2xl">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-5 py-3.5">
              <span className={cn("h-2 w-2 rounded-full", s.status === "stale" ? "bg-warn" : "bg-pos")} />
              <h2 className="text-[14px] font-semibold tracking-tight">{s.site}</h2>
              <span className={cn("rounded-full px-2 py-px text-[10.5px] font-medium",
                s.status === "stale" ? "bg-warn/15 text-warn" : "bg-pos/15 text-pos")}>
                {s.status === "stale" ? "stale" : "reporting"}
              </span>
              <span className="ml-auto text-[12px] text-faint">
                last report {ago(s.age_s)} · {s.reports ?? 0} reports
                {s.missing_reports > 0 && <span className="text-warn"> · {s.missing_reports} missing</span>}
              </span>
            </div>
            {(s.recent_alerts ?? []).length > 0 && (
              <ul className="space-y-1 border-b border-border/60 px-5 py-3 text-[12.5px]">
                {(s.recent_alerts ?? []).map((a, i) => (
                  <li key={i} className="text-muted-foreground">
                    <span className="text-neg">●</span>{" "}
                    <span className="font-medium text-neg">{a.kind === "downgrade" ? "Downgrade" : "New failure"}</span>{" "}
                    of {a.attribute} on <span className="font-mono">{a.tunnel}</span>: {fmt(a.usual)} → {fmt(a.now)}
                    <span className="ml-2 text-[11px] text-faint">{ago(a.age_s)}</span>
                  </li>
                ))}
              </ul>
            )}
            {s.note ? (
              <p className="px-5 py-4 text-[13px] text-warn">{s.note}</p>
            ) : s.tunnels.length === 0 ? (
              <p className="px-5 py-4 text-[13px] text-muted-foreground">No IPsec traffic in the last window.</p>
            ) : (
              <ul className="divide-y divide-border/60">
                {s.tunnels.map((t) => (
                  <li key={`${t.src}-${t.dst}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3 text-[12.5px]">
                    <span className="font-mono text-foreground/90">{t.src} ↔ {t.dst}</span>
                    <span className="text-muted-foreground">
                      {t.posture}
                      {t.last_handshake && t.last_handshake.posture !== t.posture && (
                        <span className="ml-2 text-faint">
                          · last handshake seen {ago(t.last_handshake.age_s)}: <span className="text-foreground/85">{t.last_handshake.posture}</span>
                        </span>
                      )}
                    </span>
                    <span className={cn("ml-auto", t.fails.length ? "text-neg" : "text-faint")}>
                      {t.fails.length ? `failing ${t.fails.join(", ")}` : "no failing rule"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ))
      )}
    </div>
  )
}
