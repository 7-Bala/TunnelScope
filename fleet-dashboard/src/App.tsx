import { Topbar } from "@/components/dashboard/Topbar"
import { KpiStrip } from "@/components/dashboard/KpiStrip"
import { SignalTrace } from "@/components/dashboard/SignalTrace"
import { PostureGauge } from "@/components/dashboard/PostureGauge"
import { SeverityBars } from "@/components/dashboard/SeverityBars"
import { FleetRegister } from "@/components/dashboard/FleetRegister"
import { GATEWAYS, fleetStats } from "@/lib/fleet"

function App() {
  const s = fleetStats(GATEWAYS)

  const readouts = [
    { label: "Sources", value: s.total, foot: "captures, no parse errors" },
    { label: "PQ-ready", value: s.counts.pq, tone: "pos" as const, foot: "hybrid ML-KEM" },
    { label: "Downgraded", value: s.counts.downgraded, tone: "warn" as const, foot: "PQ offered, classical used" },
    { label: "Critical", value: s.high, tone: "neg" as const, foot: "high-severity, cited" },
    { label: "CVE-2026-78135", value: s.cve, tone: s.cve ? ("neg" as const) : undefined, foot: s.cve ? "pre-auth Child SA" : "none observed" },
  ]

  return (
    <div className="min-h-screen bg-background text-foreground">
      <main className="mx-auto max-w-[1240px] px-6 pb-20 pt-7">
        <Topbar scanned={s.total} />

        {/* HERO — one bold, honest reading of the fleet, carried by the trace */}
        <section className="rise mb-5" style={{ animationDelay: "40ms" }}>
          <div className="max-w-[46ch]">
            <h2 className="text-[30px] font-semibold leading-[1.12] tracking-[-0.02em] text-foreground sm:text-[38px]">
              {s.vulnerable} of {s.total} tunnels still negotiate classical key exchange.
            </h2>
            <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">
              One was silently downgraded from post-quantum; one carries the CVE-2026-78135 pre-auth
              pattern. Only <span className="text-pos">{s.counts.pq}</span> is hardened with hybrid ML-KEM.
            </p>
          </div>
          <div className="mt-6 h-[168px] w-full">
            <SignalTrace gateways={GATEWAYS} height={168} />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[12px] text-muted-foreground">
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-warn" />classical</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-pos" />post-quantum</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-neg" />downgrade / CVE</span>
            <span className="sm:ml-auto">per-gateway finding load</span>
          </div>
        </section>

        <div className="mb-5">
          <KpiStrip readouts={readouts} />
        </div>

        <div className="grid items-start gap-4 lg:grid-cols-[300px_1fr]">
          <div className="rise flex flex-col gap-4" style={{ animationDelay: "140ms" }}>
            <div className="rounded-2xl border border-border bg-card">
              <div className="border-b border-border px-5 py-3.5">
                <h2 className="text-[14px] font-semibold tracking-tight">Quantum posture</h2>
              </div>
              <PostureGauge counts={s.counts} total={s.total} />
            </div>
            <div className="rounded-2xl border border-border bg-card">
              <div className="border-b border-border px-5 py-3.5">
                <h2 className="text-[14px] font-semibold tracking-tight">Findings by severity</h2>
              </div>
              <SeverityBars high={s.high} medium={s.medium} informational={s.informational} />
            </div>
          </div>

          <FleetRegister gateways={GATEWAYS} />
        </div>

        <footer className="mt-8 flex flex-wrap items-center justify-between gap-4 border-t border-border pt-5 text-[12px] text-muted-foreground">
          <p>
            Absence of evidence is never scored as compliance — every verdict cites{" "}
            <span className="text-foreground/80">baseline · rule</span>.
          </p>
          <p className="text-faint">tunnelscope fleet · shadcn/ui</p>
        </footer>
      </main>
    </div>
  )
}

export default App
