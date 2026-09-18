import { cn } from "@/lib/utils"

// Clean geometric mark: a tunnel aperture — concentric rounded squares receding to
// a point. "Look down the tunnel." Single-weight teal stroke.
function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="h-8 w-8" fill="none" aria-hidden>
      <rect x="3" y="3" width="26" height="26" rx="7" stroke="var(--teal)" strokeWidth="1.6" opacity="0.35" />
      <rect x="8" y="8" width="16" height="16" rx="4.5" stroke="var(--teal)" strokeWidth="1.6" opacity="0.7" />
      <rect x="13" y="13" width="6" height="6" rx="2" fill="var(--teal)" />
    </svg>
  )
}

export type View = "uploads" | "sample"
export type Engine = "checking" | "online" | "offline"

const ENGINE_LABEL: Record<Engine, string> = {
  checking: "Checking engine",
  online: "Engine on 127.0.0.1",
  offline: "Engine offline",
}

export function Topbar({
  view,
  onView,
  uploadCount,
  sampleCount,
  engine,
  lastAnalysed,
}: {
  view: View
  onView: (v: View) => void
  uploadCount: number
  sampleCount: number
  engine: Engine
  lastAnalysed: Date | null
}) {
  const tabs: { key: View; label: string; count: number }[] = [
    { key: "uploads", label: "Your captures", count: uploadCount },
    { key: "sample", label: "Sample fleet", count: sampleCount },
  ]

  return (
    <header className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4 pb-6">
      <div className="flex items-center gap-3">
        <Logo />
        <div>
          <h1 className="text-[17px] font-semibold tracking-tight text-foreground">TunnelScope</h1>
          <p className="mt-0.5 text-[12px] text-muted-foreground">IPsec and post-quantum posture, from the wire</p>
        </div>
      </div>

      <div role="tablist" aria-label="Data shown" className="order-3 flex w-full rounded-lg border border-border bg-card p-1 sm:order-none sm:w-auto">
        {tabs.map((t) => (
          <button
            key={t.key}
            role="tab"
            type="button"
            aria-selected={view === t.key}
            onClick={() => onView(t.key)}
            className={cn(
              "tactile flex flex-1 items-center justify-center gap-2 rounded-md px-3.5 py-1.5 text-[13px] font-medium transition-colors sm:flex-none",
              view === t.key ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
            <span className={cn("font-mono text-[11px] tnum", view === t.key ? "text-teal" : "text-faint")}>{t.count}</span>
          </button>
        ))}
      </div>

      <div className="flex items-center gap-5">
        {lastAnalysed && (
          <div className="hidden text-right md:block">
            <div className="font-mono text-[12px] text-foreground/80 tnum">
              {lastAnalysed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
            </div>
            <div className="text-[11px] text-muted-foreground">last analysis</div>
          </div>
        )}
        <div
          className="flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1.5"
          title={engine === "offline" ? "Start it with: tunnelscope serve" : undefined}
        >
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              engine === "online" && "bg-pos",
              engine === "offline" && "bg-neg",
              engine === "checking" && "bg-faint soft-blink",
            )}
          />
          <span className="text-[12px] text-muted-foreground">{ENGINE_LABEL[engine]}</span>
        </div>
      </div>
    </header>
  )
}
