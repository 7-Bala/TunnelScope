import { cn } from "@/lib/utils"

// The wordmark IS the mark — no separate icon. One face, one silver color,
// the full width across "TunnelScope".
function Wordmark() {
  return (
    <h1 className="font-display text-[34px] uppercase leading-none tracking-wide text-silver">
      TunnelScope
    </h1>
  )
}

export type View = "uploads" | "sample"
export type Engine = "checking" | "online" | "offline"

export function Topbar({
  view,
  onView,
  uploadCount,
  sampleCount,
  lastAnalysed,
}: {
  view: View
  onView: (v: View) => void
  uploadCount: number
  sampleCount: number
  lastAnalysed: Date | null
}) {
  const tabs: { key: View; label: string; count: number }[] = [
    { key: "uploads", label: "Your captures", count: uploadCount },
    { key: "sample", label: "Sample fleet", count: sampleCount },
  ]

  return (
    <header className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4 pb-6">
      <div className="flex items-center gap-3">
        <div>
          <Wordmark />
          <p className="mt-1.5 text-[12px] text-muted-foreground">IPsec and post-quantum posture, from the wire</p>
        </div>
      </div>

      <div role="tablist" aria-label="Data shown" className="glass order-3 flex w-full rounded-lg p-1 sm:order-none sm:w-auto">
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
            <span className={cn("font-mono text-[11px] tnum", view === t.key ? "text-violet" : "text-faint")}>{t.count}</span>
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
      </div>
    </header>
  )
}
