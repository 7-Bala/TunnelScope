import { useEffect, useState } from "react"

// The wordmark IS the mark — no separate icon. One face, one silver color,
// the full width across "TunnelScope".
function Wordmark() {
  return (
    <h1 className="font-display text-[34px] uppercase leading-none tracking-wide text-silver">
      TunnelScope
    </h1>
  )
}

export function Topbar({ scanned }: { scanned: number }) {
  const [time, setTime] = useState("")
  useEffect(() => {
    setTime(new Date().toISOString().replace("T", " ").slice(0, 16))
  }, [])

  return (
    <header className="rise flex flex-wrap items-center justify-between gap-4 pb-6">
      <div className="flex items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Wordmark />
          </div>
          <p className="mt-0.5 text-[12px] text-muted-foreground">IPsec and post-quantum posture across the fleet</p>
        </div>
      </div>

      <div className="flex items-center gap-5">
        <div className="hidden text-right sm:block">
          <div className="font-mono text-[12px] text-foreground/80 tnum">{time}</div>
          <div className="text-[11px] text-muted-foreground">last scan</div>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-border bg-card px-3 py-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-pos" style={{ animation: "soft-blink 2.4s ease-in-out infinite" }} />
          <span className="text-[12px] text-muted-foreground">
            <span className="text-foreground/85">{scanned}</span> live sources
          </span>
        </div>
      </div>
    </header>
  )
}
