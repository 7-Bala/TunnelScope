import { useEffect, useState } from "react"

// The wordmark IS the mark — no separate icon. "Tunnel" in the UI sans,
// "Scope" in the display face for a distinct, legible lockup at 17px.
function Wordmark() {
  return (
    <h1 className="flex items-baseline text-[17px] leading-none tracking-tight text-foreground">
      <span className="font-semibold">Tunnel</span>
      <span className="font-display text-[15px] font-normal text-violet">Scope</span>
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
            <span className="rounded-full bg-violet-bg px-2 py-0.5 text-[10px] font-medium text-violet">Fleet</span>
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
