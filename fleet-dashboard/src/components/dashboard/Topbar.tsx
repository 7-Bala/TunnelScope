import { useEffect, useState } from "react"

// Clean geometric mark: a tunnel aperture — concentric rounded squares receding to
// a point, with a scope tick. "Look down the tunnel." Single-weight teal stroke.
function Logo() {
  return (
    <svg viewBox="0 0 32 32" className="h-8 w-8" fill="none" aria-hidden>
      <rect x="3" y="3" width="26" height="26" rx="7" stroke="var(--teal)" strokeWidth="1.6" opacity="0.35" />
      <rect x="8" y="8" width="16" height="16" rx="4.5" stroke="var(--teal)" strokeWidth="1.6" opacity="0.7" />
      <rect x="13" y="13" width="6" height="6" rx="2" fill="var(--teal)" />
    </svg>
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
        <Logo />
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-[17px] font-semibold tracking-tight text-foreground">TunnelScope</h1>
            <span className="rounded-full bg-teal-bg px-2 py-0.5 text-[10px] font-medium text-teal">Fleet</span>
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
