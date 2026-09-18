import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"
import { FADE_MS, LEAVE_S, WORDMARK_S } from "./timeline"

const IntroTunnel = lazy(() => import("./IntroTunnel"))

const SEEN_KEY = "tunnelscope.intro.seen"
// if the 3D chunk hasn't drawn a frame by now, don't hold the page hostage
const READY_TIMEOUT_MS = 2500

// First visit only; `?intro` forces it (demo recording, testing) and
// `?intro=hold` also stays on the final frame until a key or tap, for stills.
// Never under reduced motion. Decided synchronously so the dashboard never flashes first.
function shouldPlay(): boolean {
  try {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return false
    if (new URLSearchParams(window.location.search).has("intro")) return true
    return window.localStorage.getItem(SEEN_KEY) !== "1"
  } catch {
    return false // storage blocked: skipping is safer than replaying every load
  }
}

function markSeen() {
  try {
    window.localStorage.setItem(SEEN_KEY, "1")
  } catch {
    /* private mode / blocked storage: it just plays again next time */
  }
}

function holdAtEnd(): boolean {
  try {
    return new URLSearchParams(window.location.search).get("intro") === "hold"
  } catch {
    return false
  }
}

type Phase = "dark" | "running" | "leaving" | "done"

export function Intro() {
  const [phase, setPhase] = useState<Phase>(() => (shouldPlay() ? "dark" : "done"))
  const [wordmark, setWordmark] = useState(false)
  const timers = useRef<number[]>([])

  const leave = useCallback(() => {
    setPhase((p) => (p === "done" || p === "leaving" ? p : "leaving"))
  }, [])

  const onReady = useCallback(() => {
    markSeen()
    setPhase("running")
    timers.current.push(
      window.setTimeout(() => setWordmark(true), WORDMARK_S * 1000),
      ...(holdAtEnd() ? [] : [window.setTimeout(leave, LEAVE_S * 1000)]),
    )
  }, [leave])

  const onUnsupported = useCallback(() => setPhase("done"), [])

  // leaving -> done once the fade has played
  useEffect(() => {
    if (phase !== "leaving") return
    const t = window.setTimeout(() => setPhase("done"), FADE_MS)
    return () => clearTimeout(t)
  }, [phase])

  // a stuck chunk load never blocks the page
  useEffect(() => {
    if (phase !== "dark") return
    const t = window.setTimeout(() => setPhase("done"), READY_TIMEOUT_MS)
    return () => clearTimeout(t)
  }, [phase])

  // any key, click or touch skips; the page underneath can't scroll meanwhile
  useEffect(() => {
    if (phase === "done") return
    const skip = () => {
      markSeen()
      leave()
    }
    window.addEventListener("keydown", skip)
    window.addEventListener("pointerdown", skip)
    const overflow = document.body.style.overflow
    document.body.style.overflow = "hidden"
    return () => {
      window.removeEventListener("keydown", skip)
      window.removeEventListener("pointerdown", skip)
      document.body.style.overflow = overflow
    }
  }, [phase, leave])

  useEffect(() => () => timers.current.forEach(clearTimeout), [])

  if (phase === "done") return null

  return (
    <div
      role="presentation"
      className="fixed inset-0 z-50 bg-background transition-opacity ease-out"
      style={{ opacity: phase === "leaving" ? 0 : 1, transitionDuration: `${FADE_MS}ms` }}
    >
      <Suspense fallback={null}>
        <IntroTunnel onReady={onReady} onUnsupported={onUnsupported} />
      </Suspense>

      <div className="pointer-events-none absolute inset-x-0 bottom-[16%] isolate flex flex-col items-center px-4 text-center">
        {/* a pool of dark behind the words so the lit rings never cut through the letters */}
        <div
          aria-hidden
          className={cn("absolute left-1/2 top-1/2 -z-10 h-[190px] w-[min(640px,92vw)] -translate-x-1/2 -translate-y-1/2 transition-opacity duration-700",
            wordmark ? "opacity-100" : "opacity-0")}
          style={{ background: "radial-gradient(closest-side, var(--background) 55%, transparent)" }}
        />
        <div
          className={cn(
            "font-display text-[40px] uppercase leading-none tracking-[0.08em] text-silver transition-all duration-700 ease-out sm:text-[56px]",
            wordmark ? "opacity-100 blur-0" : "translate-y-1 opacity-0 blur-sm",
          )}
        >
          TunnelScope
        </div>
        <p
          className={cn(
            "mt-3 text-[13px] text-muted-foreground transition-opacity delay-200 duration-700",
            wordmark ? "opacity-100" : "opacity-0",
          )}
        >
          IPsec and post-quantum posture, from the wire
        </p>
      </div>

      <p className="absolute bottom-5 right-5 text-[11.5px] text-faint">Press any key or tap to skip</p>
    </div>
  )
}
