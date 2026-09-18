import { Suspense, lazy, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react"
import { cn } from "@/lib/utils"
import { FADE_MS, LAND_MS, LEAVE_S, WORDMARK_S } from "./timeline"
import { shouldPlayIntro } from "./shouldPlay"
import type { CoreRect } from "./IntroTunnel"

const IntroTunnel = lazy(() => import("./IntroTunnel"))

// if the 3D chunk hasn't drawn a frame by now, don't hold the page hostage
const READY_TIMEOUT_MS = 2500

// Plays on every load; any key or tap skips it. `?intro=hold` stays on the
// final frame until a key or tap, for stills. Decided synchronously (same
// predicate as App) so the dashboard never flashes first.
function holdAtEnd(): boolean {
  try {
    return new URLSearchParams(window.location.search).get("intro") === "hold"
  } catch {
    return false
  }
}

// dark -> running (lights come on, wordmark) -> rushing (into the core) -> cut
// (the core's square lands on the drop zone's mark) -> done. A key or tap skips
// straight to a quick fade (leaving).
type Phase = "dark" | "running" | "rushing" | "cut" | "leaving" | "done"

/** the element the core lands on: the square at the centre of the drop-zone mark */
function landingRect(): CoreRect | null {
  const mark = document.querySelector<HTMLElement>("[data-intro-target]")
  if (!mark) return null
  const r = mark.getBoundingClientRect()
  if (r.bottom <= 0 || r.top >= window.innerHeight) return null // off-screen (small phone)
  // the mark's SVG is 32 units with its solid core at 13..19
  return { left: r.left + (r.width * 13) / 32, top: r.top + (r.height * 13) / 32, size: (r.width * 6) / 32 }
}

/** `onLeave` fires once, the moment the page is revealed (the cut, or a skip,
 *  or if the intro never could play): the page-background tunnel under it then
 *  shows the corridor at rest. */
export function Intro({ onLeave }: { onLeave?: () => void }) {
  const [phase, setPhase] = useState<Phase>(() => (shouldPlayIntro() ? "dark" : "done"))
  const [wordmark, setWordmark] = useState(false)
  const [rushAt, setRushAt] = useState<number | null>(null)
  const [core, setCore] = useState<CoreRect | null>(null)
  const proxyRef = useRef<HTMLDivElement>(null)
  const timers = useRef<number[]>([])

  const leave = useCallback(() => {
    setPhase((p) => (p === "done" || p === "leaving" ? p : p === "cut" ? "done" : "leaving"))
  }, [])

  const rush = useCallback(() => {
    setWordmark(false)
    setRushAt(performance.now())
    setPhase((p) => (p === "running" ? "rushing" : p))
  }, [])

  const onCut = useCallback((c: CoreRect) => {
    setCore(c)
    setPhase((p) => (p === "rushing" ? "cut" : p))
  }, [])

  const onReady = useCallback(() => {
    setPhase("running")
    timers.current.push(
      window.setTimeout(() => setWordmark(true), WORDMARK_S * 1000),
      ...(holdAtEnd() ? [] : [window.setTimeout(rush, LEAVE_S * 1000)]),
    )
  }, [rush])

  const onUnsupported = useCallback(() => setPhase("done"), [])

  const left = useRef(false)
  useEffect(() => {
    if ((phase === "cut" || phase === "leaving" || phase === "done") && !left.current) {
      left.current = true
      onLeave?.()
    }
  }, [phase, onLeave])

  // leaving -> done once the fade has played
  useEffect(() => {
    if (phase !== "leaving") return
    const t = window.setTimeout(() => setPhase("done"), FADE_MS)
    return () => clearTimeout(t)
  }, [phase])

  // the landing: the core's square flies from where the core was to the
  // drop-zone mark and hands over to it; if there's no mark on screen it just
  // shrinks away where it is
  useLayoutEffect(() => {
    if (phase !== "cut" || !core || !proxyRef.current) return
    const el = proxyRef.current
    const to = landingRect()
    const from = { left: core.left, top: core.top, width: core.size, height: core.size, borderRadius: core.size * 0.31 }
    const end = to
      ? { left: to.left, top: to.top, width: to.size, height: to.size, borderRadius: to.size * 0.33 }
      : { left: core.left + core.size / 2, top: core.top + core.size / 2, width: 0, height: 0, borderRadius: 0 }
    const px = (o: typeof from) => ({ left: `${o.left}px`, top: `${o.top}px`, width: `${o.width}px`,
      height: `${o.height}px`, borderRadius: `${o.borderRadius}px` })
    const fly = el.animate([{ ...px(from), boxShadow: "0 0 80px 24px rgb(139 92 246 / .55)" },
                            { ...px(end), boxShadow: "0 0 0 0 rgb(139 92 246 / 0)" }],
      { duration: LAND_MS, easing: "cubic-bezier(.2,.8,.2,1)", fill: "forwards" })
    fly.onfinish = () => {
      const out = el.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 160, fill: "forwards" })
      out.onfinish = () => setPhase("done")
    }
    return () => fly.cancel()
  }, [phase, core])

  // a stuck chunk load never blocks the page
  useEffect(() => {
    if (phase !== "dark") return
    const t = window.setTimeout(() => setPhase("done"), READY_TIMEOUT_MS)
    return () => clearTimeout(t)
  }, [phase])

  // any key, click or touch skips; the page underneath can't scroll meanwhile.
  // Released at the cut: the page is live while the core's square lands.
  useEffect(() => {
    if (phase === "done" || phase === "cut") return
    const skip = () => leave()
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

  if (phase === "cut") {
    // the page is already showing; only the core's square is left, in flight
    return (
      <div
        ref={proxyRef}
        aria-hidden
        className="pointer-events-none fixed z-50 bg-violet"
        style={core ? { left: core.left, top: core.top, width: core.size, height: core.size } : undefined}
      />
    )
  }

  return (
    <div
      role="presentation"
      className="fixed inset-0 z-50 bg-background transition-opacity ease-out"
      style={{ opacity: phase === "leaving" ? 0 : 1, transitionDuration: `${FADE_MS}ms` }}
    >
      <Suspense fallback={null}>
        <IntroTunnel onReady={onReady} onUnsupported={onUnsupported} rushAt={rushAt} onCut={onCut} />
      </Suspense>

      <div className="pointer-events-none absolute inset-x-0 bottom-[16%] isolate flex flex-col items-center px-4 text-center">
        {/* a pool of dark behind the words so the lit rings never cut through the letters */}
        <div
          aria-hidden
          className={cn("absolute left-1/2 top-1/2 -z-10 h-[190px] w-[min(640px,92vw)] -translate-x-1/2 -translate-y-1/2 transition-opacity",
            wordmark ? "opacity-100 duration-700" : "opacity-0 duration-200")}
          style={{ background: "radial-gradient(closest-side, var(--background) 55%, transparent)" }}
        />
        <div
          className={cn(
            "font-display text-[40px] uppercase leading-none tracking-[0.08em] text-silver transition-all ease-out sm:text-[56px]",
            wordmark ? "opacity-100 blur-0 duration-700" : "translate-y-1 opacity-0 blur-sm duration-200",
          )}
        >
          TunnelScope
        </div>
        <p
          className={cn(
            "mt-3 text-[13px] text-muted-foreground transition-opacity",
            wordmark ? "opacity-100 delay-200 duration-700" : "opacity-0 duration-200",
          )}
        >
          IPsec and post-quantum posture, from the wire
        </p>
      </div>

      <p
        className={cn("absolute bottom-5 right-5 text-[11.5px] text-faint transition-opacity duration-200",
          phase === "rushing" && "opacity-0")}
      >
        Press any key or tap to skip
      </p>
    </div>
  )
}
