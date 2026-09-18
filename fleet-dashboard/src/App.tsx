import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Topbar, type Engine, type View } from "@/components/dashboard/Topbar"
import { KpiStrip } from "@/components/dashboard/KpiStrip"
import { SignalTrace } from "@/components/dashboard/SignalTrace"
import { PostureGauge } from "@/components/dashboard/PostureGauge"
import { SeverityBars } from "@/components/dashboard/SeverityBars"
import { FleetRegister } from "@/components/dashboard/FleetRegister"
import { Intake, type QueueItem } from "@/components/dashboard/Intake"
import type { TunnelState } from "@/components/tunnel/BackgroundTunnel"
import { GATEWAYS, fleetStats, headline, postureKind, toGateway, type Gateway } from "@/lib/fleet"
import { analyzeCapture, engineHealth, ENGINE_OFFLINE } from "@/lib/api"
import { Intro } from "@/components/intro/Intro"
import { cn } from "@/lib/utils"
import { shouldPlayIntro } from "@/components/intro/shouldPlay"

const BackgroundTunnel = lazy(() => import("@/components/tunnel/BackgroundTunnel"))

let seq = 0
const MAGIC = new Set(["d4c3b2a1", "a1b2c3d4", "4d3cb2a1", "a1b23c4d", "0a0d0d0a"])

async function looksLikeCapture(file: File) {
  const head = new Uint8Array(await file.slice(0, 4).arrayBuffer())
  return MAGIC.has(Array.from(head, (b) => b.toString(16).padStart(2, "0")).join(""))
}

function worstKind(gs: Gateway[]): TunnelState {
  if (gs.some((g) => g.fails.some((f) => f.severity === "high") || postureKind(g.posture) === "downgraded")) return "neg"
  if (gs.length && gs.every((g) => postureKind(g.posture) === "pq")) return "pos"
  return "warn"
}

function App() {
  const [view, setView] = useState<View>("uploads")
  const [queue, setQueue] = useState<QueueItem[]>([])
  const [results, setResults] = useState<Record<string, Gateway[]>>({})
  const [engine, setEngine] = useState<Engine>("checking")
  const [dragging, setDragging] = useState(false)
  const [flash, setFlash] = useState<TunnelState | null>(null)
  // the background tunnel holds the intro's lit frame until the intro leaves
  const [introLit, setIntroLit] = useState(shouldPlayIntro)
  const [introPlayed] = useState(shouldPlayIntro)
  const onIntroLeave = useCallback(() => setIntroLit(false), [])
  const [lastAnalysed, setLastAnalysed] = useState<Date | null>(null)
  const working = useRef(false)
  const dragDepth = useRef(0)

  useEffect(() => {
    engineHealth().then((ok) => setEngine(ok ? "online" : "offline"))
  }, [])

  // Captures are analysed one at a time, in the order they were added.
  useEffect(() => {
    if (working.current) return
    const next = queue.find((q) => q.status === "queued")
    if (!next) return
    working.current = true
    setQueue((q) => q.map((x) => (x.key === next.key ? { ...x, status: "analysing" } : x)))
    ;(async () => {
      let patch: Partial<QueueItem>
      let landed: Gateway[] = []
      if (!(await looksLikeCapture(next.file))) {
        patch = { status: "error", error: "Not a pcap or pcapng capture, so it was not sent to the engine." }
      } else {
        const res = await analyzeCapture(next.file)
        if (res.ok) {
          landed = res.sas.map((sa, i) => toGateway(sa, i, res.sas.length))
          setResults((r) => ({ ...r, [next.key]: landed }))
          setEngine("online")
          setLastAnalysed(new Date())
          const high = landed.reduce((n, g) => n + g.fails.filter((f) => f.severity === "high").length, 0)
          patch = res.sas.length
            ? { status: "done", nSas: res.sas.length, high }
            : { status: "error", error: "No IKE or ESP traffic found in this capture." }
        } else {
          if (res.error === ENGINE_OFFLINE) setEngine("offline")
          patch = { status: "error", error: res.error }
        }
      }
      setQueue((q) => q.map((x) => (x.key === next.key ? { ...x, ...patch } : x)))
      setFlash(patch.status === "done" ? worstKind(landed) : "error")
      working.current = false
    })()
  }, [queue])

  useEffect(() => {
    if (!flash) return
    const t = setTimeout(() => setFlash(null), 2400)
    return () => clearTimeout(t)
  }, [flash])

  const addFiles = useCallback((files: File[]) => {
    if (!files.length) return
    setView("uploads")
    setQueue((q) => [...q, ...files.map((file) => ({ key: `f${++seq}`, file, status: "queued" as const }))])
  }, [])

  // Accept a drop anywhere on the page, and stop the browser opening the file.
  useEffect(() => {
    const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes("Files")
    const enter = (e: DragEvent) => {
      if (!hasFiles(e)) return
      e.preventDefault()
      dragDepth.current++
      setDragging(true)
    }
    const over = (e: DragEvent) => {
      if (hasFiles(e)) e.preventDefault()
    }
    const leave = (e: DragEvent) => {
      if (!hasFiles(e)) return
      dragDepth.current = Math.max(0, dragDepth.current - 1)
      if (dragDepth.current === 0) setDragging(false)
    }
    const drop = (e: DragEvent) => {
      if (!hasFiles(e)) return
      e.preventDefault()
      dragDepth.current = 0
      setDragging(false)
      addFiles(Array.from(e.dataTransfer?.files ?? []))
    }
    window.addEventListener("dragenter", enter)
    window.addEventListener("dragover", over)
    window.addEventListener("dragleave", leave)
    window.addEventListener("drop", drop)
    return () => {
      window.removeEventListener("dragenter", enter)
      window.removeEventListener("dragover", over)
      window.removeEventListener("dragleave", leave)
      window.removeEventListener("drop", drop)
    }
  }, [addFiles])

  const uploads = useMemo(() => queue.flatMap((q) => results[q.key] ?? []), [queue, results])
  const gateways = view === "sample" ? GATEWAYS : uploads
  const s = fleetStats(gateways)
  const busy = queue.some((q) => q.status === "queued" || q.status === "analysing")
  const tunnel: TunnelState = dragging ? "over" : busy ? "busy" : (flash ?? "idle")

  const retry = (key: string) => setQueue((q) => q.map((x) => (x.key === key ? { ...x, status: "queued", error: undefined } : x)))
  const remove = (key: string) => {
    setQueue((q) => q.filter((x) => x.key !== key))
    setResults((r) => {
      const next = { ...r }
      delete next[key]
      return next
    })
  }
  const clear = () => {
    setQueue((q) => q.filter((x) => x.status === "queued" || x.status === "analysing"))
    setResults({})
  }

  const readouts = [
    { label: view === "sample" ? "Gateways" : "Tunnels", value: s.total, foot: view === "sample" ? "lab captures" : "security associations" },
    { label: "PQ-ready", value: s.counts.pq, tone: "pos" as const, foot: "hybrid ML-KEM selected" },
    { label: "PQ not selected", value: s.counts.downgraded, tone: s.counts.downgraded ? ("warn" as const) : undefined, foot: "PQ offered, classical used" },
    { label: "High severity", value: s.high, tone: s.high ? ("neg" as const) : undefined, foot: "failed checks, each cited" },
    { label: "CVE-2026-78135", value: s.cve, tone: s.cve ? ("neg" as const) : undefined, foot: s.cve ? "pre-auth Child SA attempt" : "pattern not seen" },
  ]
  const h = s.total ? headline(s) : null

  return (
    <div className="relative isolate min-h-[100dvh] bg-background text-foreground">
      <Intro onLeave={onIntroLeave} />
      {/* the intro's corridor, dimmed, behind the top of the page only: it fades
          toward the bottom of the screen and as the page scrolls */}
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-0"
        style={{
          maskImage: "linear-gradient(to bottom, #000 0%, #000 34%, transparent 80%)",
          WebkitMaskImage: "linear-gradient(to bottom, #000 0%, #000 34%, transparent 80%)",
        }}
      >
        <Suspense fallback={null}>
          <BackgroundTunnel state={tunnel} lit={introLit} className="absolute inset-0" />
        </Suspense>
        <div
          className="absolute inset-0"
          style={{ background: "radial-gradient(ellipse 80% 70% at 50% 34%, transparent 50%, var(--background) 100%)" }}
        />
      </div>
      <main className={cn("relative z-10 mx-auto max-w-[1240px] px-4 pb-20 pt-6 sm:px-6", introPlayed && !introLit && "page-enter")}>
        <Topbar
          view={view}
          onView={setView}
          uploadCount={uploads.length}
          sampleCount={GATEWAYS.length}
          lastAnalysed={lastAnalysed}
        />

        {engine === "offline" && (
          <div role="status" className="mb-4 rounded-2xl border border-neg/30 bg-neg-bg px-4 py-3 text-[13px] text-foreground/90">
            The analysis engine isn't reachable. Run{" "}
            <code className="rounded bg-background/60 px-1.5 py-0.5 font-mono text-[12px] text-foreground">tunnelscope serve</code>{" "}
            and reload this page. The sample fleet still works without it.
          </div>
        )}

        <div className="mb-8">
          <Intake
            queue={queue}
            tunnel={tunnel}
            dragging={dragging}
            compact={gateways.length > 0}
            onFiles={addFiles}
            onRetry={retry}
            onRemove={remove}
            onClear={clear}
          />
        </div>

        {view === "sample" && (
          <p className="mb-5 max-w-[80ch] text-[12.5px] leading-relaxed text-faint">
            Sample fleet: 10 captures from the TunnelScope lab testbed, run through <code className="font-mono">tunnelscope fleet</code>.
            Gateway names are illustrative; the findings are real output for those captures.
          </p>
        )}

        {h ? (
          <>
            <section className="mb-5">
              <div className="max-w-[52ch]">
                <h2 className="text-[26px] font-semibold leading-[1.15] tracking-[-0.02em] text-foreground sm:text-[32px]">{h.title}</h2>
                <p className="mt-3 text-[15px] leading-relaxed text-muted-foreground">{h.detail}</p>
              </div>
              {gateways.length > 1 && (
                <>
                  <div className="mt-6 h-[150px] w-full">
                    <SignalTrace gateways={gateways} height={150} />
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-1 text-[12px] text-muted-foreground">
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-warn" />classical</span>
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-pos" />post-quantum</span>
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-neg" />PQ not selected / CVE</span>
                    <span className="sm:ml-auto">weighted failed checks per tunnel</span>
                  </div>
                </>
              )}
            </section>

            <div className="mb-5">
              <KpiStrip readouts={readouts} />
            </div>

            <div className="grid items-start gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
              <div className="flex flex-col gap-4">
                <div className="glass rounded-2xl">
                  <div className="border-b border-border px-5 py-3.5">
                    <h2 className="text-[14px] font-semibold tracking-tight">Quantum posture</h2>
                  </div>
                  <PostureGauge counts={s.counts} total={s.total} />
                </div>
                <div className="glass rounded-2xl">
                  <div className="border-b border-border px-5 py-3.5">
                    <h2 className="text-[14px] font-semibold tracking-tight">Failed checks by severity</h2>
                  </div>
                  <SeverityBars high={s.high} medium={s.medium} informational={s.informational} />
                </div>
              </div>

              <FleetRegister gateways={gateways} title={view === "sample" ? "Sample fleet register" : "Analysed captures"} />
            </div>
          </>
        ) : (
          view === "uploads" && (
            <section className="rounded-xl border border-dashed border-border px-6 py-10 text-center">
              <h2 className="text-[16px] font-semibold text-foreground">No captures analysed yet</h2>
              <p className="mx-auto mt-2 max-w-[56ch] text-[13.5px] leading-relaxed text-muted-foreground">
                Posture, failed checks and the evidence behind each verdict appear here once a capture is analysed. To see what
                a result looks like first, open the{" "}
                <button type="button" onClick={() => setView("sample")} className="font-medium text-violet underline-offset-4 hover:underline">
                  sample fleet
                </button>
                .
              </p>
            </section>
          )
        )}

        <footer className="mt-10 flex flex-wrap items-center justify-between gap-4 border-t border-border pt-5 text-[12px] text-muted-foreground">
          <p className="max-w-[70ch]">
            Absence of evidence is never scored as compliance. Every verdict cites its baseline and rule, and anything this
            vantage cannot see is labelled as such.
          </p>
          <p className="text-faint">TunnelScope · local engine on 127.0.0.1</p>
        </footer>
      </main>
    </div>
  )
}

export default App
