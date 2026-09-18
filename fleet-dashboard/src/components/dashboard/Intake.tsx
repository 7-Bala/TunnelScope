import { useRef } from "react"
import { AlertCircle, CheckCircle2, FileUp, RotateCcw, X } from "lucide-react"
import { cn } from "@/lib/utils"
import type { TunnelState } from "../tunnel/BackgroundTunnel"

export type QueueStatus = "queued" | "analysing" | "done" | "error"
export interface QueueItem {
  key: string
  file: File
  status: QueueStatus
  error?: string
  nSas?: number
  high?: number
}

const ACCEPT = ".pcap,.pcapng,.cap"

function Mark({ className }: { className?: string }) {
  // the TunnelScope mark; the lit tunnel itself is now the page background
  return (
    <div className={className}>
      <svg viewBox="0 0 32 32" className="h-full w-full" fill="none" aria-hidden>
        <rect x="3" y="3" width="26" height="26" rx="7" stroke="var(--violet)" strokeWidth="0.8" opacity="0.35" />
        <rect x="8" y="8" width="16" height="16" rx="4.5" stroke="var(--violet)" strokeWidth="0.8" opacity="0.7" />
        <rect x="13" y="13" width="6" height="6" rx="2" fill="var(--violet)" />
      </svg>
    </div>
  )
}

function bytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

function QueueRow({ item, onRetry, onRemove }: { item: QueueItem; onRetry: () => void; onRemove: () => void }) {
  return (
    <li className="queue-enter flex items-start gap-3 py-2.5">
      <span className="mt-0.5 shrink-0">
        {item.status === "done" && <CheckCircle2 className="h-4 w-4 text-pos" strokeWidth={1.75} />}
        {item.status === "error" && <AlertCircle className="h-4 w-4 text-neg" strokeWidth={1.75} />}
        {(item.status === "queued" || item.status === "analysing") && (
          <span className={cn("block h-4 w-4 rounded-full border border-border", item.status === "analysing" && "spin-arc")} />
        )}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="truncate text-[13px] font-medium text-foreground">{item.file.name}</span>
          <span className="shrink-0 font-mono text-[11px] text-faint tnum">{bytes(item.file.size)}</span>
        </div>
        {item.status === "queued" && <p className="mt-0.5 text-[12px] text-muted-foreground">Waiting</p>}
        {item.status === "analysing" && (
          <div className="mt-1.5 h-1 w-40 overflow-hidden rounded-full bg-secondary">
            <div className="shimmer h-full w-full" />
          </div>
        )}
        {item.status === "done" && (
          <p className="mt-0.5 text-[12px] text-muted-foreground">
            {item.nSas} security association{item.nSas === 1 ? "" : "s"}
            {item.high ? <span className="text-neg"> · {item.high} high</span> : <span> · no high-severity findings</span>}
          </p>
        )}
        {item.status === "error" && <p className="mt-0.5 text-[12px] leading-snug text-neg/90">{item.error}</p>}
      </div>
      {item.status === "error" && (
        <button
          type="button"
          onClick={onRetry}
          className="tactile flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-[12px] text-muted-foreground hover:bg-secondary hover:text-foreground"
        >
          <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.75} /> Retry
        </button>
      )}
      {(item.status === "done" || item.status === "error") && (
        <button
          type="button"
          onClick={onRemove}
          aria-label={`Remove ${item.file.name}`}
          className="tactile shrink-0 rounded-md p-1 text-faint hover:bg-secondary hover:text-foreground"
        >
          <X className="h-3.5 w-3.5" strokeWidth={1.75} />
        </button>
      )}
    </li>
  )
}

export function Intake({
  queue,
  tunnel,
  dragging,
  compact,
  onFiles,
  onRetry,
  onRemove,
  onClear,
}: {
  queue: QueueItem[]
  tunnel: TunnelState
  dragging: boolean
  compact: boolean
  onFiles: (files: File[]) => void
  onRetry: (key: string) => void
  onRemove: (key: string) => void
  onClear: () => void
}) {
  const inputRef = useRef<HTMLInputElement>(null)
  const busy = queue.some((q) => q.status === "queued" || q.status === "analysing")
  const done = queue.filter((q) => q.status === "done").length
  const failed = queue.filter((q) => q.status === "error").length
  const finished = done + failed

  return (
    <section
      aria-label="Analyse captures"
      className={cn(
        // frosted, so the background corridor glows softly through the panel
        "relative grid overflow-hidden rounded-xl border bg-card/75 backdrop-blur-md transition-[border-color,background-color] duration-200 md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]",
        dragging ? "border-violet/70 bg-violet-bg" : "border-border",
      )}
    >
      <div className="flex flex-col p-6 sm:p-7">
        <h2 className="text-[20px] font-semibold leading-tight tracking-[-0.02em] text-foreground">
          {dragging ? "Release to analyse" : "Analyse a capture"}
        </h2>
        <p className="mt-2 max-w-[52ch] text-[13.5px] leading-relaxed text-muted-foreground">
          Drop <span className="font-mono text-[12.5px] text-foreground/85">.pcap</span> or{" "}
          <span className="font-mono text-[12.5px] text-foreground/85">.pcapng</span> files anywhere on this page. Each one is
          read by the local engine, checked against every loaded baseline, and deleted as soon as its results are back.
        </p>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            className="tactile inline-flex items-center gap-2 rounded-lg bg-violet px-4 py-2.5 text-[13.5px] font-semibold text-primary-foreground hover:bg-violet/90"
          >
            <FileUp className="h-4 w-4" strokeWidth={2} />
            Choose captures
          </button>
          <span className="text-[12px] text-faint">Up to 200 MB each · stays on 127.0.0.1</span>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept={ACCEPT}
            className="sr-only"
            tabIndex={-1}
            onChange={(e) => {
              if (e.target.files?.length) onFiles(Array.from(e.target.files))
              e.target.value = ""
            }}
          />
        </div>

        {queue.length > 0 && (
          <div className="mt-6 border-t border-border pt-3">
            <div className="flex items-center justify-between">
              <h3 className="text-[12.5px] font-medium text-muted-foreground" aria-live="polite">
                {busy
                  ? `Analysing ${Math.min(finished + 1, queue.length)} of ${queue.length}`
                  : [done && `${done} analysed`, failed && `${failed} not analysed`].filter(Boolean).join(" · ")}
              </h3>
              {!busy && (
                <button type="button" onClick={onClear} className="text-[12px] text-faint hover:text-foreground">
                  Clear all
                </button>
              )}
            </div>
            <ul className="mt-1 max-h-[232px] divide-y divide-border/70 overflow-y-auto pr-1">
              {queue.map((q) => (
                <QueueRow key={q.key} item={q} onRetry={() => onRetry(q.key)} onRemove={() => onRemove(q.key)} />
              ))}
            </ul>
          </div>
        )}
      </div>

      <div
        className={cn(
          "flex min-h-[220px] flex-col border-t border-border p-4 sm:p-5 md:border-l md:border-t-0",
          compact ? "md:min-h-[260px]" : "md:min-h-[340px]",
        )}
      >
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          className={cn(
            "tactile group flex flex-1 flex-col items-center justify-center gap-3 rounded-lg border border-dashed px-4 py-6 text-center transition-colors duration-200",
            dragging
              ? "border-violet bg-violet-bg"
              : "border-border hover:border-violet/60 hover:bg-violet-bg/50",
          )}
        >
          <Mark
            className={cn(
              "h-14 w-14 transition-transform duration-300 group-hover:scale-105",
              (dragging || tunnel === "busy") && "soft-blink",
            )}
          />
          <span className="text-[14.5px] font-medium text-foreground">
            {dragging ? "Release to analyse" : tunnel === "busy" ? "Analysing…" : "Drop captures here"}
          </span>
          <span className="text-[12.5px] text-muted-foreground">
            or click to choose · <span className="font-mono text-[12px]">.pcap</span>,{" "}
            <span className="font-mono text-[12px]">.pcapng</span>
          </span>
        </button>
        <div className="mt-3 flex justify-between px-1 font-mono text-[11px] text-faint">
          <span>
            {tunnel === "busy"
              ? "reading IKE and ESP"
              : tunnel === "over"
                ? "ready"
                : tunnel === "error"
                  ? "capture refused"
                  : tunnel === "idle"
                    ? "waiting for a capture"
                    : "analysis complete"}
          </span>
          <span>127.0.0.1</span>
        </div>
      </div>
    </section>
  )
}
