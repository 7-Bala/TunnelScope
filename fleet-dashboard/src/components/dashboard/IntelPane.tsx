import { useState } from "react"
import { cn } from "@/lib/utils"
import { intelLookup, type AnalyzedSA, type IntelResult } from "@/lib/api"

const STATUS_TEXT: Record<string, string> = {
  fresh: "fetched now",
  cached: "cached (less than a day old)",
  "stale-offline": "stale cache, network off",
  "stale-error": "stale cache, source unreachable",
  unavailable: "unavailable",
}

/** The implementations TunnelScope fingerprinted (EXP-29), per end. */
function implementations(sa: AnalyzedSA): { end: string; name: string }[] {
  const f = sa.findings.find((x) => x.attribute === "implementation")
  const v = (f?.value ?? {}) as Record<string, string | null>
  return Object.entries(v)
    .filter(([, n]) => !!n)
    .map(([end, name]) => ({ end, name: name as string }))
}

/** Known vulnerabilities for the VPN software seen at each end. Looked up only when the analyst asks. */
export function IntelPane({ sa }: { sa: AnalyzedSA }) {
  const impls = implementations(sa)
  const names = [...new Set(impls.map((i) => i.name))]
  const [res, setRes] = useState<Record<string, IntelResult | null>>({})
  const [busy, setBusy] = useState(false)

  if (names.length === 0) {
    return (
      <p className="max-w-[70ch] text-[13px] text-muted-foreground">
        The VPN software at either end could not be identified from this capture (implementation: unknown), so there
        is nothing to look up. Identification comes from the plaintext handshake; an unknown or unusual stack stays
        unknown rather than being guessed.
      </p>
    )
  }

  async function look() {
    setBusy(true)
    const out: Record<string, IntelResult | null> = {}
    for (const n of names) out[n] = await intelLookup(n)
    setRes(out)
    setBusy(false)
  }

  return (
    <div className="max-w-[96ch] space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-[13px] text-muted-foreground">
          Identified: {impls.map((i) => `${i.name} (${i.end})`).join(", ")}.
        </p>
        <button
          type="button"
          onClick={look}
          disabled={busy}
          className="rounded-md border border-border px-3 py-1.5 text-[12.5px] font-medium hover:bg-secondary disabled:opacity-50"
        >
          {busy ? "Looking up…" : Object.keys(res).length ? "Look up again" : "Look up known vulnerabilities"}
        </button>
      </div>
      <p className="text-[12px] text-faint">
        Sends only the software name to NVD, ENISA EUVD and CISA KEV, and only if the engine runs with TUNNELSCOPE_NETWORK=on;
        otherwise the local cache or offline bundle is used.
      </p>

      {names.map((n) => {
        const r = res[n]
        if (r === undefined) return null
        if (r === null || !r.ok) {
          return <p key={n} className="text-[13px] text-neg">{n}: lookup failed{r?.error ? ` (${r.error})` : ""}.</p>
        }
        const c = r.counts
        return (
          <section key={n} aria-label={`Known vulnerabilities for ${n}`} className="space-y-2">
            <h4 className="text-[14px] font-semibold text-foreground/90">
              {n}: {c ? `${c.total} known CVEs` : "no data"}
              {c && c.kev > 0 && <span className="ml-2 rounded-full bg-neg-bg px-2 py-0.5 text-[11px] text-neg">{c.kev} actively exploited (CISA KEV)</span>}
            </h4>
            <p className="text-[12px] text-faint">
              {Object.entries(r.sources).map(([s, v]) => `${s}: ${STATUS_TEXT[v.status] ?? v.status}`).join(" · ")}
            </p>
            {r.cves.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[620px] text-left text-[12.5px]">
                  <thead>
                    <tr className="text-[11.5px] text-faint">
                      <th className="py-1.5 pr-3 font-medium">CVE</th>
                      <th className="py-1.5 pr-3 font-medium">CVSS</th>
                      <th className="py-1.5 pr-3 font-medium">Match</th>
                      <th className="py-1.5 font-medium">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {r.cves.slice(0, 15).map((e) => (
                      <tr key={e.id} className="align-top">
                        <td className="whitespace-nowrap py-1.5 pr-3 font-mono text-[11.5px]">
                          {e.id}
                          {e.kev && <span className="ml-1 text-neg">KEV</span>}
                        </td>
                        <td className="py-1.5 pr-3 font-mono text-[11.5px]">{e.cvss ?? "–"}</td>
                        <td className={cn("py-1.5 pr-3 text-[11.5px]", e.match === "keyword" ? "text-faint" : "text-muted-foreground")}>
                          {e.match === "cpe" ? "product listed" : e.match === "vendor" ? "vendor listed" : "mention only"}
                        </td>
                        <td className="py-1.5 leading-snug text-muted-foreground">{(e.description ?? "").split(/\s+/).join(" ").slice(0, 160)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {r.note && <p className="text-[12px] leading-relaxed text-muted-foreground">{r.note}</p>}
          </section>
        )
      })}
    </div>
  )
}
