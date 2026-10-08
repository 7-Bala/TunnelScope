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

type Row = { id: string; cvss: number | string | null; kev: boolean; match: "cpe" | "vendor" | "keyword"; description: string | null }
type View = { name: string; total?: number; kev?: number; sources: Record<string, string>; rows: Row[]; note?: string | null; error?: string }

/** The implementations TunnelScope fingerprinted (EXP-29), per end. */
function implementations(sa: AnalyzedSA): { end: string; name: string }[] {
  const f = sa.findings.find((x) => x.attribute === "implementation")
  const v = (f?.value ?? {}) as Record<string, string | null>
  return Object.entries(v)
    .filter(([, n]) => !!n)
    .map(([end, name]) => ({ end, name: name as string }))
}

function fromLookup(name: string, r: IntelResult | null): View {
  if (r === null || !r.ok) return { name, sources: {}, rows: [], error: r?.error ?? "lookup failed" }
  return {
    name,
    total: r.counts?.total,
    kev: r.counts?.kev,
    sources: Object.fromEntries(Object.entries(r.sources).map(([s, v]) => [s, v.status])),
    rows: r.cves.slice(0, 15),
    note: r.note,
  }
}

/** Known vulnerabilities for the VPN software seen at each end (DEC-045): looked up by the engine on every analysis and
 * shown here straight away; "Look up again" fetches the full, current list. Never a verdict. */
export function IntelPane({ sa }: { sa: AnalyzedSA }) {
  const impls = implementations(sa)
  const names = [...new Set(impls.map((i) => i.name))]
  const [again, setAgain] = useState<View[] | null>(null)
  const [busy, setBusy] = useState(false)
  const kv = sa.known_vulnerabilities

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
    const out: View[] = []
    for (const n of names) out.push(fromLookup(n, await intelLookup(n)))
    setAgain(out)
    setBusy(false)
  }

  const views: View[] =
    again ??
    (kv?.products ?? []).map((p) => ({
      name: p.implementation,
      total: p.counts.total,
      kev: p.counts.kev,
      sources: p.sources,
      rows: p.top,
      note: p.note,
    }))

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
          {busy ? "Looking up…" : "Look up again"}
        </button>
      </div>
      <p className="text-[12px] text-faint">
        Checked on every analysis against NVD, ENISA EUVD and CISA KEV (only the software name is sent; an install with
        TUNNELSCOPE_NETWORK=off uses its local cache or offline bundle). These are known flaws in some version of the
        software: traffic does not show the version, so none is confirmed on this tunnel, and no verdict or risk score
        uses them.
      </p>
      <p className="text-[11.5px] text-faint">This product uses data from the NVD API but is not endorsed or certified by the NVD.</p>
      {views.length === 0 && (
        <p className="text-[13px] text-muted-foreground">{kv?.note ?? "No vulnerability data for this analysis."}</p>
      )}

      {views.map((v) => {
        if (v.error) {
          return <p key={v.name} className="text-[13px] text-neg">{v.name}: lookup failed ({v.error}).</p>
        }
        return (
          <section key={v.name} aria-label={`Known vulnerabilities for ${v.name}`} className="space-y-2">
            <h4 className="text-[14px] font-semibold text-foreground/90">
              {v.name}: {v.total !== undefined ? `${v.total} known CVEs` : "no data"}
              {!!v.kev && <span className="ml-2 rounded-full bg-neg-bg px-2 py-0.5 text-[11px] text-neg">{v.kev} actively exploited (CISA KEV)</span>}
            </h4>
            <p className="text-[12px] text-faint">
              {Object.entries(v.sources).map(([s, st]) => `${s}: ${STATUS_TEXT[st] ?? st}`).join(" · ")}
            </p>
            {v.rows.length > 0 && (
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
                    {v.rows.map((e) => (
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
            {v.note && <p className="text-[12px] leading-relaxed text-muted-foreground">{v.note}</p>}
          </section>
        )
      })}
    </div>
  )
}
