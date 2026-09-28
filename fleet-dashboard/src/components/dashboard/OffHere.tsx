/** A view the public site switches off (server.py public_demo), with the reasons, in place of a view that would
 * otherwise wait forever for data it will never get. */
export function OffHere({ title, reasons }: { title: string; reasons: { label: string; text: string }[] }) {
  return (
    <section role="note" className="glass rounded-2xl px-6 py-7">
      <h2 className="text-[16px] font-semibold">{title}</h2>
      <p className="mt-2 max-w-[75ch] text-[13px] leading-relaxed text-muted-foreground">
        This is the same TunnelScope you run yourself, and there this view works. On this public site it is switched off:
      </p>
      <ul className="mt-3 max-w-[75ch] list-disc space-y-1.5 pl-5 text-[13px] leading-relaxed text-muted-foreground">
        {reasons.map((r) => (
          <li key={r.label}>
            <span className="text-foreground/85">{r.label}</span> {r.text}
          </li>
        ))}
      </ul>
      <p className="mt-3 max-w-[75ch] text-[13px] leading-relaxed text-muted-foreground">
        To use it, run TunnelScope on your own machine (<code className="font-mono text-[12px]">./start.sh</code>), where
        nothing leaves it.
      </p>
    </section>
  )
}

export function Unreachable() {
  return (
    <p role="status" className="text-[13px] text-neg">
      The analysis engine isn&apos;t answering. Check that it is running, then reload this page.
    </p>
  )
}
