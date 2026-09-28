import { useEffect, useRef } from "react"

const KEY = "tunnelscope-demo-terms-v1"

/** Whether this browser already agreed to the public demo's terms. Storage can be unavailable (private mode,
 * blocked site data); then the dialog simply shows again next visit. */
export function demoTermsAgreed(): boolean {
  try {
    return window.localStorage.getItem(KEY) === "agreed"
  } catch {
    return false
  }
}

function remember() {
  try {
    window.localStorage.setItem(KEY, "agreed")
  } catch {
    /* not stored: asked again next visit */
  }
}

/** Shown once on the public site before anything can be uploaded (DEC-046). A local install never shows it. */
export function DemoTerms({ onAgree, onDecline }: { onAgree: () => void; onDecline: () => void }) {
  const agree = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    agree.current?.focus()
  }, [])
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="demo-terms-title"
        className="glass max-h-[90dvh] w-full max-w-[620px] overflow-y-auto rounded-2xl px-6 py-6 text-[13.5px] leading-relaxed text-muted-foreground"
      >
        <h2 id="demo-terms-title" className="text-[18px] font-semibold text-foreground">
          Before you use the public demo
        </h2>
        <ul className="mt-3 list-disc space-y-2 pl-5">
          <li>
            <span className="text-foreground/90">Upload only captures you are allowed to share.</span> A capture can contain IP
            addresses and other details about a network, which may be personal or confidential.
          </li>
          <li>
            <span className="text-foreground/90">What happens to it:</span> it is sent to this server, analysed, and deleted
            as soon as the result is back (25 MB at most). Nothing from it is stored. Only the name of the VPN software it
            identifies is sent on, to NIST NVD, ENISA EUVD and CISA KEV, to look up known vulnerabilities.
          </li>
          <li>
            <span className="text-foreground/90">No cookies, no tracking.</span> Your answer here is remembered in this
            browser only, so you are not asked again.
          </li>
          <li>
            <span className="text-foreground/90">For information only.</span> The demo is provided as is, without warranty.
            Do not rely on it alone for security decisions; fixing and live monitoring are switched off here.
          </li>
          <li>
            For your own networks, run TunnelScope on your own machine, where nothing leaves it.
          </li>
        </ul>
        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            ref={agree}
            type="button"
            onClick={() => {
              remember()
              onAgree()
            }}
            className="tactile rounded-lg bg-violet px-4 py-2 text-[13.5px] font-semibold text-primary-foreground hover:bg-violet/90"
          >
            I agree
          </button>
          <button
            type="button"
            onClick={onDecline}
            className="rounded-lg border border-border px-4 py-2 text-[13.5px] font-medium text-foreground/85 hover:bg-secondary"
          >
            Not now
          </button>
        </div>
      </div>
    </div>
  )
}
