import { useState } from "react"
import { remediationPlan, applyRemediation, type RemediationPlan, type RemediationApplyResult } from "@/lib/api"
import { cn } from "@/lib/utils"

const LAB_TARGETS = [
  "sih26-alice-pq",
  "sih26-bob-pq",
  "sih26-alice",
  "sih26-bob",
  "sih26-lsw-a",
  "sih26-lsw-b",
]

export function RemediationControl({
  ruleId,
  observed,
}: {
  ruleId: string
  observed?: unknown
}) {
  const [isOpen, setIsOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [plan, setPlan] = useState<RemediationPlan | null>(null)
  const [hasFetched, setHasFetched] = useState(false)
  const [decision, setDecision] = useState<"none" | "approved" | "rejected">("none")
  const [target, setTarget] = useState(LAB_TARGETS[0])
  const [applying, setApplying] = useState(false)
  const [applyResult, setApplyResult] = useState<RemediationApplyResult | null>(null)

  async function handleOpen() {
    if (hasFetched) {
      setIsOpen(true)
      return
    }
    setLoading(true)
    try {
      const res = await remediationPlan(ruleId, observed)
      setPlan(res)
      setHasFetched(true)
      setIsOpen(true)
    } finally {
      setLoading(false)
    }
  }

  async function handleApply() {
    setApplying(true)
    setApplyResult(null)
    try {
      const res = await applyRemediation(ruleId, target, true)
      setApplyResult(res)
    } finally {
      setApplying(false)
    }
  }

  function handleDismiss() {
    setIsOpen(false)
  }


  if (!isOpen) {
    return (
      <div className="mt-1">
        <button
          type="button"
          onClick={handleOpen}
          disabled={loading}
          aria-label={`Propose fix for ${ruleId}`}
          className={cn(
            "inline-flex items-center text-[11.5px] font-medium text-violet transition-colors hover:underline disabled:opacity-50",
          )}
        >
          {loading ? "Loading plan..." : "Propose fix"}
        </button>
      </div>
    )
  }

  // If fetched but no plan exists for this rule (unknown rule or unmapped)
  if (hasFetched && !plan) {
    return (
      <div className="mt-1.5 flex items-center gap-2 text-[11.5px] text-faint">
        <span>No fix available for this finding.</span>
        <button
          type="button"
          onClick={handleDismiss}
          aria-label={`Dismiss notice for ${ruleId}`}
          className="text-faint underline hover:text-muted-foreground"
        >
          Dismiss
        </button>
      </div>
    )
  }

  if (!plan) return null

  return (
    <div className="mt-2 max-w-[540px] rounded-lg border border-border bg-background/60 p-3 text-[12.5px] text-foreground/90 space-y-2.5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <span className="text-[11px] font-medium uppercase tracking-wider text-faint">
            Proposed change
          </span>
          <p className="mt-0.5 text-[12.5px] font-medium text-foreground">
            {plan.change}
          </p>
        </div>
        <button
          type="button"
          onClick={handleDismiss}
          aria-label={`Close plan for ${ruleId}`}
          className="text-[11.5px] text-faint hover:text-muted-foreground"
        >
          Close
        </button>
      </div>

      <div>
        <span className="text-[11px] font-medium text-faint">
          Commands:
        </span>
        <ul className="mt-1 space-y-1">
          {plan.commands.map((cmd, i) => (
            <li
              key={i}
              className="rounded border border-border/70 bg-secondary/50 px-2.5 py-1.5 font-mono text-[12px] text-foreground/90 break-words select-all"
            >
              {cmd}
            </li>
          ))}
        </ul>
      </div>

      {plan.auto_applicable ? (
        <div className="border-t border-border/50 pt-2">
          {decision === "none" && (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setDecision("approved")}
                aria-label={`Approve remediation plan for ${ruleId}`}
                className="rounded border border-violet/40 bg-violet-bg px-2.5 py-1 text-[11.5px] font-medium text-violet transition-colors hover:bg-violet/20"
              >
                Approve
              </button>
              <button
                type="button"
                onClick={() => setDecision("rejected")}
                aria-label={`Reject remediation plan for ${ruleId}`}
                className="rounded border border-border bg-secondary px-2.5 py-1 text-[11.5px] font-medium text-muted-foreground transition-colors hover:text-foreground"
              >
                Reject
              </button>
            </div>
          )}

          {decision === "approved" && (
            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center gap-2">
                {/*
                  CRITICAL HONESTY DISCIPLINE (see DEC-031 / DEC-032 and build/09-REMEDIATION-ROADMAP.md Stage 2 & 3):
                  TunnelScope never claims more than the evidence shows.
                  Clicking "Approve" only records the operator's decision in memory; it does NOT execute commands,
                  alter the tunnel, or verify changes.
                  Therefore, words like "applied", "fixed", "patched", or "done" MUST NOT appear in connection
                  with the Approve action.
                  The honest words are "approved" (a decision was recorded) and "not yet applied" (nothing happened to the tunnel).
                */}
                <span className="text-[12px] font-medium text-foreground/90">
                  Approved — not yet applied. Execution is not built in this version.
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setDecision("none")
                    setApplyResult(null)
                  }}
                  aria-label={`Change decision for ${ruleId}`}
                  className="text-[11px] text-faint underline hover:text-muted-foreground"
                >
                  Change
                </button>
              </div>

              {/* Stage 3: Lab execution human gate */}
              <div className="rounded border border-border/70 bg-secondary/30 p-2.5 space-y-2 text-[12px]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-medium uppercase tracking-wider text-faint">
                      Target:
                    </span>
                    <select
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      disabled={applying}
                      aria-label={`Select lab container target for ${ruleId}`}
                      className="rounded border border-border bg-background px-2 py-0.5 font-mono text-[11.5px] text-foreground focus:outline-none"
                    >
                      {LAB_TARGETS.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </select>
                  </div>
                  <button
                    type="button"
                    onClick={handleApply}
                    disabled={applying}
                    aria-label={`Apply remediation in lab for ${ruleId}`}
                    className="rounded border border-violet/40 bg-violet px-2.5 py-1 text-[11.5px] font-semibold text-primary-foreground transition-colors hover:bg-violet/90 disabled:opacity-50"
                  >
                    {applying ? "Applying..." : "Apply in lab"}
                  </button>
                </div>

                {applying && (
                  <p className="text-[11.5px] text-muted-foreground animate-pulse">
                    Executing commands in {target}, capturing verification traffic, and analyzing fresh capture...
                  </p>
                )}

                {applyResult && (
                  <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2 text-[12px]">
                    {!applyResult.ok ? (
                      <div className="text-warn text-[12px]">
                        <span className="font-semibold">Refused: </span>
                        {applyResult.error || "Execution failed."}
                      </div>
                    ) : (
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-faint">Target:</span>
                          <span className="font-mono text-[11.5px]">{applyResult.target}</span>
                          <span className="text-faint">· Verdict:</span>
                          <span className="font-semibold">{applyResult.verdict_before}</span>
                          <span>→</span>
                          <span
                            className={cn(
                              "font-semibold",
                              applyResult.confirmed_fixed ? "text-emerald-400" : "text-warn",
                            )}
                          >
                            {applyResult.verdict_after}
                          </span>
                        </div>
                        <div>
                          {applyResult.confirmed_fixed ? (
                            <span className="text-[12px] font-semibold text-emerald-400">
                              Confirmed fixed — fresh capture verified verdict is PASS.
                            </span>
                          ) : (
                            <span className="text-[12px] font-semibold text-warn">
                              Commands executed, but verdict is {applyResult.verdict_after || "still failing"} (not fixed).
                            </span>
                          )}
                        </div>
                        {applyResult.commands_run && applyResult.commands_run.length > 0 && (
                          <div className="mt-1">
                            <span className="text-[11px] text-faint">Commands executed:</span>
                            <ul className="mt-0.5 space-y-0.5">
                              {applyResult.commands_run.map((c, idx) => (
                                <li
                                  key={idx}
                                  className="rounded border border-border/50 bg-secondary/50 px-2 py-0.5 font-mono text-[11px] text-foreground/80 select-all"
                                >
                                  {c}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}


          {decision === "rejected" && (
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-medium text-muted-foreground">
                Declined.
              </span>
              <button
                type="button"
                onClick={() => setDecision("none")}
                aria-label={`Change decision for ${ruleId}`}
                className="text-[11px] text-faint underline hover:text-muted-foreground"
              >
                Change
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border/50 pt-2">
          <p className="text-[12px] font-medium text-warn">
            Advisory only — this needs a software patch or investigation, not a config change.
          </p>
          <button
            type="button"
            onClick={handleDismiss}
            aria-label={`Acknowledge advisory for ${ruleId}`}
            className="rounded border border-border bg-secondary px-2 py-0.5 text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            Acknowledge
          </button>
        </div>
      )}
    </div>
  )
}
