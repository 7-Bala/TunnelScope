import { useEffect, useRef, useState } from "react"
import {
  remediationPlan,
  applyRemediation,
  generateRemediation,
  previewRemediation,
  remediationCapabilities,
  remediationTargets,
  type GenerateResult,
  type LabTarget,
  type RemediationCapabilities,
  type RemediationPlan,
  type RemediationApplyResult,
  type RemediationPreview,
} from "@/lib/api"
import { cn } from "@/lib/utils"

// Used only if the engine cannot list the lab (the engine still validates every target).
const FALLBACK_TARGETS: LabTarget[] = [
  { name: "sih26-alice-pq", running: true },
  { name: "sih26-bob-pq", running: true },
]

function DiffBlock({ diff }: { diff: string }) {
  return (
    <pre className="mt-1 overflow-x-auto rounded border border-border/70 bg-secondary/60 p-2 font-mono text-[11px] leading-relaxed text-foreground/90">
      {diff.split("\n").map((line, idx) => {
        const isHeader = line.startsWith("---") || line.startsWith("+++") || line.startsWith("@@")
        const isRemoved = !isHeader && line.startsWith("-")
        const isAdded = !isHeader && line.startsWith("+")
        return (
          <div
            key={idx}
            className={cn(
              isRemoved && "rounded-sm bg-red-500/10 px-1 text-red-400",
              isAdded && "rounded-sm bg-emerald-500/10 px-1 text-emerald-400",
              isHeader && "text-faint",
              !isRemoved && !isAdded && !isHeader && "text-foreground/80",
            )}
          >
            {line}
          </div>
        )
      })}
    </pre>
  )
}

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
  const [targets, setTargets] = useState<LabTarget[]>(FALLBACK_TARGETS)
  const [target, setTarget] = useState(FALLBACK_TARGETS[0].name)
  const [previewing, setPreviewing] = useState(false)
  const [preview, setPreview] = useState<RemediationPreview | null>(null)
  const [applying, setApplying] = useState(false)
  const [applyResult, setApplyResult] = useState<RemediationApplyResult | null>(null)
  const [showDetailed, setShowDetailed] = useState(false)
  // Local-model draft (DEC-034): shown next to the hand-written fix, which stays the default.
  const [caps, setCaps] = useState<RemediationCapabilities | null>(null)
  const [draft, setDraft] = useState<GenerateResult | null>(null)
  const [drafting, setDrafting] = useState(false)
  const [draftSeconds, setDraftSeconds] = useState(0)
  const [choice, setChoice] = useState<"hand" | "draft">("hand")
  const [concernAcknowledged, setConcernAcknowledged] = useState(false)
  const draftRequest = useRef(0)
  const busy = useRef(false) // a second click before React re-renders must not send a second request

  useEffect(() => {
    if (decision !== "approved") return
    let live = true
    remediationTargets().then((t) => {
      if (!live || !t || t.targets.length === 0) return
      setTargets(t.targets)
      const rec = t.targets.find((x) => x.name === t.recommended && x.running)
      if (rec) setTarget(rec.name)
    })
    remediationCapabilities().then((c) => {
      if (live) setCaps(c)
    })
    return () => {
      live = false
    }
  }, [decision])

  useEffect(() => {
    if (!drafting) return
    const started = Date.now()
    const t = setInterval(() => setDraftSeconds(Math.round((Date.now() - started) / 1000)), 500)
    return () => clearInterval(t)
  }, [drafting])

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

  function chooseTarget(name: string) {
    setTarget(name)
    // A preview (and a draft) is for one container; a new target needs new ones before applying.
    setPreview(null)
    setApplyResult(null)
    setDraft(null)
    setChoice("hand")
    setConcernAcknowledged(false)
    draftRequest.current++
    setDrafting(false)
  }

  function choosePlan(c: "hand" | "draft") {
    setChoice(c)
    setPreview(null)
    setApplyResult(null)
    setConcernAcknowledged(false)
  }

  async function handleDraft() {
    const id = ++draftRequest.current
    setDrafting(true)
    setDraftSeconds(0)
    setDraft(null)
    choosePlan("hand")
    const r = await generateRemediation(ruleId, target, observed)
    if (draftRequest.current !== id) return // cancelled, or the target changed meanwhile
    setDraft(r)
    setDrafting(false)
  }

  function cancelDraft() {
    draftRequest.current++
    setDrafting(false)
  }

  const draftPlanId = choice === "draft" && draft?.ok ? draft.plan_id : null

  async function handlePreview() {
    if (busy.current) return
    busy.current = true
    setPreviewing(true)
    setPreview(null)
    setApplyResult(null)
    try {
      setPreview(await previewRemediation(ruleId, target, draftPlanId))
    } finally {
      setPreviewing(false)
      busy.current = false
    }
  }

  async function handleApply() {
    if (busy.current) return
    busy.current = true
    setApplying(true)
    setApplyResult(null)
    try {
      const r = await applyRemediation(ruleId, target, true, { digest: preview?.digest, planId: draftPlanId })
      setApplyResult(r)
      // What was previewed no longer matches the lab: that preview must not be applied again.
      if (r.stage === "stale_preview") setPreview(null)
    } finally {
      setApplying(false)
      busy.current = false
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
          className="inline-flex items-center text-[11.5px] font-medium text-violet transition-colors hover:underline disabled:opacity-50"
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

  const automated = plan.auto_applicable && plan.automated_fix_available !== false
  const draftConcern = choice === "draft" && draft?.ok && draft.plan.self_review?.verdict === "concerns"
  const previewReady = preview?.ok === true && (!draftConcern || concernAcknowledged)
  const targetInfo = targets.find((t) => t.name === target)

  return (
    <div
      data-testid={`remediation-pane-${ruleId}`}
      className="mt-2 w-full max-w-[min(560px,calc(100vw-5rem))] space-y-2.5 rounded-lg border border-border bg-background/60 p-3 text-[12.5px] text-foreground/90"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <span className="text-[11px] font-medium uppercase tracking-wider text-faint">Proposed change</span>
          <p className="mt-0.5 text-[12.5px] font-medium text-foreground">{plan.change}</p>
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
        <span className="text-[11px] font-medium text-faint">Steps:</span>
        <ul className="mt-1 space-y-1">
          {plan.commands.map((cmd, i) => (
            <li
              key={i}
              className="select-all break-words rounded border border-border/70 bg-secondary/50 px-2.5 py-1.5 font-mono text-[12px] text-foreground/90"
            >
              {cmd}
            </li>
          ))}
        </ul>
      </div>

      {/* Detailed plan (progressive disclosure) */}
      <div className="border-t border-border/50 pt-2">
        <button
          type="button"
          onClick={() => setShowDetailed((prev) => !prev)}
          className="flex items-center gap-1.5 text-[11.5px] font-medium text-violet transition-colors hover:underline focus:outline-none"
        >
          <span>{showDetailed ? "▾ Hide detailed plan" : "▸ View detailed plan"}</span>
          {/* Honest label: every plan is written by hand. No language model generates plans or commands. */}
          <span className="rounded bg-violet/10 px-1.5 py-0.5 font-mono text-[10px] text-violet">
            Hand-written plan · checked before and after
          </span>
        </button>

        {showDetailed && (
          <div className="mt-2 space-y-2 rounded border border-border/60 bg-secondary/30 p-2.5 text-[11.5px] text-foreground/90">
            {plan.problem_analysis && (
              <div>
                <span className="font-semibold text-foreground">Problem:</span>
                <p className="mt-0.5 leading-relaxed text-muted-foreground">{plan.problem_analysis}</p>
              </div>
            )}
            {plan.cryptographic_risk && (
              <div>
                <span className="font-semibold text-warn">Why it matters:</span>
                <p className="mt-0.5 leading-relaxed text-muted-foreground">{plan.cryptographic_risk}</p>
              </div>
            )}
            {plan.proposed_strategy && (
              <div>
                <span className="font-semibold text-foreground">Fix:</span>
                <p className="mt-0.5 leading-relaxed text-muted-foreground">{plan.proposed_strategy}</p>
              </div>
            )}
            {plan.config_diff && (
              <div>
                <span className="font-semibold text-foreground">
                  {plan.config_diff_is_example ? "Example of the change" : "Configuration change"}
                </span>
                {plan.config_diff_is_example && (
                  <span className="ml-1 text-faint">
                    (illustration, not read from your configuration; use Preview for the real diff)
                  </span>
                )}
                <DiffBlock diff={plan.config_diff} />
              </div>
            )}
            {automated && plan.rollback_strategy && (
              <div className="rounded border border-border/70 bg-secondary/40 p-2">
                <span className="font-semibold text-foreground">How a change is protected</span>
                <ol className="mt-1 list-inside list-decimal space-y-0.5 text-muted-foreground">
                  <li>Each command is checked against a fixed allowlist, and never run through a shell.</li>
                  <li>A dry run on copies of the real config files shows the exact diff before you apply.</li>
                  <li>A capture before the change records which rules fail already.</li>
                  <li>{plan.rollback_strategy}</li>
                  <li>A capture after the change must show this rule passing and no other rule newly failing, or the change is undone.</li>
                </ol>
              </div>
            )}
            {plan.is_software_patch && plan.runbook && plan.runbook.length > 0 && (
              <div className="rounded border border-amber-500/30 bg-amber-500/10 p-2">
                <span className="font-semibold text-amber-400">Operator runbook:</span>
                <ol className="mt-1 list-inside list-decimal space-y-1 text-muted-foreground">
                  {plan.runbook.map((step, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}
      </div>

      {automated ? (
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
                  CRITICAL HONESTY DISCIPLINE (see DEC-031 / DEC-032 / DEC-033 and build/09-REMEDIATION-ROADMAP.md):
                  TunnelScope never claims more than the evidence shows.
                  Clicking "Approve" only records the operator's decision in memory; it does NOT execute commands,
                  alter the tunnel, or verify changes.
                  Therefore, words like "applied", "fixed", "patched", or "done" MUST NOT appear in connection
                  with the Approve action. "Confirmed fixed" appears only when the engine returns
                  confirmed_fixed: true from a fresh capture.
                */}
                <span className="text-[12px] font-medium text-foreground/90">
                  Approved — not yet applied. Preview the real change first:
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setDecision("none")
                    setPreview(null)
                    setApplyResult(null)
                  }}
                  aria-label={`Change decision for ${ruleId}`}
                  className="text-[11px] text-faint underline hover:text-muted-foreground"
                >
                  Change
                </button>
              </div>

              <div className="space-y-2 rounded border border-border/70 bg-secondary/30 p-2.5 text-[12px]">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex min-w-0 max-w-full items-center gap-2">
                    <span className="shrink-0 text-[11px] font-medium uppercase tracking-wider text-faint">Lab target:</span>
                    <select
                      value={target}
                      onChange={(e) => chooseTarget(e.target.value)}
                      disabled={applying || previewing}
                      aria-label={`Select lab container target for ${ruleId}`}
                      className="min-w-0 max-w-full rounded border border-border bg-background px-2 py-0.5 font-mono text-[11.5px] text-foreground"
                    >
                      {targets.map((t) => (
                        <option key={t.name} value={t.name}>
                          {t.name}
                          {t.running ? "" : " (not running)"}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handlePreview}
                      disabled={applying || previewing || targetInfo?.running === false}
                      aria-label={`Preview the real change for ${ruleId}`}
                      className="rounded border border-violet/40 bg-violet-bg px-2.5 py-1 text-[11.5px] font-medium text-violet transition-colors hover:bg-violet/20 disabled:opacity-50"
                    >
                      {previewing ? "Checking..." : "Preview change"}
                    </button>
                    <button
                      type="button"
                      onClick={handleApply}
                      disabled={applying || !previewReady}
                      title={previewReady ? undefined : "Preview the change on this target first"}
                      aria-label={`Apply remediation in lab for ${ruleId}`}
                      className="rounded border border-violet/40 bg-violet px-2.5 py-1 text-[11.5px] font-semibold text-primary-foreground transition-colors hover:bg-violet/90 disabled:opacity-50"
                    >
                      {applying ? "Applying..." : "Apply in lab"}
                    </button>
                  </div>
                </div>

                <DraftPanel
                  caps={caps}
                  draft={draft}
                  drafting={drafting}
                  seconds={draftSeconds}
                  choice={choice}
                  disabled={applying || previewing || targetInfo?.running === false}
                  ruleId={ruleId}
                  onDraft={handleDraft}
                  onCancel={cancelDraft}
                  onChoose={choosePlan}
                />

                {draftConcern && preview?.ok && !concernAcknowledged && (
                  <div className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-[11.5px] text-amber-300">
                    <p>
                      <span className="font-semibold">The model's own review raised a concern: </span>
                      {draft?.ok ? draft.plan.self_review?.reason : ""}
                    </p>
                    <p className="mt-1 text-foreground/80">
                      Every code check passed. The concern is the model's opinion; read the diff before you decide.
                    </p>
                    <button
                      type="button"
                      onClick={() => setConcernAcknowledged(true)}
                      aria-label={`I have read the concern, allow Apply for ${ruleId}`}
                      className="mt-1.5 rounded border border-amber-500/50 px-2 py-0.5 text-[11px] font-medium text-amber-300 hover:bg-amber-500/10"
                    >
                      I have read it, allow Apply
                    </button>
                  </div>
                )}

                {preview && !preview.ok && (
                  <p className="text-[12px] text-warn">
                    <span className="font-semibold">Cannot apply here: </span>
                    {preview.error || "the dry run failed"}
                  </p>
                )}

                {preview?.ok && (
                  <div className="space-y-1.5">
                    <p className="text-[11.5px] text-muted-foreground">
                      Dry run of the {choice === "draft" ? "local model's draft" : "hand-written fix"} on copies of the real
                      files in {target}, and strongSwan loaded the result in a throwaway copy of the container. This is exactly
                      what "Apply in lab" will change:
                    </p>
                    {Object.entries(preview.diff ?? {}).map(([file, d]) => (
                      <DiffBlock key={file} diff={d} />
                    ))}
                    {preview.peer && Object.keys(preview.peer.diff).length > 0 && (
                      <div>
                        <p className="text-[11.5px] text-muted-foreground">
                          It also changes the lab peer <span className="font-mono">{preview.peer.container}</span>
                          , because {preview.peer.why}. The peer is snapshotted and undone with the target:
                        </p>
                        {Object.entries(preview.peer.diff).map(([file, d]) => (
                          <DiffBlock key={file} diff={d} />
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {applying && (
                  <p className="animate-pulse text-[11.5px] text-muted-foreground">
                    Capturing a baseline, applying in {target}, then capturing again to check the result...
                  </p>
                )}

                {applyResult && <ApplyOutcome result={applyResult} />}
              </div>
            </div>
          )}

          {decision === "rejected" && (
            <div className="flex items-center gap-2">
              <span className="text-[12px] font-medium text-muted-foreground">Declined.</span>
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
            {plan.auto_applicable
              ? "No safe automated fix yet — this needs a manual change (for example on the other endpoint)."
              : "Advisory only — this needs a software patch or investigation, not a config change."}
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

function ApplyOutcome({ result }: { result: RemediationApplyResult }) {
  if (result.decision === "refused" || (!result.ok && result.decision !== "failed")) {
    return (
      <div className="mt-2 border-t border-border/50 pt-2 text-[12px] text-warn">
        <span className="font-semibold">Not applied: </span>
        {result.error || "refused"}
        <span className="text-faint"> Nothing was changed.</span>
      </div>
    )
  }
  const restoredText =
    result.rollback_verified === true
      ? "The configuration was restored from the pre-change snapshot, and the restored files match the originals byte for byte."
      : "The configuration was restored from the pre-change snapshot, but the restored files could not be verified. The snapshot was kept and the watchdog will retry; check the container."
  return (
    <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2 text-[12px]">
      <p className="text-[11px] text-faint">
        Plan used: {result.source === "generated" ? "the local model's draft (checked by code)" : "the hand-written fix"}
      </p>
      {result.decision === "failed" ? (
        <p className="font-semibold text-warn">A command failed in the lab: {result.error}</p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-faint">Target:</span>
          <span className="font-mono text-[11.5px]">{result.target}</span>
          <span className="text-faint">· Verdict (measured):</span>
          <span className="font-semibold">{result.verdict_before}</span>
          <span>→</span>
          <span className={cn("font-semibold", result.confirmed_fixed ? "text-emerald-400" : "text-warn")}>
            {result.verdict_after}
          </span>
        </div>
      )}
      {result.confirmed_fixed ? (
        <p className="font-semibold text-emerald-400">
          Confirmed fixed — {result.reason}. The watchdog was disarmed and the change kept.
        </p>
      ) : (
        <div className="rounded border border-warn/30 bg-warn/10 p-2 text-[11.5px] text-warn">
          <p className="font-semibold">Not fixed — the change was undone.</p>
          {result.reason && <p className="mt-0.5 text-foreground/80">{result.reason}.</p>}
          {result.regressions && result.regressions.length > 0 && (
            <p className="mt-0.5 text-foreground/80">Newly failing: {result.regressions.join(", ")}</p>
          )}
          {result.rolled_back && <p className="mt-0.5 leading-relaxed text-foreground/80">{restoredText}</p>}
          {result.service_restored && (
            <p className="mt-0.5 leading-relaxed text-foreground/80">
              {result.service_restored.matches_baseline
                ? "The tunnel was re-negotiated on the restored settings, and a fresh capture matches the pre-change baseline."
                : result.service_restored.tunnel_up
                  ? `The tunnel is up again, but these rules are still worse than before: ${(result.service_restored.worse_than_baseline ?? []).join(", ")}. Check the container.`
                  : "The tunnel did not come back up after the rollback. Check the lab now."}
            </p>
          )}
        </div>
      )}
      {result.rekey && <RekeyLine rekey={result.rekey} ruleId={result.rule_id ?? ""} />}
      {result.commands_run && result.commands_run.length > 0 && (
        <div className="mt-1">
          <span className="text-[11px] text-faint">Commands run on {result.target}:</span>
          <ul className="mt-0.5 space-y-0.5">
            {result.commands_run.map((c, idx) => (
              <li
                key={idx}
                className="select-all rounded border border-border/50 bg-secondary/50 px-2 py-0.5 font-mono text-[11px] text-foreground/80"
              >
                {c}
              </li>
            ))}
          </ul>
        </div>
      )}
      {result.peer && result.peer.commands_run.length > 0 && (
        <p className="text-[11px] text-faint">
          Also changed on the lab peer {result.peer.container} ({result.peer.commands_run.length} commands), undone
          with the target when not confirmed.
        </p>
      )}
    </div>
  )
}

const DRAFT_LABEL =
  "Drafted on this Mac by a local language model (MiniCPM5-2B). Every line was then checked by code, and the change was tried on copies of the config before you see it. The model can be wrong; the checks and the automatic rollback are what protect the lab."

function DraftPanel({
  caps,
  draft,
  drafting,
  seconds,
  choice,
  disabled,
  ruleId,
  onDraft,
  onCancel,
  onChoose,
}: {
  caps: RemediationCapabilities | null
  draft: GenerateResult | null
  drafting: boolean
  seconds: number
  choice: "hand" | "draft"
  disabled: boolean
  ruleId: string
  onDraft: () => void
  onCancel: () => void
  onChoose: (c: "hand" | "draft") => void
}) {
  if (!caps) return null
  if (!caps.generator_enabled) {
    return (
      <p className="text-[11px] text-faint">
        Local-model drafts are switched off until their evaluation (EXP-18) passes. The hand-written fix is used.
      </p>
    )
  }
  if (!caps.local_model) {
    return <p className="text-[11px] text-faint">The local model is not available on this machine.</p>
  }
  return (
    <div className="space-y-2 rounded border border-border/60 bg-background/40 p-2">
      <div className="flex flex-wrap items-center gap-2">
        {drafting ? (
          <>
            <span className="animate-pulse text-[11.5px] text-muted-foreground">
              The local model is drafting, then code checks the draft... {seconds} s
            </span>
            <button
              type="button"
              onClick={onCancel}
              aria-label={`Cancel the local model draft for ${ruleId}`}
              className="text-[11px] text-faint underline hover:text-muted-foreground"
            >
              Cancel
            </button>
          </>
        ) : (
          <button
            type="button"
            onClick={onDraft}
            disabled={disabled}
            aria-label={`Draft a fix with the local model for ${ruleId}`}
            className="rounded border border-border bg-secondary px-2.5 py-1 text-[11.5px] font-medium text-foreground/90 transition-colors hover:text-foreground disabled:opacity-50"
          >
            {draft ? "Draft again" : "Draft a fix with the local model"}
          </button>
        )}
      </div>

      {draft && !draft.ok && <DraftRefused draft={draft} />}

      {draft?.ok && (
        <div className="space-y-2">
          <div className="grid gap-2 md:grid-cols-2">
            <div className="min-w-0">
              <span className="text-[11px] font-medium text-faint">Hand-written fix</span>
              {Object.values(draft.plan.handwritten_diff ?? {}).map((d, i) => (
                <DiffBlock key={i} diff={d} />
              ))}
              {!draft.plan.handwritten_diff && (
                <p className="mt-1 text-[11px] text-faint">The hand-written fix would not change this configuration.</p>
              )}
            </div>
            <div className="min-w-0">
              <span className="text-[11px] font-medium text-faint">Local model's draft</span>
              {Object.values(draft.plan.diff).map((d, i) => (
                <DiffBlock key={i} diff={d} />
              ))}
            </div>
          </div>
          <p className="text-[11.5px] text-foreground/90">
            {draft.plan.agrees_with_handwritten ? "Both make the same change." : "They differ."}
          </p>
          <p className="text-[11px] leading-relaxed text-faint">{DRAFT_LABEL}</p>
          <DraftChecks checks={draft.plan.checks} rounds={draft.plan.revisions.length} />
          {draft.plan.self_review && (
            <p className={cn("text-[11px]", draft.plan.self_review.verdict === "concerns" ? "text-amber-300" : "text-faint")}>
              The model's review of its own draft:{" "}
              {draft.plan.self_review.verdict === "concerns"
                ? `concern: ${draft.plan.self_review.reason}`
                : draft.plan.self_review.verdict === "no concerns"
                  ? "no concerns raised (its opinion, not a check)"
                  : "not available"}
            </p>
          )}
          <fieldset className="flex flex-wrap items-center gap-3 text-[11.5px]">
            <legend className="sr-only">Which plan to preview and apply</legend>
            <label className="flex items-center gap-1.5">
              <input
                type="radio"
                name={`plan-${ruleId}`}
                checked={choice === "hand"}
                onChange={() => onChoose("hand")}
                aria-label={`Use the hand-written fix for ${ruleId}`}
              />
              Use the hand-written fix
            </label>
            <label className="flex items-center gap-1.5">
              <input
                type="radio"
                name={`plan-${ruleId}`}
                checked={choice === "draft"}
                onChange={() => onChoose("draft")}
                aria-label={`Use the local model's draft for ${ruleId}`}
              />
              Use the local model's draft
            </label>
          </fieldset>
        </div>
      )}
    </div>
  )
}

function DraftChecks({ checks, rounds }: { checks: { id: string; name: string; ok: boolean; reason: string | null }[]; rounds: number }) {
  return (
    <div>
      <span className="text-[11px] text-faint">
        Checks run by code{rounds > 1 ? ` (on the model's attempt ${rounds}; earlier attempts failed a check)` : ""}:
      </span>
      <ul className="mt-0.5 space-y-0.5">
        {checks.map((c) => (
          <li key={c.id} className="flex gap-2 text-[11px]">
            <span className={cn("w-12 shrink-0 font-mono", c.ok ? "text-emerald-400" : "text-warn")}>{c.ok ? "passed" : "failed"}</span>
            <span className="text-muted-foreground">
              {c.name}
              {!c.ok && c.reason ? `. Reason: ${c.reason}` : ""}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function DraftRefused({ draft }: { draft: Extract<GenerateResult, { ok: false }> }) {
  const last = draft.revisions?.[draft.revisions.length - 1]
  const failed = draft.checks?.find((c) => !c.ok)
  return (
    <div className="space-y-1 rounded border border-warn/30 bg-warn/10 p-2 text-[11.5px]">
      <p className="font-semibold text-warn">
        {failed ? "The local model's draft did not pass the checks." : "No draft from the local model."}
      </p>
      {failed ? (
        <p className="text-foreground/80">
          <span className="text-faint">Failed check {failed.id} ({failed.name}). </span>
          Reason: {failed.reason ?? "not given"}
        </p>
      ) : (
        <p className="text-foreground/80">{draft.reason || draft.error || "it could not be drafted"}</p>
      )}
      {draft.revisions && draft.revisions.length > 1 && (
        <p className="text-faint">The model was told which check failed and tried {draft.revisions.length} times.</p>
      )}
      {last?.raw_output && (
        <details>
          <summary className="cursor-pointer text-faint">What the model proposed</summary>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-secondary/60 p-1.5 font-mono text-[10.5px] text-foreground/80">
            {last.raw_output}
          </pre>
        </details>
      )}
      <p className="text-faint">Nothing was changed. The hand-written fix is still available above.</p>
    </div>
  )
}

function RekeyLine({ rekey, ruleId }: { rekey: NonNullable<RemediationApplyResult["rekey"]>; ruleId: string }) {
  if (rekey.tunnel_after_rekey === false) {
    return (
      <p className="text-[11.5px] text-warn">
        After a forced rekey the endpoint no longer reported the tunnel as up, so the change was not kept.
      </p>
    )
  }
  if (rekey.tunnel_after_rekey !== true) {
    return <p className="text-[11px] text-faint">The forced rekey could not be checked{rekey.error ? `: ${rekey.error}` : "."}</p>
  }
  const ep = rekey.endpoint_reported
  return (
    <p className="text-[11px] leading-relaxed text-muted-foreground">
      The tunnel stayed up after a forced rekey. What the rekey negotiated is encrypted, so it is not visible on the
      wire (not observable passively).
      {ep && ep.algorithms.length > 0 && (
        <>
          {" "}
          The endpoint itself reports {ep.algorithms.join(", ")}
          {ep.rule_verdict !== "UNKNOWN" ? ` (${ruleId} would be ${ep.rule_verdict} on those)` : ""}; this is the
          endpoint's own report, not evidence.
        </>
      )}
    </p>
  )
}
