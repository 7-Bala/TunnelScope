# Task 08: remediation plan panel in the dashboard — Stage 2 (still no execution)

Purpose: Stage 1 (`task/remediation-plan-stage1`, merged) built a read-only `/api/remediate/plan`
API endpoint but nothing in the dashboard calls it — a judge or the owner looking at the site
sees no remediation UI at all. This task makes the plan VISIBLE: a "Propose fix" control on each
failed verdict, showing the plan, with Approve/Reject buttons. **Approve does NOT apply anything
— Stage 3 (real execution against the lab) does not exist yet.** Clicking Approve must not claim
or imply a fix was applied; it only records the human's decision client-side. Getting this
distinction wrong — implying something was patched when it wasn't — is the one thing that must
not happen in this task.

- Branch: `task/remediation-plan-dashboard-ui`
- You may edit: `fleet-dashboard/src/components/dashboard/FleetRegister.tsx`,
  `fleet-dashboard/src/components/dashboard/RemediationPane.tsx` (new file),
  `fleet-dashboard/src/lib/api.ts`, `TODO.md`
- Do NOT edit: any Python file, any file under `tunnelscope/` — this task is dashboard-only, the
  API endpoint it calls already exists and does not change.
- Run checks as: `ALLOW="fleet-dashboard/src/components/dashboard/FleetRegister.tsx fleet-dashboard/src/components/dashboard/RemediationPane.tsx fleet-dashboard/src/lib/api.ts TODO.md" build/check_all.sh --fast`

## PROMPT (paste everything below this line)

Read `AGENTS.md`, `.agents/rules/00-golden-rules.md` and `.agents/rules/20-dashboard.md` first.
Then read `build/09-REMEDIATION-ROADMAP.md`'s "Stage 2: the human gate" section and
`fleet-dashboard/src/components/dashboard/FleetRegister.tsx` completely (it's the file with the
`Detail` component and the Verdicts table you're extending). Create branch
`task/remediation-plan-dashboard-ui` from `main`.

STEP 1. Add a typed API call to `fleet-dashboard/src/lib/api.ts`, following the existing style of
`analyzeCapture`/`liveStatus` in the same file (same error handling pattern, same `fetch` usage):

```ts
export type RemediationPlan = {
  rule_id: string
  change: string
  commands: string[]
  auto_applicable: boolean
  observed: unknown
}

export async function remediationPlan(ruleId: string, observed?: unknown): Promise<RemediationPlan | null> {
  try {
    const res = await fetch("/api/remediate/plan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rule_id: ruleId, observed: observed ?? null }),
    })
    if (!res.ok) return null
    return (await res.json()) as RemediationPlan
  } catch {
    return null
  }
}
```

Adapt to match the file's actual conventions if they differ from this sketch (e.g. if there's a
shared fetch wrapper already, use it) — read the file first, don't just paste blindly.

STEP 2. Write `fleet-dashboard/src/components/dashboard/RemediationPane.tsx`, a new component
`RemediationControl({ ruleId, observed }: { ruleId: string; observed?: unknown })`:

  - Renders a small "Propose fix" button/link. On click, calls `remediationPlan(ruleId, observed)`
    and shows a loading state while waiting.
  - If the call returns `null` (unknown rule, or the rule has no remediation entry — e.g. a
    diagnostic-only rule like `CVE-2026-78135` or `RFC4303-SEQ` will still return a plan with
    `auto_applicable: false`, but a truly unmapped rule ID returns `null`): show nothing, or a
    quiet "no fix available for this finding" note — do not show an error banner for this
    expected case.
  - If a plan comes back, show:
    - The `change` text.
    - The `commands` list (as a small code-styled list, monospace, matching how the rest of the
      dashboard shows technical detail — look at `TunnelAI.tsx`'s existing panels for the visual
      language, e.g. the `font-mono text-[12px]` pattern used elsewhere in this codebase).
    - If `auto_applicable` is `false`: a clearly visible note, e.g. "Advisory only — this needs a
      software patch or investigation, not a config change." No Approve/Apply button at all for
      this case, only an acknowledge/dismiss.
    - If `auto_applicable` is `true`: two buttons, **Approve** and **Reject**. Neither makes a
      network call — Stage 3 doesn't exist. On Approve, show a state change to something like
      "Approved — not yet applied. Execution is not built in this version." On Reject, show
      "Declined." Store this decision in local component state only (useState is fine; it does
      not need to persist across reloads for this task — do not build a backend for it, do not
      call `localStorage` either, keep it simple and clearly ephemeral).
    - **Nowhere in this component may the words "applied", "fixed", "patched", or "done" appear
      in connection with the Approve action** — the honest words are "approved" (a decision was
      recorded) and "not yet applied" (nothing happened to the tunnel). Write a comment in the
      code at the point where this label is set explaining why the wording matters (link to
      DEC-031/DEC-032's discipline if you want, or just state it plainly), so a future editor
      doesn't casually change it to something that overclaims.

STEP 3. Wire it into `FleetRegister.tsx`'s Verdicts table (`pane === "verdicts"` block). For each
row where `v.verdict === "FAIL"`, add a `<RemediationControl ruleId={v.rule_id} observed={v.observed} />`
in the Detail column, after the existing text, not replacing it. Rows that are not FAIL (PASS,
UNKNOWN, etc.) get nothing added — there's nothing to remediate. Read the existing `<tr>`/`<td>`
structure and match its exact styling conventions (`text-[12.5px]`, `text-muted-foreground`,
spacing) rather than inventing new classes.

STEP 4. Visual QA. Use `preview_start`/the browser tools available in this environment: load the
dashboard, upload a sample capture with failing rules (or use one already in the repo's
`testbed/captures/` set — check `README.md` for how to start the engine and dashboard together,
likely `./start.sh`), open a capture with FAIL verdicts, click "Propose fix" on at least one
`auto_applicable: true` finding and one `auto_applicable: false` finding (e.g. `CVE-2026-78135`
or `RFC4303-SEQ`), click Approve, and take a screenshot of each state (collapsed, plan shown,
approved). Confirm zero console errors. Confirm the page still works at 375px width (mobile —
this project tests that on every dashboard change, check `DESIGN.md` if it exists for the
convention).

STEP 5. `ALLOW="fleet-dashboard/src/components/dashboard/FleetRegister.tsx fleet-dashboard/src/components/dashboard/RemediationPane.tsx fleet-dashboard/src/lib/api.ts TODO.md" build/check_all.sh --fast`
must be `RESULT: PASS` (tsc, lint, build). Add one line to `TODO.md`. Commit:
`T-095: remediation plan panel in the dashboard, Stage 2 (approve/reject only, no execution)`,
with no Co-Authored-By line.

REPORT: the check table, the screenshots from STEP 4, confirmation of 0 console errors, and an
explicit statement of where in the code the "not yet applied" wording lives so it's easy to find
and check.

## DONE WHEN

- A judge or the owner can see and click "Propose fix" on a real failing finding in the browser
  and it shows the real plan from the real API — not mocked.
- Approve/Reject exist but visibly, unambiguously do NOT claim anything was applied — verified by
  reading the actual rendered text, not just that a button exists.
- `RESULT: PASS`, 0 console errors, works at 375px.
- No Python file touched.
