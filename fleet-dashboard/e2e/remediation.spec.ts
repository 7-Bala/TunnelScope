// Browser tests for the remediation pane with a mocked engine (build/13 T-105, B1-01..B1-18).
// Runs in CI: the built dashboard is served by `vite preview`, and every /api call is answered by
// the typed fixtures in ./fixtures.ts. Each case runs at 1440x900 and 375x812, light and dark.
import { expect, test, type Page, type Request, type Route } from "@playwright/test"
import {
  ANALYZE, APPLY_CONFIRMED, APPLY_CONFIRMED_REKEY, APPLY_REKEY_DOWN, APPLY_ROLLED_BACK, APPLY_STALE, CAPS_CLOUD_NO_KEY, CAPS_CLOUD_ON,
  CAPS_NO_MODEL, CAPS_OFF, CAPS_ON, CAPTURE,
  DRAFT_AGREES, DRAFT_AGREES_CLOUD, DRAFT_DIFFERS_CONCERN, DRAFT_REFUSED_V4, PLAN, PREVIEW_DRAFT, PREVIEW_HAND, TARGETS,
} from "./fixtures.ts"
import type { GenerateResult, RemediationApplyResult, RemediationCapabilities, RemediationPreview } from "../src/lib/api.ts"

const RULE = "V-207193"
const FORBIDDEN = /guarantee|AI-Assisted|100%|compliant|fully secure/i

type Engine = {
  caps?: RemediationCapabilities
  preview?: (body: Record<string, unknown>) => RemediationPreview
  apply?: RemediationApplyResult
  generate?: GenerateResult
  generateDelayMs?: number
}

type Seen = { preview: Record<string, unknown>[]; apply: Record<string, unknown>[]; generate: number; consoleErrors: string[] }

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) })

async function mockEngine(page: Page, engine: Engine): Promise<Seen> {
  const seen: Seen = { preview: [], apply: [], generate: 0, consoleErrors: [] }
  page.on("console", (m) => m.type() === "error" && seen.consoleErrors.push(m.text()))
  page.on("pageerror", (e) => seen.consoleErrors.push(`pageerror: ${e.message}`))
  const body = (r: Request) => (r.postData() ? JSON.parse(r.postData() as string) : {})
  await page.route("**/health", (r) => json(r, { ok: true, dashboard: true, history: false, live: false }))
  await page.route("**/api/analyze**", (r) => json(r, ANALYZE))
  await page.route("**/api/live", (r) => json(r, { ok: true, enabled: false }))
  await page.route("**/api/history", (r) => json(r, { ok: true, tunnels: [] }))
  await page.route("**/api/remediate/plan", (r) => json(r, PLAN))
  await page.route("**/api/remediate/targets", (r) => json(r, TARGETS))
  await page.route("**/api/remediate/capabilities", (r) => json(r, engine.caps ?? CAPS_OFF))
  await page.route("**/api/remediate/preview", (r) => {
    const b = body(r.request())
    seen.preview.push(b)
    const res = (engine.preview ?? (() => PREVIEW_HAND))(b)
    return json(r, res, res.ok ? 200 : 400)
  })
  await page.route("**/api/remediate/apply", (r) => {
    seen.apply.push(body(r.request()))
    const res = engine.apply ?? APPLY_CONFIRMED
    return json(r, res, res.decision === "refused" ? 400 : 200)
  })
  await page.route("**/api/remediate/generate", async (r) => {
    seen.generate++
    if (engine.generateDelayMs) await new Promise((ok) => setTimeout(ok, engine.generateDelayMs))
    return json(r, engine.generate ?? DRAFT_REFUSED_V4).catch(() => {})
  })
  return seen
}

async function openPane(page: Page) {
  await page.goto("/")
  await page.locator("input[type=file]").setInputFiles(CAPTURE)
  await page.locator("[data-state][aria-expanded]").first().click()
  await page.getByRole("tab", { name: /Verdicts/ }).click()
  await page.getByRole("button", { name: `Propose fix for ${RULE}` }).click()
  const pane = page.getByTestId(`remediation-pane-${RULE}`)
  await expect(pane).toBeVisible()
  return pane
}

async function approve(page: Page) {
  await page.getByRole("button", { name: `Approve remediation plan for ${RULE}` }).click()
  await expect(page.getByRole("button", { name: `Preview the real change for ${RULE}` })).toBeVisible()
}

/** B1-14/15/16/17, checked at the end of every case. */
async function invariants(page: Page, seen: Seen, allowedConsole: RegExp[] = []) {
  const pane = page.getByTestId(`remediation-pane-${RULE}`)
  const { scroll, inner } = await page.evaluate(() => ({ scroll: document.scrollingElement!.scrollWidth, inner: window.innerWidth }))
  expect(scroll, "no horizontal page scroll").toBeLessThanOrEqual(inner)
  expect(await pane.innerText()).not.toMatch(FORBIDDEN)
  const unnamed = await pane.locator("button, select, input").evaluateAll((els) =>
    els.filter((e) => !(e.getAttribute("aria-label") || e.textContent || "").trim()).map((e) => e.outerHTML.slice(0, 80)),
  )
  expect(unnamed, "every control has an accessible name").toEqual([])
  const unexpected = seen.consoleErrors.filter((t) => !allowedConsole.some((a) => a.test(t)))
  expect(unexpected, "no console errors except the expected ones").toEqual([])
}

const HTTP_400 = /status of 400/

for (const vp of [{ width: 1440, height: 900 }, { width: 375, height: 812 }]) {
  for (const colorScheme of ["light", "dark"] as const) {
    test.describe(`${vp.width}px ${colorScheme}`, () => {
      test.use({ viewport: vp, colorScheme })

      test("B1-01 hand-written plan: Apply needs a preview; no draft UI when drafts are off", async ({ page }) => {
        const seen = await mockEngine(page, { caps: CAPS_OFF })
        const pane = await openPane(page)
        await approve(page)
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeDisabled()
        await expect(page.getByRole("button", { name: `Preview the real change for ${RULE}` })).toBeEnabled()
        await expect(pane.getByText("Local-model drafts are switched off")).toBeVisible()
        await expect(page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` })).toHaveCount(0)
        await invariants(page, seen)
      })

      test("B1-02 preview shows the real diff and enables Apply", async ({ page }) => {
        const seen = await mockEngine(page, {})
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await expect(pane.getByText("+        proposals = aes128-sha1-modp4096").first()).toBeVisible()
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeEnabled()
        expect(seen.preview[0]).toMatchObject({ rule_id: RULE, target: "sih26-alice-pq", plan_id: null })
        await invariants(page, seen)
      })

      test("B1-03 changing the target clears the preview", async ({ page }) => {
        const seen = await mockEngine(page, {})
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeEnabled()
        await page.getByRole("combobox", { name: `Select lab container target for ${RULE}` }).selectOption("sih26-bob-pq")
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeDisabled()
        await expect(pane.getByText("aes128-sha1-modp4096")).toHaveCount(0)
        await invariants(page, seen)
      })

      test("B1-04 apply sends the digest; confirmed only when the engine says so", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_CONFIRMED })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText(/Confirmed fixed/)).toBeVisible()
        await expect(pane.getByText("Plan used: the hand-written fix")).toBeVisible()
        expect(seen.apply).toHaveLength(1)
        expect(seen.apply[0]).toMatchObject({ digest: PREVIEW_HAND.digest, plan_id: null, confirm: true })
        await invariants(page, seen)
      })

      test("B1-19 rekey: confirmed fix says what the rekey shows and what it cannot", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_CONFIRMED_REKEY })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText(/Confirmed fixed/)).toBeVisible()
        const line = pane.getByText(/stayed up after a forced rekey/)
        await expect(line).toBeVisible()
        await expect(line).toContainText("not observable passively")
        await expect(line).toContainText("The endpoint itself reports AES_CBC_256, HMAC_SHA2_256_128, PRF_HMAC_SHA2_256, MODP_4096")
        await expect(line).toContainText("V-207193 would be PASS on those")
        await expect(line).toContainText("not evidence")
        await invariants(page, seen)
      })

      test("B1-20 rekey: a tunnel that does not survive is shown as not kept, never fixed", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_REKEY_DOWN })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText(/no longer reported the tunnel as up, so the change was not kept/)).toBeVisible()
        await expect(pane.getByText("Not fixed — the change was undone.")).toBeVisible()
        await expect(pane.getByText(/Confirmed fixed/)).toHaveCount(0)
        await invariants(page, seen)
      })

      test("B1-05 rolled back: says so, lists regressions, never says fixed", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_ROLLED_BACK })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText("Not fixed — the change was undone.")).toBeVisible()
        await expect(pane.getByText("Newly failing: RFC8247-DH-MUST")).toBeVisible()
        await expect(pane.getByText(/match the originals byte for byte/)).toBeVisible()
        await expect(pane.getByText(/Confirmed fixed/)).toHaveCount(0)
        await invariants(page, seen)
      })

      test("B1-21 connection lost during apply: result not known, never 'nothing was changed'", async ({ page }) => {
        // Found in the 2026-09-25 E2E run: the engine was killed mid-apply after the lab had been
        // changed, and the pane said "Nothing was changed".
        const seen = await mockEngine(page, {})
        await page.route("**/api/remediate/apply", (r) => r.abort("connectionreset"))
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText(/Result not known/)).toBeVisible()
        await expect(pane.getByText(/may already have been made in the lab/)).toBeVisible()
        await expect(pane.getByText(/Nothing was changed/)).toHaveCount(0)
        await expect(pane.getByText(/Confirmed fixed/)).toHaveCount(0)
        await invariants(page, seen, [/Failed to load resource/])
      })

      test("B1-22 server error during apply: result not known, with the watchdog timeout", async ({ page }) => {
        const seen = await mockEngine(page, {})
        await page.route("**/api/remediate/apply", (r) =>
          json(r, { ok: false, stage: "execute", decision: "unknown", error: "unexpected server error during remediation", watchdog_timeout_s: 180 }, 500))
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText(/Result not known/)).toBeVisible()
        await expect(pane.getByText(/within 180 seconds/)).toBeVisible()
        await expect(pane.getByText(/Nothing was changed/)).toHaveCount(0)
        await invariants(page, seen, [/status of 500/])
      })

      test("B1-06 stale preview: refused, and a new preview is required", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_STALE })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText(/not what you previewed/)).toBeVisible()
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeDisabled()
        await invariants(page, seen, [HTTP_400])
      })

      test("B1-23 cloud backend, no key: distinct line from the local-model case", async ({ page }) => {
        const seen = await mockEngine(page, { caps: CAPS_CLOUD_NO_KEY })
        const pane = await openPane(page)
        await approve(page)
        await expect(pane.getByText("The cloud model is not configured (no API key).")).toBeVisible()
        await expect(pane.getByText("The local model is not available on this machine.")).toHaveCount(0)
        await expect(page.getByRole("button", { name: `Draft a fix with the cloud model for ${RULE}` })).toHaveCount(0)
        expect(seen.generate).toBe(0)
        await invariants(page, seen)
      })

      test("B1-24 cloud backend: sending-data disclosure shown, draft labelled as cloud, network sent to the engine only", async ({ page }) => {
        const seen = await mockEngine(page, {
          caps: CAPS_CLOUD_ON,
          generate: DRAFT_AGREES_CLOUD,
          preview: (b) => (b.plan_id ? { ...PREVIEW_DRAFT, plan_id: b.plan_id as string } : PREVIEW_HAND),
        })
        const pane = await openPane(page)
        await approve(page)
        await expect(pane.getByText(/sends the failing rule and the lab connection.s current settings to that service/)).toBeVisible()
        await page.getByRole("button", { name: `Draft a fix with the cloud model for ${RULE}` }).click()
        await expect(pane.getByText("Cloud model's draft", { exact: true })).toBeVisible()
        await expect(pane.getByText(/Drafted by a cloud model this machine sent a request to/)).toBeVisible()
        await expect(page.getByRole("radio", { name: `Use the cloud model's draft for ${RULE}` })).toBeVisible()
        expect(seen.generate).toBe(1)
        await invariants(page, seen)
      })

      test("B1-07 model unavailable: a plain line, no draft button", async ({ page }) => {
        const seen = await mockEngine(page, { caps: CAPS_NO_MODEL })
        const pane = await openPane(page)
        await approve(page)
        await expect(pane.getByText("The local model is not available on this machine.")).toBeVisible()
        await expect(page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` })).toHaveCount(0)
        expect(seen.generate).toBe(0)
        await invariants(page, seen)
      })

      test("B1-08 + B1-18 refused draft: failed check named, long raw output stays in its box", async ({ page }) => {
        const seen = await mockEngine(page, { caps: CAPS_ON, generate: DRAFT_REFUSED_V4 })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` }).click()
        await expect(pane.getByText("The local model's draft did not pass the checks.")).toBeVisible()
        await expect(pane.getByText(/modp3076' is not a keyword/)).toBeVisible()
        await expect(pane.getByText(/tried 3 times/)).toBeVisible()
        await expect(page.getByRole("radio", { name: `Use the local model's draft for ${RULE}` })).toHaveCount(0)
        const raw = pane.locator("details pre")
        await expect(raw).toBeHidden()
        await pane.getByText("What the model proposed").click()
        await expect(raw).toBeVisible()
        await invariants(page, seen)
      })

      test("B1-09 draft agrees: both columns, all checks listed, draft previewed and applied by its id", async ({ page }) => {
        const seen = await mockEngine(page, {
          caps: CAPS_ON,
          generate: DRAFT_AGREES,
          preview: (b) => (b.plan_id ? { ...PREVIEW_DRAFT, plan_id: b.plan_id as string } : PREVIEW_HAND),
          apply: { ...APPLY_CONFIRMED, source: "generated" },
        })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` }).click()
        await expect(pane.getByText("Both make the same change.")).toBeVisible()
        await expect(pane.getByText("Hand-written fix", { exact: true })).toBeVisible()
        await expect(pane.getByText("Local model's draft", { exact: true })).toBeVisible()
        await expect(pane.getByText(/Drafted on this Mac by a local language model/)).toBeVisible()
        await expect(pane.locator("li", { hasText: "passed" })).toHaveCount(10)
        await expect(page.getByRole("radio", { name: `Use the hand-written fix for ${RULE}` })).toBeChecked()
        await page.getByRole("radio", { name: `Use the local model's draft for ${RULE}` }).check()
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
        await expect(pane.getByText("Plan used: the local model's draft (checked by code)")).toBeVisible()
        expect(seen.preview.at(-1)).toMatchObject({ plan_id: DRAFT_AGREES.ok ? DRAFT_AGREES.plan_id : "" })
        expect(seen.apply[0]).toMatchObject({ plan_id: DRAFT_AGREES.ok ? DRAFT_AGREES.plan_id : "", digest: PREVIEW_DRAFT.digest })
        await invariants(page, seen)
      })

      test("B1-10 draft differs with a self-review concern: Apply needs a second, explicit step", async ({ page }) => {
        const seen = await mockEngine(page, {
          caps: CAPS_ON,
          generate: DRAFT_DIFFERS_CONCERN,
          preview: (b) => (b.plan_id ? PREVIEW_DRAFT : PREVIEW_HAND),
        })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` }).click()
        await expect(pane.getByText("They differ.")).toBeVisible()
        await expect(pane.getByText(/concern: ecp384 may not be offered/)).toBeVisible()
        await page.getByRole("radio", { name: `Use the local model's draft for ${RULE}` }).check()
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        // wait until the preview has arrived, so "disabled" is not just "still previewing"
        await expect(pane.getByText("The model's own review raised a concern:")).toBeVisible()
        await expect(pane.getByText("+        proposals = aes128-sha1-ecp384").first()).toBeVisible()
        const apply = page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })
        await expect(apply).toBeDisabled()
        await page.getByRole("button", { name: `I have read the concern, allow Apply for ${RULE}` }).click()
        await expect(apply).toBeEnabled()
        await invariants(page, seen)
      })

      test("B1-11 cancel during drafting: a late answer changes nothing", async ({ page }) => {
        const seen = await mockEngine(page, { caps: CAPS_ON, generate: DRAFT_AGREES, generateDelayMs: 1500 })
        const pane = await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` }).click()
        await expect(pane.getByText(/The local model is drafting/)).toBeVisible()
        await page.getByRole("button", { name: `Cancel the local model draft for ${RULE}` }).click()
        await page.waitForTimeout(2000)
        await expect(pane.getByText("Both make the same change.")).toHaveCount(0)
        await expect(page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` })).toBeVisible()
        await invariants(page, seen)
      })

      test("B1-12 double-click on Apply sends one request", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_CONFIRMED })
        await openPane(page)
        await approve(page)
        await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeEnabled()
        // two clicks in the same event-loop turn: React has not re-rendered (or disabled the button) in between
        await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).evaluate((b) => {
          ;(b as HTMLButtonElement).click()
          ;(b as HTMLButtonElement).click()
        })
        await expect(page.getByTestId(`remediation-pane-${RULE}`).getByText(/Confirmed fixed/)).toBeVisible()
        await page.waitForTimeout(300)
        expect(seen.apply).toHaveLength(1)
        await invariants(page, seen)
      })

      test("B1-13 keyboard only: every step reachable, focus visible", async ({ page }) => {
        const seen = await mockEngine(page, { apply: APPLY_CONFIRMED })
        await page.goto("/")
        await page.locator("input[type=file]").setInputFiles(CAPTURE)
        await page.locator("[data-state][aria-expanded]").first().click()
        await page.getByRole("tab", { name: /Verdicts/ }).click()
        const pressOn = async (label: string) => {
          // real keyboard navigation: Tab until the control has focus
          for (let i = 0; i < 250; i++) {
            if ((await page.evaluate(() => document.activeElement?.getAttribute("aria-label"))) === label) break
            await page.keyboard.press("Tab")
          }
          expect(await page.evaluate(() => document.activeElement?.getAttribute("aria-label")), `Tab reaches "${label}"`).toBe(label)
          const el = page.getByRole("button", { name: label })
          const visible = await el.evaluate((e) => {
            const s = getComputedStyle(e)
            return (s.outlineStyle !== "none" && parseFloat(s.outlineWidth) > 0) || s.boxShadow !== "none"
          })
          expect(visible, `focus is visible on "${label}"`).toBe(true)
          await page.keyboard.press("Enter")
        }
        await pressOn(`Propose fix for ${RULE}`)
        await pressOn(`Approve remediation plan for ${RULE}`)
        await pressOn(`Preview the real change for ${RULE}`)
        await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeEnabled()
        await pressOn(`Apply remediation in lab for ${RULE}`)
        await expect(page.getByTestId(`remediation-pane-${RULE}`).getByText(/Confirmed fixed/)).toBeVisible()
        await invariants(page, seen)
      })
    })
  }
}
