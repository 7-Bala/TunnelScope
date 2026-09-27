// DEC-044 browser test with a mocked engine (runs in CI with the mock project): a real gateway can be
// changed only after its terms and risks are accepted in the UI, and Apply stays disabled until the
// exact per-change sentence is typed. The same flow against two real gateways: gateway.live.spec.ts.
import { expect, test, type Page, type Request, type Route } from "@playwright/test"
import { ANALYZE, APPLY_CONFIRMED, CAPS_OFF, CAPTURE, PLAN, PREVIEW_HAND, TARGETS } from "./fixtures.ts"
import type { RemediationPreview } from "../src/lib/api.ts"

const RULE = "V-207193"
const ACK = "APPLY V-207193 ON office-a"
const TERMS = { ok: true, version: "2026-09-27.1", title: "TunnelScope live gateway changes: terms and risks",
  clauses: ["What TunnelScope will do.", "The tunnel will go down for a short time."], sha256: "b".repeat(64) }
const PREVIEW_LIVE: RemediationPreview = {
  ...PREVIEW_HAND,
  peer: null,
  live: { gateway: "office-a", host: "192.168.77.10", connection: "office-link", peer: null, ack_phrase: ACK,
    risks: ["The tunnel 'office-link' on office-a restarts about three times during this change.", "You are approving V-207193 on a real gateway, not the lab."],
    watchdog_timeout_s: 180 },
}
const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) })

async function mock(page: Page) {
  const seen = { accept: [] as Record<string, unknown>[], apply: [] as Record<string, unknown>[], errors: [] as string[] }
  let accepted = false
  const body = (r: Request) => (r.postData() ? JSON.parse(r.postData() as string) : {})
  page.on("console", (m) => m.type() === "error" && seen.errors.push(m.text()))
  await page.route("**/health", (r) => json(r, { ok: true, dashboard: true, history: false, live: false }))
  await page.route("**/api/analyze**", (r) => json(r, ANALYZE))
  await page.route("**/api/live", (r) => json(r, { ok: true, enabled: false }))
  await page.route("**/api/history", (r) => json(r, { ok: true, tunnels: [] }))
  await page.route("**/api/remediate/plan", (r) => json(r, PLAN))
  await page.route("**/api/remediate/capabilities", (r) => json(r, CAPS_OFF))
  await page.route("**/api/remediate/targets", (r) => json(r, { ...TARGETS, gateways: [{
    name: "gw:office-a", host: "192.168.77.10", connection: "office-link", accepted, accept_phrase: "I ACCEPT THE RISKS FOR office-a",
    consent: { accepted, reason: accepted ? null : "the terms and risks have not been accepted for this gateway" } }] }))
  await page.route("**/api/remediate/terms", (r) => json(r, TERMS))
  await page.route("**/api/remediate/terms/accept", (r) => {
    const b = body(r.request())
    seen.accept.push(b)
    accepted = b.typed === "I ACCEPT THE RISKS FOR office-a"
    return json(r, accepted ? { ok: true } : { ok: false, error: "type exactly" }, accepted ? 200 : 400)
  })
  await page.route("**/api/remediate/preview", (r) => json(r, PREVIEW_LIVE))
  await page.route("**/api/remediate/apply", (r) => {
    seen.apply.push(body(r.request()))
    return json(r, { ...APPLY_CONFIRMED, target: "gw:office-a" })
  })
  return seen
}

test("a real gateway needs accepted terms, then the exact per-change sentence", async ({ page }) => {
  const seen = await mock(page)
  await page.goto("/")
  await page.locator("input[type=file]").setInputFiles(CAPTURE)
  await page.locator("[data-state][aria-expanded]").first().click()
  await page.getByRole("tab", { name: /Verdicts/ }).click()
  await page.getByRole("button", { name: `Propose fix for ${RULE}` }).click()
  await page.getByRole("button", { name: `Approve remediation plan for ${RULE}` }).click()
  const pane = page.getByTestId(`remediation-pane-${RULE}`)

  await page.getByRole("combobox", { name: `Select lab container target for ${RULE}` }).selectOption("gw:office-a")
  const terms = pane.getByTestId("gateway-terms")
  await expect(terms).toBeVisible()
  await expect(terms.getByText("The tunnel will go down for a short time.")).toBeVisible()
  await expect(page.getByRole("button", { name: `Preview the real change for ${RULE}` })).toBeDisabled()
  const acceptBtn = terms.getByRole("button", { name: "I accept the terms and risks" })
  await terms.getByLabel("Name of the person accepting").fill("Test Operator")
  await terms.getByLabel("Type the acceptance sentence").fill("i accept")
  await expect(acceptBtn).toBeDisabled()
  await terms.getByLabel("Type the acceptance sentence").fill("I ACCEPT THE RISKS FOR office-a")
  await acceptBtn.click()
  await expect(terms).toBeHidden()
  expect(seen.accept[0]).toMatchObject({ target: "gw:office-a", accepted_by: "Test Operator", terms_sha256: TERMS.sha256 })

  await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
  const risks = pane.getByTestId("live-risks")
  await expect(risks).toBeVisible()
  await expect(risks.getByText(/not the lab/)).toBeVisible()
  const apply = page.getByRole("button", { name: `Apply remediation to real gateway for ${RULE}` })
  await expect(apply).toBeDisabled()
  await risks.getByLabel(`Type the confirmation sentence for ${RULE}`).fill("APPLY V-207193")
  await expect(apply).toBeDisabled()
  await risks.getByLabel(`Type the confirmation sentence for ${RULE}`).fill(ACK)
  await expect(apply).toBeEnabled()
  await apply.click()
  await expect(pane.getByText(/Confirmed fixed/)).toBeVisible()
  expect(seen.apply[0]).toMatchObject({ target: "gw:office-a", risk_ack: ACK, digest: PREVIEW_HAND.digest })
  expect(seen.errors).toEqual([])
})
