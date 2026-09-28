// DEC-049 live browser test: the real engine, two REAL strongSwan gateways reached only over SSH
// (testbed/live-gateway/setup.sh), a fresh history folder with both gateways registered but no terms
// accepted. Local only, as root:
//   sudo testbed/live-gateway/teardown.sh && sudo testbed/live-gateway/setup.sh
//   (register office-a with --peer office-b and office-b in $E2E_HISTORY, start `tunnelscope serve
//    --port 8767 --history $E2E_HISTORY`), then
//   E2E_LIVE=1 E2E_HISTORY=... npx playwright test --project=gateway
import { readFileSync } from "node:fs"
import { expect, test } from "@playwright/test"
import { CAPTURE } from "./fixtures.ts"

const RULE = "V-207193"
const HISTORY = process.env.E2E_HISTORY ?? ""
const CONF = "/srv/tunnelscope-gw/office-a/swanctl/swanctl.conf"

test("a real gateway is fixed through the UI after the terms and the per-change sentence", async ({ page }) => {
  expect(HISTORY, "E2E_HISTORY must name the engine's history folder").not.toBe("")
  expect(readFileSync(CONF, "utf8")).toContain("proposals = aes256-sha256-modp2048")
  const errors: string[] = []
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()))
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
  await page.screenshot({ path: "test-results/gateway-terms.png", fullPage: true })
  await terms.getByLabel("Name of the person accepting").fill("Browser Test Operator")
  await terms.getByLabel("Type the acceptance sentence").fill("I ACCEPT THE RISKS FOR office-a")
  await terms.getByRole("button", { name: "I accept the terms and risks" }).click()
  await expect(terms).toBeHidden()
  // the other end is changed too, so its terms must also be accepted: the engine refuses otherwise
  await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
  await expect(pane.getByText(/gw:office-b: the terms and risks have not been accepted/)).toBeVisible()
  await page.getByRole("combobox", { name: `Select lab container target for ${RULE}` }).selectOption("gw:office-b")
  await terms.getByLabel("Name of the person accepting").fill("Browser Test Operator")
  await terms.getByLabel("Type the acceptance sentence").fill("I ACCEPT THE RISKS FOR office-b")
  await terms.getByRole("button", { name: "I accept the terms and risks" }).click()
  await expect(terms).toBeHidden()
  await page.getByRole("combobox", { name: `Select lab container target for ${RULE}` }).selectOption("gw:office-a")

  await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
  await expect(pane.getByText(/proposals = aes256-sha256-modp4096/).first()).toBeVisible()
  const risks = pane.getByTestId("live-risks")
  await expect(risks).toBeVisible()
  await risks.getByLabel(`Type the confirmation sentence for ${RULE}`).fill("APPLY V-207193 ON office-a")
  await page.screenshot({ path: "test-results/gateway-risks.png", fullPage: true })
  await page.getByRole("button", { name: `Apply remediation to real gateway for ${RULE}` }).click()
  await expect(pane.getByText(/Confirmed fixed/)).toBeVisible()
  await page.screenshot({ path: "test-results/gateway-applied.png", fullPage: true })

  expect(readFileSync(CONF, "utf8")).toContain("proposals = aes256-sha256-modp4096")
  const log = readFileSync(`${HISTORY}/remediate.jsonl`, "utf8").trim().split("\n").map((l) => JSON.parse(l))
  expect(log.filter((x) => x.decision === "terms_accepted").map((x) => x.accepted_by)).toContain("Browser Test Operator")
  expect(log.filter((x) => x.decision === "applied").at(-1)).toMatchObject({
    target: "gw:office-a", live: true, risk_ack: "APPLY V-207193 ON office-a", confirmed_fixed: true,
    verdict_before: "FAIL", verdict_after: "PASS",
  })
  // the one expected error: the browser logs the deliberately refused preview (HTTP 400) above
  expect(errors.filter((e) => !/status of 400/.test(e))).toEqual([])
  expect(errors.filter((e) => /status of 400/.test(e))).toHaveLength(1)
})
