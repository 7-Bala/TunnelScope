// Live browser tests (build/13 T-105 B2): the real engine, the real local model and the real Docker
// lab. Local only; run by `build/live_checks.py browser`, which starts an engine with drafts switched
// on for the test (TUNNELSCOPE_GENERATOR=1) and a throwaway history folder (E2E_HISTORY).
// The lab is put back to its generated config before and after every test.
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { expect, test, type Page } from "@playwright/test"
import { CAPTURE } from "./fixtures.ts"

const ROOT = fileURLToPath(new URL("../../", import.meta.url))
const RULE = "V-207193"
const HISTORY = process.env.E2E_HISTORY ?? ""

function resetLab() {
  execFileSync(".venv/bin/python", ["-c", "import sys; sys.path.insert(0, 'tests'); from test_remediate import _reset_lab_tunnel; _reset_lab_tunnel()"], { cwd: ROOT, stdio: "ignore" })
}

function audit(): Record<string, unknown>[] {
  return readFileSync(`${HISTORY}/remediate.jsonl`, "utf8").trim().split("\n").map((l) => JSON.parse(l))
}

async function openAndApprove(page: Page) {
  await page.goto("/")
  await page.locator("input[type=file]").setInputFiles(CAPTURE)
  await page.locator("[data-state][aria-expanded]").first().click()
  await page.getByRole("tab", { name: /Verdicts/ }).click()
  await page.getByRole("button", { name: `Propose fix for ${RULE}` }).click()
  await page.getByRole("button", { name: `Approve remediation plan for ${RULE}` }).click()
  const pane = page.getByTestId(`remediation-pane-${RULE}`)
  await expect(pane).toBeVisible()
  return pane
}

test.beforeEach(() => resetLab())
test.afterAll(() => resetLab())

test("B2-1 a real draft is shown with its checks, then the hand-written fix is applied through the UI", async ({ page }) => {
  expect(HISTORY, "E2E_HISTORY must name the engine's history folder").not.toBe("")
  const errors: string[] = []
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()))
  const pane = await openAndApprove(page)

  // The real local model drafts; code checks it. Either outcome is shown honestly, never hidden.
  await page.getByRole("button", { name: `Draft a fix with the local model for ${RULE}` }).click()
  const refused = pane.getByText(/did not pass the checks|No draft from the local model/)
  const accepted = pane.getByText(/Both make the same change\.|They differ\./)
  await expect(refused.or(accepted)).toBeVisible()
  const draftWasAccepted = await accepted.isVisible()
  await page.screenshot({ path: "test-results/live-draft.png" })

  // Apply the hand-written fix through the real gate: preview (real dry run + clone), then apply.
  if (draftWasAccepted) await page.getByRole("radio", { name: `Use the hand-written fix for ${RULE}` }).check()
  await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
  await expect(pane.getByText(/proposals = aes256-sha256-modp4096/).first()).toBeVisible()
  await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
  await expect(pane.getByText(/Confirmed fixed/)).toBeVisible()
  await expect(pane.getByText("Plan used: the hand-written fix")).toBeVisible()
  await page.screenshot({ path: "test-results/live-applied.png" })

  const log = audit()
  const gen = log.filter((x) => x.decision === "generate")
  const applied = log.filter((x) => x.decision === "applied")
  expect(gen.length).toBeGreaterThan(0)
  expect(gen.at(-1)!.ok).toBe(draftWasAccepted)
  expect(applied.at(-1)).toMatchObject({ source: "hand-written", confirmed_fixed: true, verdict_before: "FAIL", verdict_after: "PASS" })
  expect(typeof applied.at(-1)!.digest).toBe("string")
  expect(errors).toEqual([])
})

test("B2-2 a config changed after the preview is refused in the UI, and nothing changes", async ({ page }) => {
  const errors: string[] = []
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()))
  const pane = await openAndApprove(page)
  await page.getByRole("button", { name: `Preview the real change for ${RULE}` }).click()
  await expect(pane.getByText(/proposals = aes256-sha256-modp4096/).first()).toBeVisible()
  // someone edits the lab config between the preview and the apply
  execFileSync("docker", ["exec", "sih26-alice-pq", "sed", "-i", "/^    t-tun {/a\\        # edited after the preview", "/tmp/exp15-alice.conf"])
  const before = execFileSync("docker", ["exec", "sih26-alice-pq", "cat", "/tmp/exp15-alice.conf"]).toString()
  await page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` }).click()
  await expect(pane.getByText(/not what you previewed/)).toBeVisible()
  await expect(page.getByRole("button", { name: `Apply remediation in lab for ${RULE}` })).toBeDisabled()
  const after = execFileSync("docker", ["exec", "sih26-alice-pq", "cat", "/tmp/exp15-alice.conf"]).toString()
  expect(after).toBe(before)
  await page.screenshot({ path: "test-results/live-stale.png" })
  expect(errors.filter((e) => !/status of 400/.test(e))).toEqual([])
})
