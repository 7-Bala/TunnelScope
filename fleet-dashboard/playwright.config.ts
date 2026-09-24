import { defineConfig, devices } from "@playwright/test"

// Two kinds of browser test (build/13 T-105):
//   mock  (CI):   the built dashboard served by `vite preview`, every /api call answered by typed fixtures
//   live  (local): the real engine (default 127.0.0.1:8766, or E2E_BASE_URL) with the real lab and the real local model,
//                 run with `E2E_LIVE=1 npx playwright test --project=live`
const live = !!process.env.E2E_LIVE

export default defineConfig({
  testDir: "./e2e",
  timeout: live ? 240_000 : 30_000,
  expect: { timeout: live ? 120_000 : 5_000 },
  fullyParallel: !live,
  workers: live ? 1 : undefined,
  reporter: [["list"]],
  use: { reducedMotion: "reduce", trace: "off" },
  projects: [
    {
      name: "mock",
      testMatch: /remediation\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"], baseURL: "http://127.0.0.1:4173" },
    },
    {
      name: "live",
      testMatch: /remediation\.live\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"], baseURL: process.env.E2E_BASE_URL ?? "http://127.0.0.1:8766" },
    },
  ],
  webServer: live
    ? undefined
    : {
        command: "npx vite preview --port 4173 --strictPort --host 127.0.0.1",
        url: "http://127.0.0.1:4173",
        reuseExistingServer: !process.env.CI,
        timeout: 60_000,
      },
})
