import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: ["*.playwright.spec.mjs"],
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  snapshotPathTemplate: "screenshots/{arg}-{platform}{ext}",
  use: {
    ...devices["Desktop Chrome"],
    trace: process.env.PW_TRACE || "retain-on-failure",
    screenshot: process.env.PW_SCREENSHOT || "on",
    video: process.env.PW_VIDEO || "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
    },
  ],
});
