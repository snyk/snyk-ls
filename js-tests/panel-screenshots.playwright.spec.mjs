import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ideVariants = [
  { name: "vscode", background: "rgb(30, 30, 30)", foreground: "rgb(204, 204, 204)" },
  { name: "intellij", background: "rgb(43, 43, 43)", foreground: "rgb(187, 187, 187)" },
  { name: "visualStudio", background: "rgb(37, 37, 38)", foreground: "rgb(241, 241, 241)" },
  { name: "eclipse", background: "rgb(27, 30, 35)", foreground: "rgb(216, 221, 229)" },
];

const panels = [
  { name: "tree-view", fixture: "tree-view.html" },
  { name: "config-page", fixture: "config-page.html" },
  { name: "code-suggestion", fixture: "code-suggestion.html" },
  { name: "oss-suggestion", fixture: "oss-suggestion.html" },
  { name: "iac-suggestion", fixture: "iac-suggestion.html" },
  { name: "secrets-suggestion", fixture: "secrets-suggestion.html" },
  { name: "scan-summary", fixture: "scan-summary.html" },
];

for (const panel of panels) {
  for (const ide of ideVariants) {
    test(`screenshot: ${panel.name} × ${ide.name}`, async ({ page }, testInfo) => {
      const rawHtml = await readFile(join(__dirname, "fixtures", panel.fixture), "utf8");
      // Strip CSP meta tags — fixtures contain webview CSPs that block test-injected styles.
      const html = rawHtml.replace(/<meta[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi, "");
      await page.setViewportSize({ width: 1280, height: 900 });
      await page.setContent(html, { waitUntil: "domcontentloaded" });
      await page.addStyleTag({
        content: `body { background-color: ${ide.background} !important; color: ${ide.foreground} !important; }`,
      });
      const buf = await page.screenshot({ fullPage: true, animations: "disabled" });
      await testInfo.attach(`${panel.name}-${ide.name} (full page)`, {
        body: buf,
        contentType: "image/png",
      });
      await expect(page).toHaveScreenshot(`${panel.name}-${ide.name}.png`, {
        fullPage: true,
        threshold: 0.2,
        maxDiffPixelRatio: 0.02,
        animations: "disabled",
      });
    });
  }
}
