// ABOUTME: Shared test helper that builds a JSDOM environment loading all scripts
// ABOUTME: in the same order as production (matching config.html), so tests run
// ABOUTME: against the real app stack rather than cherry-picked subsets.

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Matches the script loading order in config.html (jQuery/Bootstrap excluded — not needed for logic tests)
const SCRIPT_FILES = [
  "core/polyfills.js",
  "core/utils.js",
  "core/dom.js",
  "state/dirty-tracker.js",
  "state/form-state.js",
  "ide/bridge.js",
  "ui/form-handler.js",
  "ui/tooltips.js",
  "ui/reset-handler.js",
  "features/validation.js",
  "features/folders.js",
  "features/authentication.js",
  "features/auth-field-monitor.js",
  "features/auto-save.js",
  "app.js",
];

/**
 * Builds a fully-initialized JSDOM environment mirroring the production app stack.
 * Initial field values are set before the window load event fires so the dirty tracker
 * captures them as the baseline.
 *
 * @param {object} [options]
 * @param {string} [options.initialToken=""]
 * @param {string} [options.initialAuthMethod="oauth"]
 * @param {string} [options.initialEndpoint="https://api.snyk.io"]
 * @returns {Promise<Window>}
 */
export async function buildDom({
  initialToken = "",
  initialAuthMethod = "oauth",
  initialEndpoint = "https://api.snyk.io",
} = {}) {
  const [fixtureHtml, ...scriptContents] = await Promise.all([
    readFile(join(__dirname, "fixtures", "config-page.html"), "utf8"),
    ...SCRIPT_FILES.map((f) => readFile(join(__dirname, "..", "js", f), "utf8")),
  ]);

  const scriptTags = scriptContents.map((s) => `<script>${s}</script>`).join("\n");
  const html = fixtureHtml.replace("</body>", `${scriptTags}\n</body>`);

  const dom = new JSDOM(html, { runScripts: "dangerously" });
  const win = dom.window;

  // Set initial values before the window load event fires so the dirty tracker
  // captures them as the baseline state.
  win.document.getElementById("token").value = initialToken;
  win.document.getElementById("authenticationMethod").value = initialAuthMethod;
  win.document.getElementById("endpoint").value = initialEndpoint;

  // Yield to the event loop so JSDOM can fire the window 'load' event, which
  // triggers app.js initialization (dirtyTracker, validation listeners, etc.).
  await new Promise((resolve) => win.setTimeout(resolve, 0));

  return win;
}
