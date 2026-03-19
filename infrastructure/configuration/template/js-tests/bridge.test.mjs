import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function loadScript(filename) {
  return readFile(join(__dirname, "..", "js", filename), "utf8");
}

/**
 * Builds a DOM with the scripts needed to test bridge.js.
 * Mocks formState.triggerChangeHandlers to avoid requiring the full auto-save stack.
 */
async function buildDom({ initialToken = "", initialAuthMethod = "token" } = {}) {
  const [fixtureHtml, domScript, validationScript, bridgeScript] = await Promise.all([
    readFile(join(__dirname, "fixtures", "config-page.html"), "utf8"),
    loadScript("core/dom.js"),
    loadScript("features/validation.js"),
    loadScript("ide/bridge.js"),
  ]);

  // Inject a stub for formState so triggerChangeHandlers doesn't throw
  const stubScript = `
    window.ConfigApp = window.ConfigApp || {};
    window.ConfigApp.formState = {
      triggerChangeHandlers: function() {}
    };
  `;

  const html = fixtureHtml.replace(
    "</body>",
    `<script>${domScript}</script>` +
    `<script>${stubScript}</script>` +
    `<script>${validationScript}</script>` +
    `<script>${bridgeScript}</script>\n</body>`
  );

  const dom = new JSDOM(html, { runScripts: "dangerously" });
  const win = dom.window;

  win.document.getElementById("token").value = initialToken;
  win.document.getElementById("authenticationMethod").value = initialAuthMethod;

  return win;
}

/**
 * Builds a DOM that also loads auth-field-monitor.js to test the interaction
 * between the monitor's stale-token state and setAuthToken.
 */
async function buildDomWithAuthMonitor({ initialToken = "", initialAuthMethod = "token" } = {}) {
  const [fixtureHtml, domScript, validationScript, monitorScript, bridgeScript] = await Promise.all([
    readFile(join(__dirname, "fixtures", "config-page.html"), "utf8"),
    loadScript("core/dom.js"),
    loadScript("features/validation.js"),
    loadScript("features/auth-field-monitor.js"),
    loadScript("ide/bridge.js"),
  ]);

  // Stub formState and dirtyTracker so triggerChangeHandlers and syncBaselineFields don't throw
  const stubScript = `
    window.ConfigApp = window.ConfigApp || {};
    window.ConfigApp.formState = {
      triggerChangeHandlers: function() {}
    };
    window.dirtyTracker = {
      syncBaselineFields: function() {}
    };
  `;

  const html = fixtureHtml.replace(
    "</body>",
    `<script>${domScript}</script>` +
    `<script>${stubScript}</script>` +
    `<script>${validationScript}</script>` +
    `<script>${monitorScript}</script>` +
    `<script>${bridgeScript}</script>\n</body>`
  );

  const dom = new JSDOM(html, { runScripts: "dangerously" });
  const win = dom.window;

  win.document.getElementById("token").value = initialToken;
  win.document.getElementById("authenticationMethod").value = initialAuthMethod;

  return win;
}

test("setAuthToken hides token-error even when a pre-existing validation error was present", async () => {
  const win = await buildDom({ initialToken: "", initialAuthMethod: "token" });

  // Simulate a pre-existing validation error by running token validation with an invalid token
  win.document.getElementById("token").value = "not-a-uuid";
  win.ConfigApp.validation.validateTokenOnInput();

  // Confirm the error is visible before the auth callback
  const tokenError = win.document.getElementById("token-error");
  assert.ok(!tokenError.className.includes("hidden"), "token-error should be visible before setAuthToken");

  // IDE calls setAuthToken with a valid UUID token after successful authentication
  const validUUID = "12345678-1234-1234-1234-123456789abc";
  win.setAuthToken(validUUID, null);

  // The error must now be hidden
  assert.ok(tokenError.className.includes("hidden"), "token-error should be hidden after setAuthToken with valid UUID");
});

test("setAuthToken sets token input value", async () => {
  const win = await buildDom({ initialToken: "", initialAuthMethod: "token" });

  const validUUID = "12345678-1234-1234-1234-123456789abc";
  win.setAuthToken(validUUID, null);

  assert.equal(win.document.getElementById("token").value, validUUID);
});

test("setAuthToken disables authenticate-btn and enables logout-btn", async () => {
  const win = await buildDom({ initialToken: "", initialAuthMethod: "token" });

  const validUUID = "12345678-1234-1234-1234-123456789abc";
  win.setAuthToken(validUUID, null);

  assert.equal(win.document.getElementById("authenticate-btn").disabled, true);
  assert.equal(win.document.getElementById("logout-btn").disabled, false);
});

test("setAuthToken sets endpoint when apiUrl is provided", async () => {
  const win = await buildDom({ initialToken: "", initialAuthMethod: "token" });

  const validUUID = "12345678-1234-1234-1234-123456789abc";
  win.setAuthToken(validUUID, "https://api.eu.snyk.io");

  assert.equal(win.document.getElementById("endpoint").value, "https://api.eu.snyk.io");
});

test("setAuthToken does not restore stale pre-auth token after auth method switch", async () => {
  const oldToken = "old-api-token-12345";
  const win = await buildDomWithAuthMonitor({ initialToken: oldToken, initialAuthMethod: "token" });

  const monitor = win.ConfigApp.authFieldMonitor;

  // Simulate the user switching auth method: monitor clears token and saves old one
  const baseline = { authenticationMethod: "token", endpoint: "https://api.snyk.io" };
  const changed  = { authenticationMethod: "oauth", endpoint: "https://api.snyk.io" };
  monitor.onDataChange(baseline, changed);

  // Verify monitor cleared the token and saved the old one internally
  assert.equal(win.document.getElementById("token").value, "", "token should be cleared after auth method change");

  // IDE calls setAuthToken after successful OAuth flow
  const newOAuthToken = "new-oauth-token-99999";
  win.setAuthToken(newOAuthToken, null);

  // The new token must be present — the old savedToken must NOT be restored
  assert.equal(
    win.document.getElementById("token").value,
    newOAuthToken,
    "setAuthToken must not be overwritten by the stale pre-auth savedToken"
  );
});
