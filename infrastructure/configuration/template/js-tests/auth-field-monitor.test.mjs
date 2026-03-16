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
 * Builds a minimal DOM that auth-field-monitor.js needs:
 * - window.ConfigApp.dom (minimal shim: get delegates to getElementById)
 * - HTML elements: authenticate-btn, logout-btn, token, authenticationMethod select, endpoint input
 */
async function buildDom({ initialEndpoint = "https://api.snyk.io", initialAuthMethod = "oauth", initialToken = "abc123" } = {}) {
  const monitorScript = await loadScript("features/auth-field-monitor.js");

  const html = `<!doctype html>
<html><body>
  <input type="password" id="token" value="${initialToken}" />
  <select id="authenticationMethod"><option value="${initialAuthMethod}" selected>${initialAuthMethod}</option></select>
  <input type="text" id="endpoint" value="${initialEndpoint}" />
  <button id="authenticate-btn" disabled></button>
  <button id="logout-btn"></button>
  <script>
    window.ConfigApp = window.ConfigApp || {};
    window.ConfigApp.dom = {
      get: function(id) { return document.getElementById(id); }
    };
  </script>
  <script>${monitorScript}</script>
</body></html>`;

  const dom = new JSDOM(html, { runScripts: "dangerously" });
  return dom.window;
}

function collectData(win) {
  return {
    endpoint: win.document.getElementById("endpoint").value,
    authenticationMethod: win.document.getElementById("authenticationMethod").value,
  };
}

test("token is cleared when endpoint changes from baseline", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, endpoint: "https://api.eu.snyk.io" };

  monitor.onDataChange(baseline, changed);

  assert.equal(win.document.getElementById("token").value, "");
  assert.equal(win.document.getElementById("authenticate-btn").disabled, false);
  assert.equal(win.document.getElementById("logout-btn").disabled, true);
});

test("token is cleared when authenticationMethod changes from baseline", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, authenticationMethod: "token" };

  monitor.onDataChange(baseline, changed);

  assert.equal(win.document.getElementById("token").value, "");
});

test("token is NOT cleared again on subsequent calls when already cleared", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, endpoint: "https://api.eu.snyk.io" };

  // First call: clears token
  monitor.onDataChange(baseline, changed);
  assert.equal(win.document.getElementById("token").value, "");

  // User manually pastes a new token
  win.document.getElementById("token").value = "new-pat-token";

  // Subsequent calls (from other field blurs) must NOT clear the newly-entered token
  monitor.onDataChange(baseline, changed);
  assert.equal(win.document.getElementById("token").value, "new-pat-token", "manually entered token must not be wiped on subsequent dirty checks");
});

test("hasCleared flag resets when sensitive fields return to baseline", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, endpoint: "https://api.eu.snyk.io" };

  // First: endpoint changed, token cleared
  monitor.onDataChange(baseline, changed);
  assert.equal(win.document.getElementById("token").value, "");

  // User pastes new token
  win.document.getElementById("token").value = "my-pat";

  // Now endpoint returns to baseline (user reverts their change)
  monitor.onDataChange(baseline, baseline);

  // Change endpoint again - token should be cleared this time since flag was reset
  win.document.getElementById("token").value = "my-pat";
  monitor.onDataChange(baseline, changed);
  assert.equal(win.document.getElementById("token").value, "", "token should be cleared again after flag was reset on baseline match");
});

test("no action when sensitive fields match baseline", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);

  // No change
  monitor.onDataChange(baseline, baseline);

  // Token should be unchanged, authenticate-btn disabled (token exists)
  assert.equal(win.document.getElementById("token").value, "abc123");
  assert.equal(win.document.getElementById("authenticate-btn").disabled, true);
});
