import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function loadFixture() {
  const fixturePath = join(__dirname, "fixture.html");
  try {
    return await readFile(fixturePath, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") {
      throw new Error("fixture.html not found — run 'make test-config-js' to generate it first");
    }
    throw e;
  }
}

function setupDom(html) {
  const dom = new JSDOM(html, { runScripts: "dangerously" });
  const w = dom.window;

  // Simulate what formState.initializeDirtyTracking() does at page load
  w.dirtyTracker = new w.DirtyTracker();
  w.dirtyTracker.initialize(function () {
    return w.ConfigApp.formHandler.collectData();
  });

  // Register auth field monitor via the DirtyTracker change listener API (same as app.js)
  w.dirtyTracker.addChangeListener(w.ConfigApp.authFieldMonitor.onDataChange);

  return dom;
}

test("advisory indicator is hidden on load when auth fields match saved values", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);

  const indicator = dom.window.document.getElementById("auth-reauth-advisory");
  assert.ok(indicator, "auth-reauth-advisory element must exist");
  assert.ok(
    indicator.className.indexOf("hidden") !== -1,
    "indicator must be hidden when fields match saved values"
  );
});

test("advisory indicator shows when authenticationMethod changes from saved value", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  var authMethodEl = w.document.getElementById("authenticationMethod");
  authMethodEl.value = "pat";

  // Trigger dirty check (simulates form change event → formState.triggerChangeHandlers → checkDirty)
  w.dirtyTracker.checkDirty();

  const indicator = w.document.getElementById("auth-reauth-advisory");
  assert.ok(
    indicator.className.indexOf("hidden") === -1,
    "indicator must be visible when authenticationMethod differs from saved value"
  );
});

test("advisory indicator shows when endpoint changes from saved value", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  var endpointEl = w.document.getElementById("endpoint");
  endpointEl.value = "https://api.custom.snyk.io";

  w.dirtyTracker.checkDirty();

  const indicator = w.document.getElementById("auth-reauth-advisory");
  assert.ok(
    indicator.className.indexOf("hidden") === -1,
    "indicator must be visible when endpoint differs from saved value"
  );
});

test("advisory indicator hides when field is reverted to saved value", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  var authMethodEl = w.document.getElementById("authenticationMethod");
  var savedValue = authMethodEl.value;

  // Change to something different
  authMethodEl.value = "pat";
  w.dirtyTracker.checkDirty();

  // Revert to saved
  authMethodEl.value = savedValue;
  w.dirtyTracker.checkDirty();

  const indicator = w.document.getElementById("auth-reauth-advisory");
  assert.ok(
    indicator.className.indexOf("hidden") !== -1,
    "indicator must be hidden after reverting to saved value"
  );
});

test("advisory indicator hides when dirtyTracker resets after save", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  // Show advisory by changing a field
  var authMethodEl = w.document.getElementById("authenticationMethod");
  authMethodEl.value = "pat";
  w.dirtyTracker.checkDirty();

  const indicator = w.document.getElementById("auth-reauth-advisory");
  assert.ok(indicator.className.indexOf("hidden") === -1, "advisory must be visible after field change");

  // Simulate save: reset updates originalData to current values and notifies listeners
  w.dirtyTracker.setDirtyState(true);
  w.dirtyTracker.reset();

  assert.ok(indicator.className.indexOf("hidden") !== -1, "advisory must hide immediately after dirtyTracker reset");
});

test("advisory indicator does not throw when onDataChange called with null data", async () => {
  const html = await loadFixture();
  const dom = new JSDOM(html, { runScripts: "dangerously" });
  const w = dom.window;

  assert.doesNotThrow(function () {
    w.ConfigApp.authFieldMonitor.onDataChange(null, null);
  }, "onDataChange must not throw when called with null data");
});

test("advisory indicator does not auto-logout when auth fields change", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  var logoutCalled = false;
  w.__ideExecuteCommand__ = function (cmd) {
    if (cmd === "snyk.logout") { logoutCalled = true; }
  };

  var authMethodEl = w.document.getElementById("authenticationMethod");
  authMethodEl.value = "pat";
  w.dirtyTracker.checkDirty();

  assert.equal(logoutCalled, false, "changing auth fields must NOT trigger logout");
});
