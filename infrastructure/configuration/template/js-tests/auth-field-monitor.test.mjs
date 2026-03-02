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

test("Authenticate button is disabled on load when auth fields match saved values and token present", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  // Trigger a dirty check to invoke the monitor now that the listener is registered
  w.dirtyTracker.checkDirty();

  const authBtn = w.document.getElementById("authenticate-btn");
  assert.ok(authBtn, "authenticate-btn must exist");
  // fixture renders with token="test-token" and fields matching saved values → Authenticate disabled
  assert.equal(authBtn.disabled, true, "Authenticate must be disabled when fields match saved values and token present");
});

test("Authenticate button is enabled when authenticationMethod changes from saved value", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  var authMethodEl = w.document.getElementById("authenticationMethod");
  authMethodEl.value = "pat";

  // Trigger dirty check (simulates form change event → formState.triggerChangeHandlers → checkDirty)
  w.dirtyTracker.checkDirty();

  const authBtn = w.document.getElementById("authenticate-btn");
  assert.equal(authBtn.disabled, false, "Authenticate must be enabled when authenticationMethod differs from saved value");
});

test("Authenticate button is enabled when endpoint changes from saved value", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  var endpointEl = w.document.getElementById("endpoint");
  endpointEl.value = "https://api.custom.snyk.io";

  w.dirtyTracker.checkDirty();

  const authBtn = w.document.getElementById("authenticate-btn");
  assert.equal(authBtn.disabled, false, "Authenticate must be enabled when endpoint differs from saved value");
});

test("Authenticate button is disabled when field is reverted and token present", async () => {
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

  const authBtn = w.document.getElementById("authenticate-btn");
  // fixture has token="test-token" so Authenticate must be disabled again
  assert.equal(authBtn.disabled, true, "Authenticate must be disabled after reverting to saved value with token present");
});

test("Authenticate button is disabled when dirtyTracker resets after save and token present", async () => {
  const html = await loadFixture();
  const dom = setupDom(html);
  const w = dom.window;

  // Enable Authenticate by changing a field
  var authMethodEl = w.document.getElementById("authenticationMethod");
  authMethodEl.value = "pat";
  w.dirtyTracker.checkDirty();

  const authBtn = w.document.getElementById("authenticate-btn");
  assert.equal(authBtn.disabled, false, "Authenticate must be enabled after field change");

  // Simulate save: reset updates originalData to current values and notifies listeners
  w.dirtyTracker.setDirtyState(true);
  w.dirtyTracker.reset();

  // fixture has token="test-token" so Authenticate must be disabled after reset
  assert.equal(authBtn.disabled, true, "Authenticate must be disabled immediately after dirtyTracker reset when token present");
});

test("onDataChange does not throw when called with null data", async () => {
  const html = await loadFixture();
  const dom = new JSDOM(html, { runScripts: "dangerously" });
  const w = dom.window;

  assert.doesNotThrow(function () {
    w.ConfigApp.authFieldMonitor.onDataChange(null, null);
  }, "onDataChange must not throw when called with null data");
});

test("auth field changes do NOT trigger logout", async () => {
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
