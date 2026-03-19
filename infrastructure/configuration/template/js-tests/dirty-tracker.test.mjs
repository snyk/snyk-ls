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
 * Builds a minimal DOM with FormUtils and DirtyTracker loaded.
 * No HTML fixture is needed since DirtyTracker does not interact with DOM elements.
 */
async function buildDom() {
  const [utilsScript, trackerScript] = await Promise.all([
    loadScript("core/utils.js"),
    loadScript("state/dirty-tracker.js"),
  ]);

  const dom = new JSDOM("<!DOCTYPE html><html><body></body></html>", {
    runScripts: "dangerously",
  });
  const win = dom.window;

  const utilsEl = win.document.createElement("script");
  utilsEl.textContent = utilsScript;
  win.document.body.appendChild(utilsEl);

  const trackerEl = win.document.createElement("script");
  trackerEl.textContent = trackerScript;
  win.document.body.appendChild(trackerEl);

  return win;
}

// ---------------------------------------------------------------------------
// addChangeListener / _notifyChangeListeners
// ---------------------------------------------------------------------------

test("addChangeListener: registered callback is called on checkDirty", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();

  const data = { value: "hello" };
  tracker.initialize(() => ({ ...data }));

  let calls = 0;
  tracker.addChangeListener(() => { calls++; });

  tracker.checkDirty();

  assert.equal(calls, 1, "listener should be called once by checkDirty");
});

test("addChangeListener: callback receives originalData and currentData", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();

  const original = { endpoint: "https://api.snyk.io" };
  let capturedOriginal = null;
  let capturedCurrent  = null;

  tracker.initialize(() => ({ endpoint: "https://api.eu.snyk.io" }));
  // Overwrite originalData to a known value after initialization
  tracker.originalData = { endpoint: "https://api.snyk.io" };

  tracker.addChangeListener((orig, cur) => {
    capturedOriginal = orig;
    capturedCurrent  = cur;
  });

  tracker.checkDirty();

  assert.deepEqual(capturedOriginal, original);
  assert.deepEqual(capturedCurrent, { endpoint: "https://api.eu.snyk.io" });
});

test("addChangeListener: all registered listeners are called", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({}));

  let callsA = 0;
  let callsB = 0;
  tracker.addChangeListener(() => { callsA++; });
  tracker.addChangeListener(() => { callsB++; });

  tracker.checkDirty();

  assert.equal(callsA, 1);
  assert.equal(callsB, 1);
});

test("_notifyChangeListeners: a failing listener does not prevent others from running", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({}));

  let secondListenerCalled = false;
  tracker.addChangeListener(() => { throw new Error("deliberate error"); });
  tracker.addChangeListener(() => { secondListenerCalled = true; });

  // Should not throw
  tracker.checkDirty();

  assert.ok(secondListenerCalled, "second listener must run even if first throws");
});

test("addChangeListener: callback is also called on reset", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({ v: 1 }));

  let calls = 0;
  tracker.addChangeListener(() => { calls++; });

  tracker.reset();

  assert.equal(calls, 1, "listener should be called once by reset");
});

// ---------------------------------------------------------------------------
// syncBaselineFields
// ---------------------------------------------------------------------------

test("syncBaselineFields: advances specified fields in baseline from current form data", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();

  let currentEndpoint = "https://api.snyk.io";
  tracker.initialize(() => ({ endpoint: currentEndpoint, token: "abc" }));

  // Simulate the form updating the endpoint (e.g. IDE pushed a new value)
  currentEndpoint = "https://api.eu.snyk.io";

  tracker.syncBaselineFields(["endpoint"]);

  // After sync, baseline endpoint should match the new current value
  assert.equal(tracker.originalData.endpoint, "https://api.eu.snyk.io");
  // Non-synced fields are unchanged
  assert.equal(tracker.originalData.token, "abc");
});

test("syncBaselineFields: is a no-op when originalData is null", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  // Do not call initialize — originalData stays null

  // Should not throw
  tracker.syncBaselineFields(["endpoint"]);
});

test("syncBaselineFields: is a no-op when fields is null", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({ endpoint: "https://api.snyk.io" }));

  // Should not throw
  tracker.syncBaselineFields(null);

  assert.equal(tracker.originalData.endpoint, "https://api.snyk.io");
});

test("syncBaselineFields: ignores fields not present in current form data", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({ token: "abc" }));

  // "endpoint" is not in the current form data
  tracker.syncBaselineFields(["endpoint", "token"]);

  assert.equal(tracker.originalData.token, "abc");
  assert.ok(!tracker.originalData.hasOwnProperty("endpoint"), "absent field must not be added to baseline");
});
