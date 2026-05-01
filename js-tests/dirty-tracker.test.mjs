import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// ---------------------------------------------------------------------------
// addChangeListener / runChangeListeners / _notifyChangeListeners
// ---------------------------------------------------------------------------

test("runChangeListeners: registered callback is called", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();

  const data = { value: "hello" };
  tracker.initialize(() => ({ ...data }));

  let calls = 0;
  tracker.addChangeListener(() => { calls++; });

  tracker.runChangeListeners();

  assert.equal(calls, 1, "listener should be called once by runChangeListeners");
});

test("runChangeListeners: callback receives originalData and currentData", async () => {
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

  tracker.runChangeListeners();

  assert.deepEqual(capturedOriginal, original);
  assert.deepEqual(capturedCurrent, { endpoint: "https://api.eu.snyk.io" });
});

test("runChangeListeners: all registered listeners are called", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({}));

  let callsA = 0;
  let callsB = 0;
  tracker.addChangeListener(() => { callsA++; });
  tracker.addChangeListener(() => { callsB++; });

  tracker.runChangeListeners();

  assert.equal(callsA, 1);
  assert.equal(callsB, 1);
});

test("runChangeListeners: a failing listener does not prevent others from running", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({}));

  let secondListenerCalled = false;
  tracker.addChangeListener(() => { throw new Error("deliberate error"); });
  tracker.addChangeListener(() => { secondListenerCalled = true; });

  // Should not throw
  tracker.runChangeListeners();

  assert.ok(secondListenerCalled, "second listener must run even if first throws");
});

test("checkDirty: does not call change listeners", async () => {
  const win = await buildDom();
  const tracker = new win.DirtyTracker();
  tracker.initialize(() => ({ v: 1 }));

  let calls = 0;
  tracker.addChangeListener(() => { calls++; });

  tracker.checkDirty();

  assert.equal(calls, 0, "checkDirty must not invoke change listeners");
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
