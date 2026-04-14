import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

function collectData(win) {
  return {
    api_endpoint: win.document.getElementById("api_endpoint").value,
    authentication_method: win.document.getElementById("authentication_method").value,
  };
}

test("token is cleared when endpoint changes from baseline", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, api_endpoint: "https://api.eu.snyk.io" };

  monitor.onDataChange(baseline, changed);

  assert.equal(win.document.getElementById("token").value, "");
  assert.equal(win.document.getElementById("authenticate-btn").disabled, false);
  assert.equal(win.document.getElementById("logout-btn").disabled, true);
});

test("token is cleared when authenticationMethod changes from baseline", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, authentication_method: "token" };

  monitor.onDataChange(baseline, changed);

  assert.equal(win.document.getElementById("token").value, "");
});

test("token is NOT cleared again on subsequent calls when already cleared", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, api_endpoint: "https://api.eu.snyk.io" };

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
  const changed = { ...baseline, api_endpoint: "https://api.eu.snyk.io" };

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

test("logoutBtn is re-enabled when sensitive fields revert to baseline with token present", async () => {
  const win = await buildDom({ initialToken: "abc123" });
  const monitor = win.ConfigApp.authFieldMonitor;

  const baseline = collectData(win);
  const changed = { ...baseline, api_endpoint: "https://api.eu.snyk.io" };

  // Endpoint changed — logoutBtn must be disabled, authBtn enabled
  monitor.onDataChange(baseline, changed);
  assert.equal(win.document.getElementById("logout-btn").disabled, true);
  assert.equal(win.document.getElementById("authenticate-btn").disabled, false);

  // Endpoint reverted — logoutBtn must be re-enabled (token is still present), authBtn disabled
  monitor.onDataChange(baseline, baseline);
  assert.equal(win.document.getElementById("logout-btn").disabled, false);
  assert.equal(win.document.getElementById("authenticate-btn").disabled, true);
});

test("saved token is NOT restored after a successful save (apply)", async () => {
  // Regression: when the user changes auth method and clicks Apply, the save completes
  // and dirtyTracker.reset() fires onDataChange with the new baseline (new method, empty token).
  // The monitor must NOT restore the pre-change savedToken at this point — the save is the
  // commit point and the old token is no longer valid.
  const win = await buildDom({ initialToken: "old-token", initialAuthMethod: "token" });
  const monitor = win.ConfigApp.authFieldMonitor;

  // Step 1: user changes auth method → monitor clears token, saves old token
  const baseline = { authentication_method: "token", api_endpoint: "https://api.snyk.io" };
  const changed  = { authentication_method: "oauth", api_endpoint: "https://api.snyk.io" };
  monitor.onDataChange(baseline, changed);
  assert.equal(win.document.getElementById("token").value, "", "token must be cleared after method change");

  // Step 2: save succeeds → resetSavedState() is called before dirtyTracker.reset()
  monitor.resetSavedState();

  // Step 3: dirtyTracker.reset() fires onDataChange with the new saved baseline
  const newBaseline = { authentication_method: "oauth", api_endpoint: "https://api.snyk.io" };
  monitor.onDataChange(newBaseline, newBaseline);

  // Token must NOT be restored — the old token is no longer valid after the method change was saved
  assert.equal(
    win.document.getElementById("token").value,
    "",
    "old token must not be restored after save completes"
  );
});

test("token-error is hidden when token is cleared due to a sensitive field change", async () => {
  const win = await buildDom({ initialToken: "not-a-uuid", initialAuthMethod: "token" });

  // Produce a visible token validation error
  win.ConfigApp.validation.validateTokenOnInput();

  const tokenError = win.document.getElementById("token-error");
  assert.ok(!tokenError.className.includes("hidden"), "token-error should be visible before onDataChange");

  // Sensitive field changes — monitor clears the token
  const originalData = { authentication_method: "token", api_endpoint: "https://api.snyk.io" };
  const currentData  = { authentication_method: "pat",   api_endpoint: "https://api.snyk.io" };
  win.ConfigApp.authFieldMonitor.onDataChange(originalData, currentData);

  assert.ok(tokenError.className.includes("hidden"), "token-error should be hidden after token is cleared");
});
