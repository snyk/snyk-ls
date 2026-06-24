import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

function isHidden(el) {
  return el.className.includes("hidden");
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

  assert.equal(win.document.getElementById("api_endpoint").value, "https://api.eu.snyk.io");
});

test("setAuthToken does not restore stale pre-auth token after auth method switch", async () => {
  const oldToken = "old-api-token-12345";
  const win = await buildDom({ initialToken: oldToken, initialAuthMethod: "token" });

  const monitor = win.ConfigApp.authFieldMonitor;

  // Simulate the user switching auth method: monitor clears token and saves old one
  const baseline = { authentication_method: "token", api_endpoint: "https://api.snyk.io" };
  const changed  = { authentication_method: "oauth", api_endpoint: "https://api.snyk.io" };
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

test("setAuthToken preserves OAuth visibility classes and shows logout", async () => {
  const win = await buildDom({ initialToken: "", initialAuthMethod: "oauth" });

  const tokenFieldGroup = win.document.getElementById("token-field-group");
  const getTokenLink = win.document.getElementById("get-token-link");
  const authBtn = win.document.getElementById("authenticate-btn");
  const logoutBtn = win.document.getElementById("logout-btn");

  win.setAuthToken("12345678-1234-1234-1234-123456789abc", null);

  assert.equal(isHidden(tokenFieldGroup), true, "token field should stay hidden for oauth");
  assert.equal(isHidden(getTokenLink), true, "get-token link should stay hidden for oauth");
  assert.equal(isHidden(authBtn), false, "authenticate button should stay visible for oauth");
  assert.equal(isHidden(logoutBtn), false, "logout button should be visible when token exists");
  assert.equal(authBtn.disabled, true, "authenticate button should be disabled after setAuthToken");
  assert.equal(logoutBtn.disabled, false, "logout button should be enabled after setAuthToken");
});

// ---------------------------------------------------------------------------
// ideBridge.confirm — dedicated __ideConfirmationDialog__ bridge
// ---------------------------------------------------------------------------

test("ideBridge.confirm: __ideConfirmationDialog__ called with the message and a function callback", async () => {
  const win = await buildDom();

  let receivedMessage = null;
  let receivedCallback = null;
  win.__ideConfirmationDialog__ = (msg, cb) => { receivedMessage = msg; receivedCallback = cb; };

  win.ConfigApp.ideBridge.confirm("Are you sure?", () => {});

  assert.equal(receivedMessage, "Are you sure?", "message forwarded to __ideConfirmationDialog__");
  assert.equal(typeof receivedCallback, "function", "__ideConfirmationDialog__ receives a function callback (done wrapper)");
});

test("ideBridge.confirm: cb(false) → outer callback called with false (cancel → no save)", async () => {
  const win = await buildDom();
  win.__IS_IDE_AUTOSAVE_ENABLED__ = true;
  const saveCalls = [];
  win.__saveIdeConfig__ = (json) => saveCalls.push(json);

  let capturedCb;
  win.__ideConfirmationDialog__ = (_msg, cb) => { capturedCb = cb; };

  let confirmedResult = null;
  win.ConfigApp.ideBridge.confirm("Reset?", (result) => { confirmedResult = result; });

  capturedCb(false);

  assert.equal(confirmedResult, false, "outer callback receives false");
  assert.equal(saveCalls.length, 0, "no save triggered when cancelled");
});

test("ideBridge.confirm: cb(true) → outer callback called with true (confirm → proceeds)", async () => {
  const win = await buildDom();
  win.__IS_IDE_AUTOSAVE_ENABLED__ = true;
  const saveCalls = [];
  win.__saveIdeConfig__ = (json) => saveCalls.push(json);

  let capturedCb;
  win.__ideConfirmationDialog__ = (_msg, cb) => { capturedCb = cb; };

  let confirmedResult = null;
  win.ConfigApp.ideBridge.confirm("Reset?", (result) => { confirmedResult = result; });

  capturedCb(true);

  assert.equal(confirmedResult, true, "outer callback receives true");
});

test("ideBridge.confirm: non-boolean result logs console.error and is treated as cancel (fail-closed)", async () => {
  const win = await buildDom();

  let capturedCb;
  win.__ideConfirmationDialog__ = (_msg, cb) => { capturedCb = cb; };

  const errors = [];
  win.console = { error: (...args) => errors.push(args) };

  let confirmedResult = null;
  win.ConfigApp.ideBridge.confirm("Reset?", (result) => { confirmedResult = result; });

  // Pass a non-boolean (object) — should log error and coerce to false (fail-closed)
  capturedCb({ confirmed: true });

  assert.ok(errors.length > 0, "console.error called for non-boolean result");
  assert.ok(errors[0].join(" ").includes("expected boolean"), "error message mentions expected boolean");
  assert.equal(confirmedResult, false, "non-boolean result treated as cancel (fail-closed)");
});

test("ideBridge.confirm: non-boolean string result also fail-closed", async () => {
  const win = await buildDom();

  let capturedCb;
  win.__ideConfirmationDialog__ = (_msg, cb) => { capturedCb = cb; };

  const errors = [];
  win.console = { error: (...args) => errors.push(args) };

  let confirmedResult = null;
  win.ConfigApp.ideBridge.confirm("Reset?", (result) => { confirmedResult = result; });

  capturedCb("yes");

  assert.ok(errors.length > 0, "console.error called for string result");
  assert.equal(confirmedResult, false, "string result treated as cancel (fail-closed)");
});

test("ideBridge.confirm: no-bridge fallback uses window.confirm (returns true)", async () => {
  const win = await buildDom();
  // Ensure no dedicated bridge is present
  delete win.__ideConfirmationDialog__;
  win.confirm = () => true;

  let confirmedResult = null;
  win.ConfigApp.ideBridge.confirm("Reset?", (result) => { confirmedResult = result; });

  assert.equal(confirmedResult, true, "fallback window.confirm true → callback called with true");
});

test("ideBridge.confirm: no-bridge fallback uses window.confirm (returns false)", async () => {
  const win = await buildDom();
  delete win.__ideConfirmationDialog__;
  win.confirm = () => false;

  let confirmedResult = null;
  win.ConfigApp.ideBridge.confirm("Reset?", (result) => { confirmedResult = result; });

  assert.equal(confirmedResult, false, "fallback window.confirm false → callback called with false");
});

test("ideBridge.confirm: missing callback throws TypeError (programmer error — fail fast)", async () => {
  const win = await buildDom();

  win.__ideConfirmationDialog__ = (_msg, _cb) => {};

  // A missing callback is a coding mistake — confirm must throw loudly, not silently no-op.
  assert.throws(
    () => win.ConfigApp.ideBridge.confirm("Reset?"),
    /callback is required and must be a function/,
    "confirm with no callback must throw TypeError"
  );
});

// ---------------------------------------------------------------------------
// handleSectionReset — gates applyDefaults behind confirm callback
// ---------------------------------------------------------------------------

test("handleSectionReset: confirmed=false → no defaults applied (fields unchanged)", async () => {
  const win = await buildDom();

  // Stub ideBridge.confirm to capture the callback and NOT invoke it yet
  let pendingConfirmCb = null;
  win.ConfigApp.ideBridge.confirm = (_msg, cb) => { pendingConfirmCb = cb; };

  // Change a field from its default so we can detect if applyDefaults runs
  const scanOssEl = win.document.querySelector('[name="snyk_oss_enabled"]');
  assert.ok(scanOssEl, "snyk_oss_enabled element exists");
  const originalValue = scanOssEl.checked;

  const btn = win.document.querySelector('.reset-section-btn[data-section="scanConfiguration"]');
  assert.ok(btn, "scanConfiguration reset button exists");
  btn.click();

  assert.ok(pendingConfirmCb, "confirm was called on reset button click");

  // Cancel: defaults must NOT be applied
  pendingConfirmCb(false);

  assert.equal(scanOssEl.checked, originalValue, "snyk_oss_enabled unchanged when reset cancelled");
});

test("handleSectionReset: confirmed=true → defaults applied", async () => {
  const win = await buildDom();
  win.__IS_IDE_AUTOSAVE_ENABLED__ = true;

  // Inject dedicated bridge so we control the confirmation
  let pendingConfirmCb = null;
  win.__ideConfirmationDialog__ = (_msg, cb) => { pendingConfirmCb = cb; };

  const btn = win.document.querySelector('.reset-section-btn[data-section="scanConfiguration"]');
  assert.ok(btn, "scanConfiguration reset button exists");
  btn.click();

  assert.ok(pendingConfirmCb, "ideConfirmationDialog was called on reset button click");

  // Confirm: defaults should be applied (snyk_oss_enabled default is false per sectionDefaults)
  pendingConfirmCb(true);

  const scanOssEl = win.document.querySelector('[name="snyk_oss_enabled"]');
  assert.equal(scanOssEl.checked, false, "snyk_oss_enabled reset to default (false) after confirmed=true");
});
