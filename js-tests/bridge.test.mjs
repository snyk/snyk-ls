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
