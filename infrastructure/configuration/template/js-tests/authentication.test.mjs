import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

function sleep(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

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

function ideBridge(calls) {
  return function (cmd, args, cb) {
    calls.push({ cmd, args, cb });
  };
}

function initDirtyTrackerWithAuthMonitor(w) {
  w.dirtyTracker = new w.DirtyTracker();
  w.dirtyTracker.initialize(w.ConfigApp.formHandler.collectData);
  w.dirtyTracker.addChangeListener(w.ConfigApp.authFieldMonitor.onDataChange);
}

test("authenticate collects form values via formHandler and calls __ideExecuteCommand__ with snyk.login", async () => {
  const html = await loadFixture();
  const calls = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = ideBridge(calls);
    },
  });

  dom.window.ConfigApp.authentication.authenticate();

  var loginCalls = calls.filter(function (c) { return c.cmd === "snyk.login"; });
  assert.equal(loginCalls.length, 1, "should call __ideExecuteCommand__ with snyk.login exactly once");
  // fixture renders with authMethod="oauth", endpoint="https://api.snyk.io", insecure=false
  assert.equal(loginCalls[0].args[0], "oauth", "arg[0] should be authMethod from rendered form");
  assert.equal(loginCalls[0].args[1], "https://api.snyk.io", "arg[1] should be endpoint from rendered form");
  assert.equal(loginCalls[0].args[2], false, "arg[2] should be insecure from rendered form");
});

test("authenticate does not pass a callback to snyk.login — token is delivered via $/snyk.hasAuthenticated", async () => {
  const html = await loadFixture();
  const calls = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = ideBridge(calls);
    },
  });

  dom.window.ConfigApp.authentication.authenticate();

  var loginCalls = calls.filter(function (c) { return c.cmd === "snyk.login"; });
  assert.equal(loginCalls.length, 1);
  assert.equal(loginCalls[0].cb, undefined, "snyk.login must NOT pass a callback — the IDE handles the token via $/snyk.hasAuthenticated notification");
});

test("setAuthToken does not change the endpoint field when apiUrl is omitted", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  var endpointInput = dom.window.document.getElementById("endpoint");
  var originalEndpoint = endpointInput.value;

  dom.window.setAuthToken("my-token");

  assert.equal(endpointInput.value, originalEndpoint, "endpoint field must not change when setAuthToken is called without apiUrl");
});

test("setAuthToken with apiUrl updates the endpoint field", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  var endpointInput = dom.window.document.getElementById("endpoint");

  dom.window.setAuthToken("my-token", "https://api.eu.snyk.io");

  assert.equal(endpointInput.value, "https://api.eu.snyk.io", "endpoint field must be updated when setAuthToken is called with apiUrl");
});

test("setAuthToken does not clear the token field when apiUrl differs from the saved endpoint", async () => {
  // Regression test for the auth-field-monitor race: when setAuthToken is called after
  // successful OAuth, apiUrl may differ from the pre-auth saved endpoint (e.g. canonical
  // URL from token audience vs user-typed URL). Auth-sensitive fields must be synced into
  // the baseline before change handlers run so auth-field-monitor sees no sentinel-field
  // change and does not clear the freshly-set token.
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
      window.__saveIdeConfig__ = function () {};
    },
  });

  // Simulate the form having a different endpoint in its saved baseline by changing
  // the endpoint field programmatically (bypassing events so dirty-tracker baseline stays
  // at the fixture default).
  var endpointInput = dom.window.document.getElementById("endpoint");
  var tokenInput = dom.window.document.getElementById("token");
  endpointInput.value = "https://api.snyk.io";

  // setAuthToken is called with an apiUrl that differs from the current endpoint.
  // The token must NOT be cleared by auth-field-monitor.
  dom.window.setAuthToken("new-oauth-token", "https://api.eu.snyk.io");

  assert.equal(tokenInput.value, "new-oauth-token", "token field must not be cleared when setAuthToken updates the endpoint");
  assert.equal(endpointInput.value, "https://api.eu.snyk.io", "endpoint field must be updated to the new apiUrl");
});

test("authenticate does NOT call __saveIdeConfig__ before login", async () => {
  const html = await loadFixture();
  const saveConfigCalls = [];
  const calls = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = ideBridge(calls);
      window.__saveIdeConfig__ = function () { saveConfigCalls.push(true); };
    },
  });

  dom.window.ConfigApp.authentication.authenticate();

  assert.equal(saveConfigCalls.length, 0, "authenticate must NOT call __saveIdeConfig__");
});

test("authenticate reads live DOM values — changed form values override fixture defaults", async () => {
  const html = await loadFixture();
  const calls = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = ideBridge(calls);
    },
  });

  // Simulate user editing the form without saving
  var authMethodEl = dom.window.document.getElementById("authenticationMethod");
  var endpointEl = dom.window.document.getElementById("endpoint");
  var insecureEl = dom.window.document.querySelector("[name='insecure']");

  authMethodEl.value = "pat";
  endpointEl.value = "https://api.eu.snyk.io";
  insecureEl.checked = true;

  dom.window.ConfigApp.authentication.authenticate();

  var loginCalls = calls.filter(function (c) { return c.cmd === "snyk.login"; });
  assert.equal(loginCalls.length, 1);
  assert.equal(loginCalls[0].args[0], "pat", "should read updated authMethod");
  assert.equal(loginCalls[0].args[1], "https://api.eu.snyk.io", "should read updated endpoint");
  assert.equal(loginCalls[0].args[2], true, "should read updated insecure");
});

test("logout calls __ideExecuteCommand__ with snyk.logout and empty args", async () => {
  const html = await loadFixture();
  const calls = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = ideBridge(calls);
    },
  });

  dom.window.ConfigApp.authentication.logout();

  var logoutCalls = calls.filter(function (c) { return c.cmd === "snyk.logout"; });
  assert.equal(logoutCalls.length, 1, "should call __ideExecuteCommand__ with snyk.logout exactly once");
  assert.equal(logoutCalls[0].args.length, 0, "logout args should be empty array");
});

test("logout clears the token field value", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  var tokenInput = dom.window.document.getElementById("token");
  // fixture renders with token="test-token"
  assert.equal(tokenInput.value, "test-token", "token field should have fixture value before logout");

  dom.window.ConfigApp.authentication.logout();

  assert.equal(tokenInput.value, "", "token field must be cleared after logout");
});

test("authenticate does not throw when __ideExecuteCommand__ is not defined", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    // __ideExecuteCommand__ intentionally not set
  });

  assert.doesNotThrow(function () {
    dom.window.ConfigApp.authentication.authenticate();
  }, "authenticate must not throw when __ideExecuteCommand__ is not defined");
});

test("logout does not throw when __ideExecuteCommand__ is not defined", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    // __ideExecuteCommand__ intentionally not set
  });

  assert.doesNotThrow(function () {
    dom.window.ConfigApp.authentication.logout();
  }, "logout must not throw when __ideExecuteCommand__ is not defined");
});

test("setAuthToken with non-empty token disables Authenticate and enables Logout", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  dom.window.setAuthToken("new-token");

  var authBtn = dom.window.document.getElementById("authenticate-btn");
  var logoutBtn = dom.window.document.getElementById("logout-btn");
  assert.ok(authBtn, "authenticate-btn must exist");
  assert.ok(logoutBtn, "logout-btn must exist");
  assert.equal(authBtn.disabled, true, "Authenticate must be disabled after setAuthToken with token");
  assert.equal(logoutBtn.disabled, false, "Logout must be enabled after setAuthToken with token");
});

test("setAuthToken with empty string enables Authenticate and disables Logout", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  // First set a token, then clear it
  dom.window.setAuthToken("initial-token");
  dom.window.setAuthToken("");

  var authBtn = dom.window.document.getElementById("authenticate-btn");
  var logoutBtn = dom.window.document.getElementById("logout-btn");
  assert.equal(authBtn.disabled, false, "Authenticate must be enabled after clearing token");
  assert.equal(logoutBtn.disabled, true, "Logout must be disabled after clearing token");
});

test("logout enables Authenticate and disables Logout", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  // Simulate being authenticated first
  dom.window.setAuthToken("my-token");

  dom.window.ConfigApp.authentication.logout();

  var authBtn = dom.window.document.getElementById("authenticate-btn");
  var logoutBtn = dom.window.document.getElementById("logout-btn");
  assert.equal(authBtn.disabled, false, "Authenticate must be enabled after logout");
  assert.equal(logoutBtn.disabled, true, "Logout must be disabled after logout");
});

test("page load without token enables Authenticate and disables Logout", async () => {
  const html = await loadFixture();
  // pretendToBeVisual enables the window.load event to fire in JSDOM
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    pretendToBeVisual: true,
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
      // Clear the token field after scripts register their load listeners but before load fires,
      // so app.js's window.load handler sees an empty token and sets the unauthenticated button state.
      window.addEventListener("DOMContentLoaded", function() {
        var tokenInput = window.document.getElementById("token");
        if (tokenInput) { tokenInput.value = ""; }
      });
    },
  });
  // Wait for app.js window.load handler to run (sets initial button states)
  await sleep(50);

  var authBtn = dom.window.document.getElementById("authenticate-btn");
  var logoutBtn = dom.window.document.getElementById("logout-btn");
  // token was cleared before load → unauthenticated initial state
  assert.equal(authBtn.disabled, false, "Authenticate must be enabled at page load when no token");
  assert.equal(logoutBtn.disabled, true, "Logout must be disabled at page load when no token");
});

test("page load with token present disables Authenticate and enables Logout", async () => {
  const html = await loadFixture();
  // pretendToBeVisual enables the window.load event to fire in JSDOM
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    pretendToBeVisual: true,
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });
  // Wait for app.js window.load handler to run (sets initial button states)
  await sleep(50);

  var authBtn = dom.window.document.getElementById("authenticate-btn");
  var logoutBtn = dom.window.document.getElementById("logout-btn");
  // fixture renders with token="test-token" (non-empty)
  assert.equal(authBtn.disabled, true, "Authenticate must be disabled at page load when token present");
  assert.equal(logoutBtn.disabled, false, "Logout must be enabled at page load when token present");
});

test("setAuthToken marks the form dirty so the save button becomes active", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });
  const w = dom.window;

  // Initialize dirty tracker with the fixture state as baseline (token="test-token")
  w.dirtyTracker = new w.DirtyTracker();
  w.dirtyTracker.initialize(w.ConfigApp.formHandler.collectData);
  assert.equal(w.dirtyTracker.isDirty, false, "form must be clean before setAuthToken");

  // IDE calls setAuthToken after successful OAuth with a new token
  w.setAuthToken("new-oauth-token");

  assert.equal(w.dirtyTracker.isDirty, true, "form must be dirty after setAuthToken so the save button becomes active");
});

test("setAuthToken with different endpoint does not clear token when auth-field-monitor is registered", async () => {
  // Stronger version of the auth-field-monitor regression test: verifies that with a
  // properly initialized dirty tracker and auth-field-monitor listener, the token is
  // not cleared when setAuthToken updates the endpoint to a value differing from the baseline.
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
      window.__saveIdeConfig__ = function () {};
    },
  });
  const w = dom.window;
  initDirtyTrackerWithAuthMonitor(w);

  var tokenInput = w.document.getElementById("token");
  var endpointInput = w.document.getElementById("endpoint");

  // setAuthToken is called with apiUrl that differs from the fixture baseline endpoint
  w.setAuthToken("new-oauth-token", "https://api.eu.snyk.io");

  assert.equal(tokenInput.value, "new-oauth-token", "token must not be cleared when endpoint changes via setAuthToken");
  assert.equal(endpointInput.value, "https://api.eu.snyk.io", "endpoint must be updated");
  assert.equal(w.dirtyTracker.isDirty, true, "form must be dirty after setAuthToken");
});

test("setAuthToken does not clear token when authenticationMethod was changed before login", async () => {
  // When the user changes authenticationMethod in the form, auth-field-monitor correctly
  // clears the token. After the user authenticates with the new method, setAuthToken must
  // not clear the freshly-set token, even though authMethod now differs from the pre-auth baseline.
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
      window.__saveIdeConfig__ = function () {};
    },
  });
  const w = dom.window;
  initDirtyTrackerWithAuthMonitor(w);

  // User changes authMethod — auth-field-monitor clears the token (correct behavior)
  w.document.getElementById("authenticationMethod").value = "pat";
  w.dirtyTracker.checkDirty();
  assert.equal(w.document.getElementById("token").value, "", "token must be cleared when authMethod changes (auth-field-monitor)");

  // User authenticates with the new method; IDE calls setAuthToken
  w.setAuthToken("new-pat-token");

  assert.equal(w.document.getElementById("token").value, "new-pat-token", "token must not be cleared by setAuthToken after authMethod change");
  assert.equal(w.dirtyTracker.isDirty, true, "form must be dirty after setAuthToken");
});
