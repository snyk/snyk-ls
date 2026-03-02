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

test("setAuthToken with non-empty token shows Authenticated status", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  dom.window.setAuthToken("new-token");

  var statusEl = dom.window.document.getElementById("auth-status");
  assert.ok(statusEl, "auth-status element must exist");
  assert.equal(statusEl.innerHTML, "Authenticated", "status must show Authenticated after setAuthToken");
  assert.ok(statusEl.className.indexOf("hidden") === -1, "status element must not be hidden");
});

test("setAuthToken with empty string hides auth status", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  // First set a token
  dom.window.setAuthToken("initial-token");
  // Then clear it
  dom.window.setAuthToken("");

  var statusEl = dom.window.document.getElementById("auth-status");
  assert.ok(statusEl.className.indexOf("hidden") !== -1, "status must be hidden after clearing token");
});

test("logout hides auth status indicator", async () => {
  const html = await loadFixture();

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });

  // Simulate being authenticated first
  dom.window.setAuthToken("my-token");
  var statusEl = dom.window.document.getElementById("auth-status");
  assert.ok(statusEl.className.indexOf("hidden") === -1, "status visible before logout");

  dom.window.ConfigApp.authentication.logout();

  assert.ok(statusEl.className.indexOf("hidden") !== -1, "status must be hidden after logout");
});

test("auth status shows Authenticated on page load when token already present", async () => {
  const html = await loadFixture();
  // pretendToBeVisual enables the window.load event to fire in JSDOM
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    pretendToBeVisual: true,
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
    },
  });
  // Wait for app.js window.load handler to run (sets initial auth status)
  await sleep(50);

  var statusEl = dom.window.document.getElementById("auth-status");
  // fixture renders with token="test-token" (non-empty), so status should be Authenticated
  assert.equal(statusEl.textContent, "Authenticated", "auth status must show Authenticated at page load when token present");
  assert.ok(statusEl.className.indexOf("hidden") === -1, "auth status must not be hidden");
});
