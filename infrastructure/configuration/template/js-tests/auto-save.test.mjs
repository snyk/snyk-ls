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

function setupDom(html, calls) {
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function (cmd, args) { calls.push({ cmd, args }); };
      // Stub the save bridge so save "succeeds"
      window.__saveIdeConfig__ = function () {};
    },
  });

  const w = dom.window;

  // Simulate what formState.initializeDirtyTracking() does at page load
  w.dirtyTracker = new w.DirtyTracker();
  w.dirtyTracker.initialize(function () {
    return w.ConfigApp.formHandler.collectData();
  });
  w.dirtyTracker.addChangeListener(w.ConfigApp.authFieldMonitor.onDataChange);

  return dom;
}

test("getAndSaveIdeConfig does NOT call snyk.logout when endpoint changes", async () => {
  const html = await loadFixture();
  const calls = [];
  const dom = setupDom(html, calls);
  const w = dom.window;

  // User changes endpoint
  const endpointEl = w.document.getElementById("endpoint");
  endpointEl.value = "https://api.eu.snyk.io";

  // Trigger auto-save (simulates blur → triggerChangeHandlers → getAndSaveIdeConfig)
  w.ConfigApp.autoSave.getAndSaveIdeConfig();

  const logoutCalls = calls.filter(c => c.cmd === "snyk.logout");
  assert.equal(logoutCalls.length, 0,
    "auto-save must NOT call snyk.logout when endpoint changes — logout interferes with subsequent snyk.login");
});

test("getAndSaveIdeConfig does NOT call snyk.logout when endpoint is unchanged", async () => {
  const html = await loadFixture();
  const calls = [];
  const dom = setupDom(html, calls);
  const w = dom.window;

  // Endpoint unchanged — trigger auto-save
  w.ConfigApp.autoSave.getAndSaveIdeConfig();

  const logoutCalls = calls.filter(c => c.cmd === "snyk.logout");
  assert.equal(logoutCalls.length, 0, "auto-save must not call snyk.logout when endpoint is unchanged");
});

test("getAndSaveIdeConfig saves form data to __saveIdeConfig__ on success", async () => {
  const html = await loadFixture();
  const savedPayloads = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
      window.__saveIdeConfig__ = function (payload) { savedPayloads.push(payload); };
    },
  });

  dom.window.ConfigApp.autoSave.getAndSaveIdeConfig();

  assert.equal(savedPayloads.length, 1, "__saveIdeConfig__ must be called once");
  const saved = JSON.parse(savedPayloads[0]);
  assert.ok(saved.endpoint !== undefined, "saved payload must include endpoint");
});

test("getAndSaveIdeConfig does not call __saveIdeConfig__ when validation fails", async () => {
  const html = await loadFixture();
  const savedPayloads = [];

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    beforeParse(window) {
      window.__ideExecuteCommand__ = function () {};
      window.__saveIdeConfig__ = function (payload) { savedPayloads.push(payload); };
    },
  });
  const w = dom.window;

  // Inject an invalid endpoint then run the input-level validator to update validationState
  const endpointEl = w.document.getElementById("endpoint");
  endpointEl.value = "not-a-valid-url";
  w.ConfigApp.validation.validateEndpointOnInput();

  w.ConfigApp.autoSave.getAndSaveIdeConfig();

  assert.equal(savedPayloads.length, 0, "__saveIdeConfig__ must NOT be called when validation fails");
});
