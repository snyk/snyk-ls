// ABOUTME: Tests for the settings-fallback.html inline script.
// ABOUTME: Covers collectData, diff-based dirty tracking, save gating, and validation.
//
// Regenerate snapshot when an intentional change shifts the payload:
//   UPDATE_SNAPSHOT=1 npm test --prefix js-tests -- --test-name-pattern="settings-fallback payload"

import assert from "node:assert/strict";
import test from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFallbackDom } from "./helpers.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT_PATH = join(__dirname, "snapshots", "settings-fallback-payload.json");

function stableStringify(value) {
  return (
    JSON.stringify(
      value,
      (_key, val) => {
        if (val && typeof val === "object" && !Array.isArray(val)) {
          return Object.keys(val)
            .sort()
            .reduce((acc, k) => {
              acc[k] = val[k];
              return acc;
            }, {});
        }
        return val;
      },
      2
    ) + "\n"
  );
}

// ---------------------------------------------------------------------------
// collectData smoke tests
// ---------------------------------------------------------------------------

test("settings-fallback: collectData returns isFallbackForm and all 5 field keys", async () => {
  const win = await buildFallbackDom();
  const data = win.collectData();
  assert.ok(data.isFallbackForm === true, "isFallbackForm must be true");
  assert.ok("cli_path" in data, "must have cli_path");
  assert.ok("automatic_download" in data, "must have automatic_download");
  assert.ok("binary_base_url" in data, "must have binary_base_url");
  assert.ok("cli_release_channel" in data, "must have cli_release_channel");
  assert.ok("proxy_insecure" in data, "must have proxy_insecure");
});

test("settings-fallback: collectData serializes checkboxes as booleans", async () => {
  const win = await buildFallbackDom();
  const data = win.collectData();
  assert.strictEqual(typeof data.automatic_download, "boolean");
  assert.strictEqual(typeof data.proxy_insecure, "boolean");
});

test("settings-fallback: collectData falls back to placeholder when binary_base_url is empty", async () => {
  const win = await buildFallbackDom();
  const input = win.document.getElementById("binary_base_url");
  input.value = "";
  const data = win.collectData();
  assert.strictEqual(data.binary_base_url, input.placeholder);
});

test("settings-fallback: collectData resolves custom channel value with v prefix", async () => {
  const win = await buildFallbackDom();
  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  sel.value = "custom";
  customInput.value = "1.1292.0"; // no 'v' prefix
  const data = win.collectData();
  assert.strictEqual(data.cli_release_channel, "v1.1292.0");
});

test("settings-fallback: collectData resolves custom channel with existing v prefix", async () => {
  const win = await buildFallbackDom();
  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  sel.value = "custom";
  customInput.value = "v1.1292.0";
  const data = win.collectData();
  assert.strictEqual(data.cli_release_channel, "v1.1292.0");
});

test("settings-fallback: collectData falls back to stable when custom input is empty", async () => {
  const win = await buildFallbackDom();
  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  sel.value = "custom";
  customInput.value = "";
  const data = win.collectData();
  assert.strictEqual(data.cli_release_channel, "stable");
});

// ---------------------------------------------------------------------------
// collectChangedData diff tests
// ---------------------------------------------------------------------------

test("settings-fallback: collectChangedData returns only isFallbackForm when nothing changed", async () => {
  const win = await buildFallbackDom();
  const changed = win.collectChangedData();
  const keys = Object.keys(changed);
  assert.deepStrictEqual(keys, ["isFallbackForm"], "no-op save must only contain isFallbackForm");
  assert.strictEqual(changed.isFallbackForm, true);
});

test("settings-fallback: collectChangedData returns only toggled field", async () => {
  const win = await buildFallbackDom();
  const checkbox = win.document.getElementById("proxy_insecure");
  const originalValue = checkbox.checked;
  checkbox.checked = !originalValue;

  const changed = win.collectChangedData();
  assert.strictEqual(changed.isFallbackForm, true);
  assert.strictEqual(changed.proxy_insecure, !originalValue);
  // other fields must not be included
  assert.ok(!("cli_path" in changed), "cli_path must not appear in diff");
  assert.ok(!("automatic_download" in changed), "automatic_download must not appear in diff");
  assert.ok(!("binary_base_url" in changed), "binary_base_url must not appear in diff");
  assert.ok(!("cli_release_channel" in changed), "cli_release_channel must not appear in diff");
});

test("settings-fallback: baseline resets after save so second save has fresh diff", async () => {
  const win = await buildFallbackDom();
  const saved = [];
  win.__saveIdeConfig__ = (json) => saved.push(JSON.parse(json));

  // First change: cli_path
  win.document.getElementById("cli_path").value = "/custom/path";
  win.getAndSaveIdeConfig();
  assert.strictEqual(saved.length, 1);
  assert.ok("cli_path" in saved[0], "first save must contain cli_path");

  // Second change: proxy_insecure only (cli_path is now baseline)
  win.document.getElementById("proxy_insecure").checked = true;
  win.getAndSaveIdeConfig();
  assert.strictEqual(saved.length, 2);
  assert.ok("proxy_insecure" in saved[1], "second save must contain proxy_insecure");
  assert.ok(!("cli_path" in saved[1]), "second save must NOT contain cli_path (already baseline)");
});

// ---------------------------------------------------------------------------
// isDirty / dirty callback tests
// ---------------------------------------------------------------------------

test("settings-fallback: __isFormDirty__ is false initially", async () => {
  const win = await buildFallbackDom();
  assert.strictEqual(win.__isFormDirty__(), false);
});

test("settings-fallback: __isFormDirty__ is true after field change", async () => {
  const win = await buildFallbackDom();
  win.document.getElementById("cli_path").value = "/changed/path";
  assert.strictEqual(win.__isFormDirty__(), true);
});

test("settings-fallback: __isFormDirty__ is false when field reverted to original", async () => {
  const win = await buildFallbackDom();
  const input = win.document.getElementById("cli_path");
  const original = input.value;
  input.value = "/changed/path";
  assert.strictEqual(win.__isFormDirty__(), true);
  input.value = original;
  assert.strictEqual(win.__isFormDirty__(), false);
});

test("settings-fallback: __onFormDirtyChange__ fires on markDirty transitions", async () => {
  const win = await buildFallbackDom();
  const dirtyEvents = [];
  win.__onFormDirtyChange__ = (isDirty) => dirtyEvents.push(isDirty);

  // Change cli_path — should fire with true (dirty)
  win.document.getElementById("cli_path").value = "/new/path";
  win.markDirty();
  assert.ok(dirtyEvents.includes(true), "dirty=true must fire after field change");
});

// ---------------------------------------------------------------------------
// Save gating on invalid custom version
// ---------------------------------------------------------------------------

test("settings-fallback: getAndSaveIdeConfig is blocked on invalid custom version", async () => {
  const win = await buildFallbackDom();
  const saveAttempts = [];
  const saveFinished = [];
  win.__saveIdeConfig__ = (json) => saveAttempts.push(json);
  win.__ideSaveAttemptFinished__ = (status) => saveFinished.push(status);

  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  sel.value = "custom";
  customInput.value = "not-a-version";

  win.getAndSaveIdeConfig();

  assert.strictEqual(saveAttempts.length, 0, "__saveIdeConfig__ must NOT be called on invalid version");
  assert.deepStrictEqual(saveFinished, ["validation_error"], "__ideSaveAttemptFinished__ must be called with validation_error");
});

test("settings-fallback: getAndSaveIdeConfig succeeds with valid custom version", async () => {
  const win = await buildFallbackDom();
  const saveAttempts = [];
  win.__saveIdeConfig__ = (json) => saveAttempts.push(json);

  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  sel.value = "custom";
  customInput.value = "v1.1292.0";

  win.getAndSaveIdeConfig();

  assert.strictEqual(saveAttempts.length, 1, "__saveIdeConfig__ must be called for valid version");
});

// ---------------------------------------------------------------------------
// Validation on load (stale warning regression)
// ---------------------------------------------------------------------------

test("settings-fallback: error message is hidden on load for valid custom version fixture", async () => {
  // Default fixture has stable channel — error must be hidden on load
  const win = await buildFallbackDom();
  const error = win.document.getElementById("cli-version-error");
  assert.ok(
    error.className.includes("hidden"),
    `cli-version-error must be hidden on load when channel is not custom; got class="${error.className}"`
  );
});

test("settings-fallback: error message is hidden on load when custom fixture has valid version", async () => {
  // Fixture rendered with a valid custom version: custom input visible, valid version, no error
  const win = await buildFallbackDom({ fixtureName: "settings-fallback-custom-valid.html" });
  const error = win.document.getElementById("cli-version-error");
  assert.ok(
    error.className.includes("hidden"),
    `cli-version-error must be hidden on load for valid custom version; got class="${error.className}"`
  );
  const sel = win.document.getElementById("cli_release_channel");
  assert.strictEqual(sel.value, "custom");
});

test("settings-fallback: error message is visible on load when custom fixture has invalid version", async () => {
  // Fixture rendered with an invalid custom version string — error must surface on load
  const win = await buildFallbackDom({ fixtureName: "settings-fallback-custom-invalid.html" });
  const error = win.document.getElementById("cli-version-error");
  assert.ok(
    !error.className.includes("hidden"),
    `cli-version-error must be visible on load for invalid custom version; got class="${error.className}"`
  );
});

// ---------------------------------------------------------------------------
// Validation on select change
// ---------------------------------------------------------------------------

test("settings-fallback: switching from custom to stable hides error message", async () => {
  const win = await buildFallbackDom();
  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  const error = win.document.getElementById("cli-version-error");

  // Set invalid custom value to make the error appear
  sel.value = "custom";
  customInput.value = "not-a-version";
  // Manually surface the error (simulate user typing invalid version)
  error.className = error.className.replace(/\bhidden\b/, "").trim();

  // Switch back to stable
  sel.value = "stable";
  // Fire the select change handler (the one that calls toggleCustomVersionInput + validateCliVersion)
  sel.dispatchEvent(new win.Event("change"));

  assert.ok(
    error.className.includes("hidden"),
    "cli-version-error must be hidden after switching to stable"
  );
});

test("settings-fallback: error shown when custom channel has invalid value", async () => {
  const win = await buildFallbackDom();
  const sel = win.document.getElementById("cli_release_channel");
  const customInput = win.document.getElementById("cli_release_channel_custom");
  const error = win.document.getElementById("cli-version-error");

  sel.value = "custom";
  customInput.value = "bad-version-string";
  customInput.dispatchEvent(new win.Event("input"));

  assert.ok(
    !error.className.includes("hidden"),
    "cli-version-error must be visible for invalid custom version"
  );
});

// ---------------------------------------------------------------------------
// Log out control (IDE-2181)
// ---------------------------------------------------------------------------

test("settings-fallback: the authentication section offers a log out control and no login control", async () => {
  const win = await buildFallbackDom();
  const logoutBtn = win.document.getElementById("logout-button");
  assert.ok(logoutBtn, "a log out control (#logout-button) must exist");
  assert.strictEqual(
    logoutBtn.textContent.trim(),
    "Clear credentials",
    'log out control label must be "Clear credentials"'
  );

  // No login/"Connect" control must be present.
  assert.ok(
    !win.document.getElementById("reauth-button"),
    "no #reauth-button (login control) must exist"
  );

  // The log out button must live inside the Authentication section.
  const authHeading = [...win.document.querySelectorAll("h2")].find(
    (h) => h.textContent.trim() === "Authentication"
  );
  assert.ok(authHeading, "Authentication section heading must exist");
  const authSection = authHeading.closest(".section");
  assert.ok(
    authSection && authSection.contains(logoutBtn),
    "log out control must be inside the Authentication section"
  );
});

test("settings-fallback: activating the control dispatches snyk.logout through the bridge", async () => {
  const win = await buildFallbackDom();
  const calls = [];
  win.__ideExecuteCommand__ = (cmd, args, callback) => {
    calls.push({ cmd, args, callback });
  };

  const btn = win.document.getElementById("logout-button");
  btn.dispatchEvent(new win.Event("click"));

  assert.strictEqual(calls.length, 1, "__ideExecuteCommand__ must be called exactly once");
  assert.strictEqual(calls[0].cmd, "snyk.logout", "command must be snyk.logout");
  assert.ok(Array.isArray(calls[0].args), "args must be an array");
  assert.strictEqual(calls[0].args.length, 0, "no args should be passed to snyk.logout");
});

test("settings-fallback: activating the control is a no-op-safe when the bridge is absent", async () => {
  const win = await buildFallbackDom();
  // No window.__ideExecuteCommand__ defined.
  const btn = win.document.getElementById("logout-button");
  assert.doesNotThrow(() => {
    btn.dispatchEvent(new win.Event("click"));
  }, "clicking the log out control without a bridge must not throw");
});

test("settings-fallback: after logout the status copy confirms credentials were cleared", async () => {
  const win = await buildFallbackDom();
  let captured;
  win.__ideExecuteCommand__ = (_cmd, _args, callback) => { captured = callback; };

  const btn = win.document.getElementById("logout-button");
  btn.dispatchEvent(new win.Event("click"));

  assert.strictEqual(typeof captured, "function", "bridge must receive a done callback");

  // Before done fires the status copy is the default prompt.
  const status = win.document.getElementById("logout-status");
  const textBefore = status.textContent.trim();
  assert.strictEqual(textBefore.length, 0, "status copy must be empty before logout");

  // Fire the done callback (LS confirmed credentials cleared).
  captured();

  // After done the status copy must confirm the cleared state.
  const textAfter = status.textContent.trim();
  assert.ok(
    /signed out|credentials.*cleared/i.test(textAfter),
    `status copy must confirm credentials cleared after done; got "${textAfter}"`
  );
});

// ---------------------------------------------------------------------------
// Payload snapshot
// ---------------------------------------------------------------------------

test("settings-fallback payload snapshot: collectChangedData output matches fixture", async () => {
  const win = await buildFallbackDom();

  // Make one deterministic change
  win.document.getElementById("cli_path").value = "/test/snyk-cli";
  win.document.getElementById("proxy_insecure").checked = true;

  const data = win.collectChangedData();
  const actual = stableStringify(data);

  if (process.env.UPDATE_SNAPSHOT === "1") {
    await writeFile(SNAPSHOT_PATH, actual, "utf8");
    return;
  }

  let expected;
  try {
    expected = await readFile(SNAPSHOT_PATH, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error(
        `snapshot missing at ${SNAPSHOT_PATH}; run UPDATE_SNAPSHOT=1 npm test to create`
      );
    }
    throw err;
  }

  assert.equal(
    actual,
    expected,
    "settings-fallback payload changed — review diff; if intentional re-run with UPDATE_SNAPSHOT=1"
  );
});
