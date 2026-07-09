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
// Re-authentication control (IDE-2181 CP2)
// ---------------------------------------------------------------------------

test("settings-fallback: re-auth control is present in the Authentication section", async () => {
  const win = await buildFallbackDom();
  const btn = win.document.getElementById("reauth-button");
  assert.ok(btn, "a re-auth control (#reauth-button) must exist");

  // It must live inside the Authentication section, not CLI Configuration.
  const authHeading = [...win.document.querySelectorAll("h2")].find(
    (h) => h.textContent.trim() === "Authentication"
  );
  assert.ok(authHeading, "Authentication section heading must exist");
  const authSection = authHeading.closest(".section");
  assert.ok(
    authSection && authSection.contains(btn),
    "re-auth control must be inside the Authentication section"
  );
});

test("settings-fallback: activating the control dispatches snyk.login through the bridge", async () => {
  const win = await buildFallbackDom();
  const calls = [];
  win.__ideExecuteCommand__ = (cmd, args, callback) => {
    calls.push({ cmd, args, callback });
  };

  const btn = win.document.getElementById("reauth-button");
  btn.dispatchEvent(new win.Event("click"));

  assert.strictEqual(calls.length, 1, "__ideExecuteCommand__ must be called exactly once");
  assert.strictEqual(calls[0].cmd, "snyk.login", "command must be snyk.login");
  // D2(a): pass no auth args so the LS re-auths with the existing configured method/endpoint.
  // (args is created in the jsdom realm, so compare shape/length rather than deepStrictEqual.)
  assert.ok(Array.isArray(calls[0].args), "args must be an array");
  assert.strictEqual(calls[0].args.length, 0, "no auth args should be passed (reuse configured auth)");
  // Complete the lifecycle so the client-side safety timeout started by startReauth
  // is cleared and does not linger (a dangling jsdom timer keeps `node --test` alive).
  calls[0].callback();
});

test("settings-fallback: activating the control is a no-op-safe when the bridge is absent", async () => {
  const win = await buildFallbackDom();
  // No window.__ideExecuteCommand__ defined.
  const btn = win.document.getElementById("reauth-button");
  assert.doesNotThrow(() => {
    btn.dispatchEvent(new win.Event("click"));
  }, "clicking the control without a bridge must not throw");
});

// ---------------------------------------------------------------------------
// Re-auth control lifecycle: disable → done/timeout → re-enable (IDE-2181 CP2)
// ---------------------------------------------------------------------------

test("settings-fallback: activating the control disables it and shows Connecting…", async () => {
  const win = await buildFallbackDom();
  win.__REAUTH_TIMEOUT_MS__ = 5; // tiny safety timeout so no timer lingers
  win.__ideExecuteCommand__ = () => {}; // bridge accepts the call, never invokes done
  const btn = win.document.getElementById("reauth-button");

  btn.dispatchEvent(new win.Event("click"));

  assert.strictEqual(btn.disabled, true, "button must be disabled while re-auth is in progress");
  assert.strictEqual(btn.textContent, "Connecting…", "button label must show progress");

  // Drain the tiny safety timeout so the jsdom timer does not linger.
  // Generous margin (40x the timer) so a loaded CI runner still drains it.
  await new Promise((r) => win.setTimeout(r, 200));
});

test("settings-fallback: the bridge done callback re-enables the control and restores the label", async () => {
  const win = await buildFallbackDom();
  let captured;
  win.__ideExecuteCommand__ = (_cmd, _args, callback) => { captured = callback; };
  const btn = win.document.getElementById("reauth-button");

  btn.dispatchEvent(new win.Event("click"));
  assert.strictEqual(typeof captured, "function", "bridge must receive a done callback as its 3rd arg");
  assert.strictEqual(btn.disabled, true, "button disabled after click");

  captured(); // LS signals completion

  assert.strictEqual(btn.disabled, false, "button must be re-enabled after done fires");
  assert.strictEqual(btn.textContent, "Connect", "label must be restored after done fires");
});

test("settings-fallback: a second activation while in progress does not dispatch a second snyk.login", async () => {
  const win = await buildFallbackDom();
  const calls = [];
  let captured;
  win.__ideExecuteCommand__ = (cmd, _args, callback) => { calls.push(cmd); captured = callback; };
  const btn = win.document.getElementById("reauth-button");

  btn.dispatchEvent(new win.Event("click"));
  btn.dispatchEvent(new win.Event("click")); // while still disabled/in progress

  assert.strictEqual(calls.length, 1, "second activation while in progress must be ignored");

  captured(); // clear the safety timer
});

test("settings-fallback: the safety timeout re-enables the control if done never fires", async () => {
  const win = await buildFallbackDom();
  win.__REAUTH_TIMEOUT_MS__ = 5; // short, injectable safety timeout for the test
  win.__ideExecuteCommand__ = () => {}; // bridge accepts the call but never invokes done
  const btn = win.document.getElementById("reauth-button");

  btn.dispatchEvent(new win.Event("click"));
  assert.strictEqual(btn.disabled, true, "button disabled immediately after click");

  // Wait well past the safety timeout (40x) so a loaded CI runner still fires it.
  await new Promise((r) => win.setTimeout(r, 200));

  assert.strictEqual(btn.disabled, false, "button must re-enable after the safety timeout");
  assert.strictEqual(btn.textContent, "Connect", "label must be restored after the safety timeout");
});

test("settings-fallback: a stale done() from a superseded re-auth cycle is inert during a new cycle", async () => {
  const win = await buildFallbackDom();
  const calls = [];
  const callbacks = [];
  win.__ideExecuteCommand__ = (cmd, _args, callback) => {
    calls.push(cmd);
    callbacks.push(callback);
  };
  const btn = win.document.getElementById("reauth-button");

  // Cycle A: click → disabled, arms a tiny safety timer, bridge receives doneA (captured, NOT invoked).
  win.__REAUTH_TIMEOUT_MS__ = 5;
  btn.dispatchEvent(new win.Event("click"));
  assert.strictEqual(calls.length, 1, "cycle A must dispatch snyk.login");
  const doneA = callbacks[0];

  // Auth exceeds the safety timeout (SSO/2FA) → doneA fires via the timer → button re-enabled.
  // Generous drain (40x the timer) keeps this deterministic on a loaded CI runner.
  await new Promise((r) => win.setTimeout(r, 200));
  assert.strictEqual(btn.disabled, false, "cycle A safety timeout must re-enable the button");

  // Cycle B: user clicks again → new cycle, dispatches a 2nd snyk.login, disables the button.
  // Long timeout so cycle B stays in flight for the rest of the test (drained via doneB below).
  win.__REAUTH_TIMEOUT_MS__ = 60000;
  btn.dispatchEvent(new win.Event("click"));
  assert.strictEqual(calls.length, 2, "cycle B must dispatch a second snyk.login");
  assert.strictEqual(btn.disabled, true, "cycle B must disable the button");
  assert.strictEqual(btn.textContent, "Connecting…", "cycle B must show progress");

  // Cycle A's original bridge call finally completes → invokes the still-referenced stale doneA.
  doneA();

  // The stale callback must be INERT: cycle B's in-flight state must be preserved.
  assert.strictEqual(btn.disabled, true, "stale doneA must NOT re-enable the button mid-cycle-B");
  assert.strictEqual(btn.textContent, "Connecting…", "stale doneA must NOT restore the label mid-cycle-B");

  // And it must not have opened the double-dispatch guard: a further click stays blocked.
  btn.dispatchEvent(new win.Event("click"));
  assert.strictEqual(calls.length, 2, "no further snyk.login may be dispatched while cycle B is in flight");

  // Drain cycle B's safety timer so no jsdom timer lingers and keeps `node --test` alive.
  callbacks[1]();
});

test("settings-fallback: the auth status copy is state-neutral (does not overclaim signed-out state)", async () => {
  const win = await buildFallbackDom();
  const status = win.document.getElementById("reauth-status");
  const text = status.textContent.trim().toLowerCase();

  assert.ok(text.length > 0, "status copy must be present");
  assert.ok(
    !text.includes("you are not signed in"),
    `status copy must not assert the user is signed out; got "${status.textContent}"`
  );
  assert.ok(
    /reconnect|sign in/.test(text),
    `status copy should be action-oriented (mention reconnect/sign in); got "${status.textContent}"`
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
