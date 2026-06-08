// ABOUTME: Regression tests for IDE-1992 — settings panel loses changes when closed
// ABOUTME: without blurring a focused text field first.
//
// Three cases from the ticket:
//   1. Auto-save IDE: visibilitychange → hidden fires save with the focused field's value
//   2. Non-auto-save IDE: getAndSaveIdeConfig() (OK button path) captures focused field value
//   3. Non-auto-save IDE: visibilitychange does NOT trigger a save

import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Enable auto-save on the window and install a __saveIdeConfig__ spy.
 * Returns the list of call arguments (each is the JSON string that was passed).
 */
function enableAutoSave(win) {
  win.__IS_IDE_AUTOSAVE_ENABLED__ = true;
  var calls = [];
  win.__saveIdeConfig__ = function(jsonString) {
    calls.push(jsonString);
  };
  return calls;
}

/**
 * Install a __saveIdeConfig__ spy without enabling auto-save.
 */
function spySaveConfig(win) {
  var calls = [];
  win.__saveIdeConfig__ = function(jsonString) {
    calls.push(jsonString);
  };
  return calls;
}

/**
 * Dispatch a visibilitychange event with document.visibilityState mocked to 'hidden'.
 */
function simulatePanelClose(win) {
  Object.defineProperty(win.document, 'visibilityState', {
    value: 'hidden',
    configurable: true,
  });
  win.document.dispatchEvent(new win.Event('visibilitychange'));
}

// ---------------------------------------------------------------------------
// Case 1: Auto-save IDE — panel closed without blurring focused text field
// ---------------------------------------------------------------------------

test("auto-save IDE: visibilitychange saves typed value from focused text input", async () => {
  const win = await buildDom();
  const calls = enableAutoSave(win);

  const orgField = win.document.getElementById('organization');
  assert.ok(orgField, "organization field must exist in fixture");

  // Type a value without triggering blur (simulates user typing and immediately closing panel)
  orgField.value = 'my-typed-org';
  orgField.focus();

  simulatePanelClose(win);

  assert.ok(calls.length > 0, "save must have been called on panel close");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.organization, 'my-typed-org', "saved payload must include the typed value");
});

test("auto-save IDE: visibilitychange saves typed value from focused CLI path input", async () => {
  const win = await buildDom();
  const calls = enableAutoSave(win);

  const cliPathField = win.document.getElementById('cli_path');
  assert.ok(cliPathField, "cli_path field must exist in fixture");

  cliPathField.value = '/usr/local/bin/snyk-typed';
  cliPathField.focus();

  simulatePanelClose(win);

  assert.ok(calls.length > 0, "save must have been called on panel close");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.cli_path, '/usr/local/bin/snyk-typed', "saved payload must include the typed CLI path");
});

test("auto-save IDE: visibilitychange with no focused text input still saves (no blur needed)", async () => {
  const win = await buildDom();
  const calls = enableAutoSave(win);

  // Ensure nothing is focused
  if (win.document.activeElement && win.document.activeElement.blur) {
    win.document.activeElement.blur();
  }

  simulatePanelClose(win);

  // Save should still be attempted even with no focused input (form may have dirty state)
  assert.ok(calls.length > 0, "save must still be attempted when no text input is focused");
});

// ---------------------------------------------------------------------------
// Case 2: Non-auto-save IDE — getAndSaveIdeConfig() (OK button path)
// ---------------------------------------------------------------------------

test("non-auto-save IDE: getAndSaveIdeConfig captures focused text input value", async () => {
  const win = await buildDom();
  const calls = spySaveConfig(win);
  // auto-save is NOT enabled (default false)

  const orgField = win.document.getElementById('organization');
  orgField.value = 'org-from-ok-button';
  orgField.focus();

  // IDE calls this when the user clicks OK
  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must have been called when IDE invokes getAndSaveIdeConfig");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.organization, 'org-from-ok-button', "saved payload must include value from focused field");
});

test("non-auto-save IDE: getAndSaveIdeConfig captures focused api_endpoint value", async () => {
  const win = await buildDom();
  const calls = spySaveConfig(win);

  const endpointField = win.document.getElementById('api_endpoint');
  endpointField.value = 'https://api.eu.snyk.io';
  endpointField.focus();

  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must have been called");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.api_endpoint, 'https://api.eu.snyk.io', "saved payload must include typed endpoint");
});

// ---------------------------------------------------------------------------
// Case 3: Non-auto-save IDE — visibilitychange must NOT trigger a save
// ---------------------------------------------------------------------------

test("non-auto-save IDE: visibilitychange does NOT trigger save", async () => {
  const win = await buildDom();
  const calls = spySaveConfig(win);
  // auto-save is NOT enabled (default false)

  const orgField = win.document.getElementById('organization');
  orgField.value = 'value-that-must-not-be-saved';
  orgField.focus();

  simulatePanelClose(win);

  assert.equal(calls.length, 0, "visibilitychange must not trigger save when auto-save is disabled");
});

// ---------------------------------------------------------------------------
// Case 2b: Non-auto-save IDE — select (combo box) change saved on OK click
// ---------------------------------------------------------------------------

test("non-auto-save IDE: getAndSaveIdeConfig captures focused select value (scan_automatic)", async () => {
  const win = await buildDom();
  const calls = spySaveConfig(win);

  const sel = win.document.getElementById('scan_automatic');
  assert.ok(sel, "scan_automatic select must exist in fixture");

  // Set value directly without dispatching change event — simulates JCEF native dropdown
  // updating el.value without firing the change event before IntelliJ calls OK.
  const originalValue = sel.value;
  const expectedValue = originalValue === 'true' ? 'false' : 'true';
  sel.value = expectedValue;
  sel.focus();

  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must have been called");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.scan_automatic, expectedValue === 'true', "scan_automatic must reflect the toggled boolean value");
});

test("auto-save IDE: visibilitychange saves focused select value (scan_automatic)", async () => {
  const win = await buildDom();
  const calls = enableAutoSave(win);

  const sel = win.document.getElementById('scan_automatic');
  assert.ok(sel, "scan_automatic select must exist in fixture");

  const originalValue = sel.value;
  const expectedValue = originalValue === 'true' ? 'false' : 'true';
  sel.value = expectedValue;
  sel.focus();

  simulatePanelClose(win);

  assert.ok(calls.length > 0, "save must have been called on panel close");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.scan_automatic, expectedValue === 'true', "scan_automatic must reflect the toggled boolean value");
});

// ---------------------------------------------------------------------------
// Guard: no double-save when blur triggers re-entrance
// ---------------------------------------------------------------------------

test("auto-save IDE: re-entrance guard prevents double save on visibilitychange", async () => {
  const win = await buildDom();
  const calls = enableAutoSave(win);

  const orgField = win.document.getElementById('organization');
  orgField.value = 'deduped-org';
  orgField.focus();

  simulatePanelClose(win);

  // At most one save should contain the typed value (guard prevents recursive double-save)
  const matchingCalls = calls.filter(function(jsonStr) {
    try {
      return JSON.parse(jsonStr).organization === 'deduped-org';
    } catch (e) {
      return false;
    }
  });
  assert.equal(matchingCalls.length, 1, "typed value must be saved exactly once — guard must prevent double-save but not suppress the save");
});
