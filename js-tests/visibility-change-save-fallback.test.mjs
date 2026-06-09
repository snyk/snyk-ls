// ABOUTME: Regression tests for IDE-1992 — settings-fallback.html path.
// ABOUTME: Mirrors visibility-change-save.test.mjs but exercises the standalone
// ABOUTME: fallback HTML (shown before the Language Server is running) which has
// ABOUTME: its own copy of getAndSaveIdeConfig and the visibilitychange listener.

import assert from "node:assert/strict";
import test from "node:test";
import { buildFallbackDom } from "./helpers.mjs";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function enableAutoSave(win) {
  win.__IS_IDE_AUTOSAVE_ENABLED__ = true;
  var calls = [];
  win.__saveIdeConfig__ = function(jsonString) {
    calls.push(jsonString);
  };
  return calls;
}

function spySaveConfig(win) {
  var calls = [];
  win.__saveIdeConfig__ = function(jsonString) {
    calls.push(jsonString);
  };
  return calls;
}

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

test("fallback: auto-save IDE: visibilitychange saves typed value from focused cli_path", async () => {
  const win = await buildFallbackDom();
  const calls = enableAutoSave(win);

  const cliPathField = win.document.getElementById('cli_path');
  assert.ok(cliPathField, "cli_path field must exist in fallback form");

  cliPathField.value = '/typed/path/to/snyk';
  cliPathField.focus();

  simulatePanelClose(win);

  assert.ok(calls.length > 0, "save must be called on panel close");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.cli_path, '/typed/path/to/snyk', "saved payload must include the typed CLI path");
});

test("fallback: auto-save IDE: visibilitychange saves typed value from focused binary_base_url", async () => {
  const win = await buildFallbackDom();
  const calls = enableAutoSave(win);

  const urlField = win.document.getElementById('binary_base_url');
  assert.ok(urlField, "binary_base_url field must exist in fallback form");

  urlField.value = 'https://downloads.example.io';
  urlField.focus();

  simulatePanelClose(win);

  assert.ok(calls.length > 0, "save must be called on panel close");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.binary_base_url, 'https://downloads.example.io', "saved payload must include the typed URL");
});

// ---------------------------------------------------------------------------
// Case 2: Non-auto-save IDE — getAndSaveIdeConfig() (OK button path)
// ---------------------------------------------------------------------------

test("fallback: non-auto-save IDE: getAndSaveIdeConfig captures focused cli_path value", async () => {
  const win = await buildFallbackDom();
  const calls = spySaveConfig(win);

  const cliPathField = win.document.getElementById('cli_path');
  cliPathField.value = '/ok-button/path/to/snyk';
  cliPathField.focus();

  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must be called when IDE invokes getAndSaveIdeConfig");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.cli_path, '/ok-button/path/to/snyk', "saved payload must include value from focused field");
});

// ---------------------------------------------------------------------------
// Case 3: Non-auto-save IDE — visibilitychange must NOT trigger a save
// ---------------------------------------------------------------------------

test("fallback: non-auto-save IDE: visibilitychange does NOT trigger save", async () => {
  const win = await buildFallbackDom();
  const calls = spySaveConfig(win);
  // auto-save is NOT enabled (default false)

  const cliPathField = win.document.getElementById('cli_path');
  cliPathField.value = '/must-not-be-saved';
  cliPathField.focus();

  simulatePanelClose(win);

  assert.equal(calls.length, 0, "visibilitychange must not trigger save when auto-save is disabled");
});

// ---------------------------------------------------------------------------
// Case 2c: Non-auto-save IDE — select change saved on OK click (fallback)
// ---------------------------------------------------------------------------

test("fallback: non-auto-save IDE: getAndSaveIdeConfig captures focused select value (cli_release_channel)", async () => {
  const win = await buildFallbackDom();
  const calls = spySaveConfig(win);

  const sel = win.document.getElementById('cli_release_channel');
  assert.ok(sel, "cli_release_channel select must exist in fallback form");

  // Fixture default is 'stable'. Set to 'rc' without firing change — simulates JCEF dropdown.
  assert.equal(sel.value, 'stable', "fixture must start with stable so the change is detectable");
  sel.value = 'rc';
  sel.focus();

  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must have been called");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.cli_release_channel, 'rc', "saved payload must reflect the selected release channel");
});

test("fallback: auto-save IDE: visibilitychange saves focused select value (cli_release_channel)", async () => {
  const win = await buildFallbackDom();
  const calls = enableAutoSave(win);

  const sel = win.document.getElementById('cli_release_channel');
  assert.ok(sel, "cli_release_channel select must exist in fallback form");

  assert.equal(sel.value, 'stable', "fixture must start with stable so the change is detectable");
  sel.value = 'rc';
  sel.focus();

  simulatePanelClose(win);

  assert.ok(calls.length > 0, "save must have been called on panel close");
  const saved = JSON.parse(calls[calls.length - 1]);
  assert.equal(saved.cli_release_channel, 'rc', "saved payload must reflect the selected release channel");
});

// ---------------------------------------------------------------------------
// Guard: no double-save when blur triggers re-entrance (fallback path)
// ---------------------------------------------------------------------------

test("fallback: auto-save IDE: re-entrance guard prevents double save on visibilitychange", async () => {
  const win = await buildFallbackDom();
  const calls = enableAutoSave(win);

  const cliPathField = win.document.getElementById('cli_path');
  cliPathField.value = '/deduped-path';
  cliPathField.focus();

  simulatePanelClose(win);

  const matchingCalls = calls.filter(function(jsonStr) {
    try {
      return JSON.parse(jsonStr).cli_path === '/deduped-path';
    } catch (e) {
      return false;
    }
  });
  assert.equal(matchingCalls.length, 1, "typed value must be saved exactly once — guard must prevent double-save but not suppress the save");
});
