// ABOUTME: Unit tests for the project-default-propagator module.
// ABOUTME: Tests that propagateProjectDefaults walks folder panes and overwrites
// ABOUTME: non-overridden inputs with new PD values after a successful save.

import assert from "node:assert/strict";
import test from "node:test";
import { JSDOM } from "jsdom";

// ---------------------------------------------------------------------------
// Minimal DOM factory — builds an isolated JSDOM per test so tests are clean.
// Does NOT use the full config-page fixture; just the DOM nodes we care about.
// ---------------------------------------------------------------------------

/**
 * Build a minimal window that contains:
 *   - #fallbacks-pane  (Project Defaults scope)
 *   - one or more .folder-pane divs (folder scope)
 * and loads project-default-propagator.js into it.
 *
 * @param {string} html - Body HTML to inject.
 * @returns {Promise<Window>}
 */
async function buildPropagatorDom(html) {
  const { readFile } = await import("node:fs/promises");
  const { dirname, join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const scriptSrc = await readFile(
    join(__dirname, "../infrastructure/configuration/template/js/features/project-default-propagator.js"),
    "utf8"
  );

  const fullHtml = `<!DOCTYPE html><html><body>${html}</body></html>`;
  const dom = new JSDOM(fullHtml, { runScripts: "dangerously" });
  const win = dom.window;

  // Inject the script
  const scriptEl = win.document.createElement("script");
  scriptEl.textContent = scriptSrc;
  win.document.head.appendChild(scriptEl);

  return win;
}

// ---------------------------------------------------------------------------
// UNIT-001: propagate walks folder panes and overwrites a non-overridden input
// ---------------------------------------------------------------------------
test("UNIT-001: propagates new PD value into non-overridden folder input", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="checkbox" name="snyk_oss_enabled" checked>
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <input type="checkbox" name="folder_0_snyk_oss_enabled" data-setting="snyk_oss_enabled">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { snyk_oss_enabled: true };
  const originalPdValues = { snyk_oss_enabled: false };

  // Folder input starts unchecked (matches old PD value false)
  const folderInput = win.document.querySelector('.folder-pane [data-setting="snyk_oss_enabled"]');
  assert.equal(folderInput.checked, false, "precondition: folder starts with old PD value");

  propagator.propagate(changedData, originalPdValues);

  // After propagation, folder should match new PD value
  assert.equal(folderInput.checked, true, "folder input should be updated to new PD value");
});

// ---------------------------------------------------------------------------
// UNIT-002: PR #1185 regression guard — discovery via data-setting, NOT name parsing
// ---------------------------------------------------------------------------
test("UNIT-002: uses data-setting for discovery, not name attribute parsing", async () => {
  // data-setting differs from the name suffix — propagator must follow data-setting
  const html = `
    <div id="fallbacks-pane">
      <input type="text" name="organization" value="new-org">
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <!-- name suffix would be "organization" but we test with a different-looking name
             to prove the propagator is NOT parsing the name attribute -->
        <input type="text" name="folder_0_organization" data-setting="organization" value="old-org">
      </div>
    </div>
    <div class="folder-pane" id="folder-pane-1">
      <div class="override-indicator-wrapper">
        <!-- This input has data-setting="organization" but an unusual name to trip name-based logic -->
        <input type="text" name="folder_1_organization_alias" data-setting="organization" value="old-org">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const pdInput = win.document.querySelector('#fallbacks-pane [name="organization"]');
  pdInput.value = "new-org";

  const changedData = { organization: "new-org" };
  const originalPdValues = { organization: "old-org" };

  propagator.propagate(changedData, originalPdValues);

  // Both folder inputs matched via data-setting, regardless of their name attribute
  const folder0Input = win.document.querySelector('#folder-pane-0 [data-setting="organization"]');
  const folder1Input = win.document.querySelector('#folder-pane-1 [data-setting="organization"]');

  assert.equal(folder0Input.value, "new-org", "folder-0 updated via data-setting");
  assert.equal(folder1Input.value, "new-org", "folder-1 updated via data-setting even with unusual name");
});

// ---------------------------------------------------------------------------
// UNIT-003: all input type branches (checkbox, select, text/number) propagate correctly
// ---------------------------------------------------------------------------
test("UNIT-003: propagates checkbox correctly", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="checkbox" name="severity_filter_high" checked>
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <input type="checkbox" name="folder_0_severity_filter_high" data-setting="severity_filter_high">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { severity_filter_high: true };
  const originalPdValues = { severity_filter_high: false };

  propagator.propagate(changedData, originalPdValues);

  const folderInput = win.document.querySelector('.folder-pane [data-setting="severity_filter_high"]');
  assert.equal(folderInput.checked, true, "checkbox propagated correctly");
});

test("UNIT-003: propagates select correctly", async () => {
  const html = `
    <div id="fallbacks-pane">
      <select name="scan_automatic">
        <option value="true">Auto</option>
        <option value="false" selected>Manual</option>
      </select>
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <select name="folder_0_scan_automatic" data-setting="scan_automatic">
          <option value="true" selected>Auto</option>
          <option value="false">Manual</option>
        </select>
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  // PD is now "false" (Manual), folder was "true" (Auto) — folder matches old PD "true"
  const changedData = { scan_automatic: "false" };
  const originalPdValues = { scan_automatic: "true" };

  propagator.propagate(changedData, originalPdValues);

  const folderSelect = win.document.querySelector('.folder-pane [data-setting="scan_automatic"]');
  assert.equal(folderSelect.value, "false", "select propagated correctly");
});

test("UNIT-003: propagates text input correctly", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="text" name="organization" value="new-org-uuid">
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <input type="text" name="folder_0_organization" data-setting="organization" value="old-org-uuid">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { organization: "new-org-uuid" };
  const originalPdValues = { organization: "old-org-uuid" };

  propagator.propagate(changedData, originalPdValues);

  const folderInput = win.document.querySelector('.folder-pane [data-setting="organization"]');
  assert.equal(folderInput.value, "new-org-uuid", "text input propagated correctly");
});

test("UNIT-003: propagates number input correctly", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="number" name="risk_score_threshold" value="500">
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <input type="number" name="folder_0_risk_score_threshold" data-setting="risk_score_threshold" value="200">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { risk_score_threshold: "500" };
  const originalPdValues = { risk_score_threshold: "200" };

  propagator.propagate(changedData, originalPdValues);

  const folderInput = win.document.querySelector('.folder-pane [data-setting="risk_score_threshold"]');
  assert.equal(folderInput.value, "500", "number input propagated correctly");
});

// ---------------------------------------------------------------------------
// UNIT-004: folder input with user override (value !== old PD) is skipped
// ---------------------------------------------------------------------------
test("UNIT-004: skips folder input that has a user override (value differs from old PD)", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="text" name="organization" value="new-org">
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <!-- This folder has a user-set value "user-override-org" — different from old PD -->
        <input type="text" name="folder_0_organization" data-setting="organization" value="user-override-org">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { organization: "new-org" };
  const originalPdValues = { organization: "old-org" };

  propagator.propagate(changedData, originalPdValues);

  const folderInput = win.document.querySelector('.folder-pane [data-setting="organization"]');
  // Must NOT be overwritten — it had a user override
  assert.equal(folderInput.value, "user-override-org", "user-overridden folder value must not be changed");
});

// ---------------------------------------------------------------------------
// UNIT-005: source-org and source-org-locked wrappers are never overwritten
// ---------------------------------------------------------------------------
test("UNIT-005: skips folder input whose wrapper has source-org class", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="checkbox" name="snyk_oss_enabled" checked>
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper source-org">
        <input type="checkbox" name="folder_0_snyk_oss_enabled" data-setting="snyk_oss_enabled">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { snyk_oss_enabled: true };
  const originalPdValues = { snyk_oss_enabled: false };

  propagator.propagate(changedData, originalPdValues);

  const folderInput = win.document.querySelector('.folder-pane [data-setting="snyk_oss_enabled"]');
  // Still unchecked — org-managed, must not be changed
  assert.equal(folderInput.checked, false, "source-org folder must not be overwritten");
});

test("UNIT-005: skips folder input whose wrapper has source-org-locked class", async () => {
  const html = `
    <div id="fallbacks-pane">
      <input type="checkbox" name="snyk_code_enabled" checked>
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper source-org-locked">
        <input type="checkbox" name="folder_0_snyk_code_enabled" data-setting="snyk_code_enabled">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { snyk_code_enabled: true };
  const originalPdValues = { snyk_code_enabled: false };

  propagator.propagate(changedData, originalPdValues);

  const folderInput = win.document.querySelector('.folder-pane [data-setting="snyk_code_enabled"]');
  assert.equal(folderInput.checked, false, "source-org-locked folder must not be overwritten");
});

// ---------------------------------------------------------------------------
// UNIT-006: changedData key with no matching PD input is silently ignored
// ---------------------------------------------------------------------------
test("UNIT-006: key with no matching #fallbacks-pane input is ignored, no error", async () => {
  const html = `
    <div id="fallbacks-pane">
      <!-- no input for "ghost_setting" -->
    </div>
    <div class="folder-pane" id="folder-pane-0">
      <div class="override-indicator-wrapper">
        <input type="text" name="folder_0_ghost_setting" data-setting="ghost_setting" value="old">
      </div>
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  const changedData = { ghost_setting: "new-value" };
  const originalPdValues = { ghost_setting: "old" };

  // Must not throw
  assert.doesNotThrow(() => {
    propagator.propagate(changedData, originalPdValues);
  });

  // Folder input untouched
  const folderInput = win.document.querySelector('.folder-pane [data-setting="ghost_setting"]');
  assert.equal(folderInput.value, "old", "folder input must not be changed when PD input absent");
});

// ---------------------------------------------------------------------------
// UNIT-006b: folderConfigs and trusted_folders keys are skipped
// ---------------------------------------------------------------------------
test("UNIT-006b: folderConfigs and trusted_folders keys are skipped", async () => {
  const html = `
    <div id="fallbacks-pane">
    </div>
    <div class="folder-pane" id="folder-pane-0">
    </div>
  `;
  const win = await buildPropagatorDom(html);
  const propagator = win.ConfigApp.projectDefaultPropagator;

  // Should not throw even when these special keys are in changedData
  assert.doesNotThrow(() => {
    propagator.propagate(
      { folderConfigs: [{}], trusted_folders: ["/some/path"] },
      { folderConfigs: [], trusted_folders: [] }
    );
  });
});
