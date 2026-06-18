// ABOUTME: Integration tests for auto-save + project-default-propagator wiring.
// ABOUTME: Verifies that after a successful save, folder values that were
// ABOUTME: inheriting from Project Defaults are updated and the dirty tracker
// ABOUTME: considers the form clean.

import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a fully-initialized JSDOM environment from the production HTML fixture
 * with the project-default-propagator.js script also injected.
 * The fixture already contains folder panes (generated with -dummy-data).
 */
async function buildDomWithPropagator({
  initialToken = "",
  initialAuthMethod = "oauth",
  initialEndpoint = "https://api.snyk.io",
} = {}) {
  const html = await readFile(join(__dirname, "fixtures", "config-page.html"), "utf8");
  const propagatorSrc = await readFile(
    join(__dirname, "../infrastructure/configuration/template/js/features/project-default-propagator.js"),
    "utf8"
  );

  // Inject the propagator script just before </body>
  const htmlWithPropagator = html.replace("</body>", `<script>${propagatorSrc}</script></body>`);

  const dom = new JSDOM(htmlWithPropagator, { runScripts: "dangerously" });
  const win = dom.window;

  win.document.getElementById("token").value = initialToken;
  win.document.getElementById("authentication_method").value = initialAuthMethod;
  win.document.getElementById("api_endpoint").value = initialEndpoint;

  // Yield to fire the window load event (initializes dirtyTracker etc.)
  await new Promise((resolve) => win.setTimeout(resolve, 0));

  return win;
}

/**
 * Install a __saveIdeConfig__ spy that returns true (success).
 */
function spySaveConfigSuccess(win) {
  const calls = [];
  win.__saveIdeConfig__ = function (jsonString) {
    calls.push(jsonString);
    return true;
  };
  return calls;
}

/**
 * Filter NodeList to only those inputs whose closest .override-indicator-wrapper
 * does NOT carry source-org or source-org-locked — i.e. inputs that the propagator
 * is allowed to update.
 */
function propagatableInputs(nodeList) {
  return Array.from(nodeList).filter((el) => {
    const wrapper = el.closest(".override-indicator-wrapper");
    if (!wrapper) return true;
    return !wrapper.classList.contains("source-org") &&
           !wrapper.classList.contains("source-org-locked");
  });
}

// ---------------------------------------------------------------------------
// INTEG-001: Full path — PD + folder panes, propagatable folder values updated
// ---------------------------------------------------------------------------

test("INTEG-001: after successful save, propagatable folder values are updated and dirtyTracker is clean", async () => {
  const win = await buildDomWithPropagator();
  const calls = spySaveConfigSuccess(win);

  // Find a PD input and its corresponding folder inputs
  const pdInput = win.document.querySelector('#fallbacks-pane [name="snyk_oss_enabled"]');
  assert.ok(pdInput, "snyk_oss_enabled PD input must exist in fixture");

  const allFolderInputs = win.document.querySelectorAll('.folder-pane [data-setting="snyk_oss_enabled"]');
  assert.ok(allFolderInputs.length > 0, "at least one folder input for snyk_oss_enabled must exist");

  // Propagatable = inputs without source-org or source-org-locked wrapper
  const propInputs = propagatableInputs(allFolderInputs);
  assert.ok(propInputs.length > 0, "at least one propagatable folder input must exist");

  // Set propagatable folder inputs to match current PD value (non-overridden state)
  const pdCurrentValue = pdInput.checked;
  for (const fi of propInputs) {
    fi.checked = pdCurrentValue;
  }

  // Re-initialize dirty tracker baseline to capture this state
  win.dirtyTracker.reset();
  assert.equal(win.dirtyTracker.isDirty, false, "precondition: form must be clean before test");

  // Change the PD value
  const newPdValue = !pdCurrentValue;
  pdInput.checked = newPdValue;
  pdInput.dispatchEvent(new win.Event("change", { bubbles: true }));

  // Trigger save
  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must have been called");

  // After save, propagatable folder inputs should have been updated to new PD value
  for (const fi of propInputs) {
    assert.equal(fi.checked, newPdValue,
      `propagatable folder input for snyk_oss_enabled should be updated to ${newPdValue}`);
  }

  // And the dirty tracker should be clean (propagation ran before reset)
  assert.equal(win.dirtyTracker.isDirty, false,
    "dirty tracker must be clean after save + propagation");
});

// ---------------------------------------------------------------------------
// INTEG-002: Severity-filter regression — severity_filter_high propagates correctly
// ---------------------------------------------------------------------------

test("INTEG-002: severity_filter_high change propagates to folder pane correctly", async () => {
  const win = await buildDomWithPropagator();
  const calls = spySaveConfigSuccess(win);

  // Get PD severity_filter_high input
  const pdHighInput = win.document.querySelector('#fallbacks-pane [name="severity_filter_high"]');
  assert.ok(pdHighInput, "severity_filter_high PD input must exist in fixture");

  // Get folder severity_filter_high inputs
  const allFolderHighInputs = win.document.querySelectorAll('.folder-pane [data-setting="severity_filter_high"]');
  assert.ok(allFolderHighInputs.length > 0, "at least one folder severity_filter_high input must exist");

  // Propagatable inputs only (not org-managed)
  const propHighInputs = propagatableInputs(allFolderHighInputs);
  assert.ok(propHighInputs.length > 0, "at least one propagatable folder severity_filter_high input must exist");

  // Also get folder severity_filter_critical to verify it is NOT affected
  const folderCriticalInputs = win.document.querySelectorAll('.folder-pane [data-setting="severity_filter_critical"]');

  // Set propagatable folder high inputs to match current PD value (non-overridden state)
  const pdHighValue = pdHighInput.checked;
  for (const fi of propHighInputs) {
    fi.checked = pdHighValue;
  }

  // Record critical value before save (should not change)
  const criticalValuesBefore = Array.from(folderCriticalInputs).map((fi) => fi.checked);

  // Reset baseline
  win.dirtyTracker.reset();

  // Change PD severity_filter_high
  const newHighValue = !pdHighValue;
  pdHighInput.checked = newHighValue;
  pdHighInput.dispatchEvent(new win.Event("change", { bubbles: true }));

  // Trigger save
  win.getAndSaveIdeConfig();

  assert.ok(calls.length > 0, "save must have been called");

  // Propagatable folder severity_filter_high inputs should be updated
  for (const fi of propHighInputs) {
    assert.equal(fi.checked, newHighValue,
      "propagatable folder severity_filter_high must be propagated");
  }

  // Folder severity_filter_critical must NOT be changed
  const criticalValuesAfter = Array.from(folderCriticalInputs).map((fi) => fi.checked);
  assert.deepEqual(criticalValuesAfter, criticalValuesBefore,
    "severity_filter_critical must not be affected by severity_filter_high change");

  // Form clean
  assert.equal(win.dirtyTracker.isDirty, false, "dirty tracker must be clean after propagation");
});
