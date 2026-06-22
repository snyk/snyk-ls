// ABOUTME: Tests for the global ("Project Defaults") reset on the HTML settings page.
// ABOUTME: Covers markGlobalForReset/isGlobalMarkedForReset, applyGlobalResets(data)
// ABOUTME: writing 14 top-level nulls, and a DOM-driven click producing those nulls in the save payload.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// The 14 org-scope global fields cleared by a global reset. Mirrors
// GLOBAL_RESET_FIELDS in form-handler.js and types.GlobalResettableSettings (Go).
var GLOBAL_RESET_FIELDS = [
	"snyk_oss_enabled",
	"snyk_code_enabled",
	"snyk_iac_enabled",
	"snyk_secrets_enabled",
	"scan_automatic",
	"scan_net_new",
	"severity_filter_critical",
	"severity_filter_high",
	"severity_filter_medium",
	"severity_filter_low",
	"issue_view_open_issues",
	"issue_view_ignored_issues",
	"risk_score_threshold",
	"organization",
];

// ---------------------------------------------------------------------------
// markGlobalForReset / isGlobalMarkedForReset
// ---------------------------------------------------------------------------

test("markGlobalForReset/isGlobalMarkedForReset: toggles the global reset flag", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	assert.equal(fh.isGlobalMarkedForReset(), false, "flag must start cleared");

	fh.markGlobalForReset();
	assert.equal(fh.isGlobalMarkedForReset(), true, "flag must be set after markGlobalForReset");
});

// ---------------------------------------------------------------------------
// applyGlobalResets(data)
// ---------------------------------------------------------------------------

test("applyGlobalResets: no-op when not marked", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	const data = { organization: "keep-me", snyk_code_enabled: true };
	fh.applyGlobalResets(data);

	assert.equal(data.organization, "keep-me", "unmarked reset must not touch data");
	assert.equal(data.snyk_code_enabled, true, "unmarked reset must not touch data");
});

test("applyGlobalResets: sets all 14 fields to null at top level and clears the flag", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	const data = { folderConfigs: [{ folder_path: "/x", organization: "folder-org" }] };
	fh.markGlobalForReset();
	fh.applyGlobalResets(data);

	for (var i = 0; i < GLOBAL_RESET_FIELDS.length; i++) {
		var key = GLOBAL_RESET_FIELDS[i];
		assert.ok(Object.prototype.hasOwnProperty.call(data, key), key + " must be present at top level");
		assert.equal(data[key], null, key + " must be null at top level");
	}

	// Resets must NOT be written inside folderConfigs.
	assert.equal(data.folderConfigs[0].organization, "folder-org", "folderConfigs must be untouched");
	assert.equal(
		Object.prototype.hasOwnProperty.call(data.folderConfigs[0], "snyk_code_enabled"),
		false,
		"global reset must not write into folderConfigs"
	);

	assert.equal(fh.isGlobalMarkedForReset(), false, "flag must be cleared after applyGlobalResets");
});

// ---------------------------------------------------------------------------
// DOM-driven: clicking the button produces 14 top-level nulls in the save payload
// ---------------------------------------------------------------------------

test("clicking .reset-global-overrides-btn saves 14 top-level nulls immediately (no confirm dialog)", async () => {
	const win = await buildDom();

	// Spy on the IDE save bridge.
	var calls = [];
	win.__saveIdeConfig__ = function (jsonString) {
		calls.push(jsonString);
	};

	const btn = win.document.querySelector(".reset-global-overrides-btn");
	assert.ok(btn, ".reset-global-overrides-btn must exist in the fixture");

	// After the fix (item 4): the click itself triggers the save immediately —
	// no confirm() dialog and no manual getAndSaveIdeConfig() call needed.
	btn.click();

	assert.ok(calls.length > 0, "save must have been called immediately on click");
	const saved = JSON.parse(calls[calls.length - 1]);

	for (var i = 0; i < GLOBAL_RESET_FIELDS.length; i++) {
		var key = GLOBAL_RESET_FIELDS[i];
		assert.ok(Object.prototype.hasOwnProperty.call(saved, key), key + " must be present in saved payload");
		assert.equal(saved[key], null, key + " must be null in saved payload");
	}

	// Resets live at the top level, never inside folderConfigs.
	if (saved.folderConfigs) {
		for (var f = 0; f < saved.folderConfigs.length; f++) {
			assert.equal(
				Object.prototype.hasOwnProperty.call(saved.folderConfigs[f], "snyk_code_enabled") &&
					saved.folderConfigs[f].snyk_code_enabled === null,
				false,
				"global reset null must not leak into folderConfigs"
			);
		}
	}
});

// ---------------------------------------------------------------------------
// Item 6b: Go ↔ JS sync test — GLOBAL_RESET_FIELDS matches GlobalResettableSettings
// ---------------------------------------------------------------------------

test("GLOBAL_RESET_FIELDS matches Go GlobalResettableSettings string values", () => {
	const __dirname = dirname(fileURLToPath(import.meta.url));
	const root = resolve(__dirname, "..");

	// Read both Go source files that contain the relevant constants.
	const writersSource = readFileSync(
		resolve(root, "internal/types/config_writers.go"),
		"utf8"
	);
	const ldxSource = readFileSync(
		resolve(root, "internal/types/ldx_sync_config.go"),
		"utf8"
	);
	const combined = writersSource + "\n" + ldxSource;

	// Extract the GlobalResettableSettings slice body.
	const blockMatch = writersSource.match(
		/GlobalResettableSettings\s*=\s*\[\]string\{([^}]+)\}/s
	);
	assert.ok(blockMatch, "GlobalResettableSettings must be present in config_writers.go");

	// Collect all Setting* constant names referenced inside the slice.
	const constNames = blockMatch[1].match(/Setting\w+/g) || [];
	assert.ok(constNames.length > 0, "GlobalResettableSettings must have entries");

	// Resolve each constant name to its string value from the combined source.
	const goValues = constNames.map((name) => {
		const m = combined.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]+)"`));
		return m ? m[1] : null;
	});

	const unresolved = constNames.filter((_, i) => goValues[i] === null);
	assert.equal(
		unresolved.length,
		0,
		"could not resolve Go constants to string values: " + unresolved.join(", ")
	);

	const resolvedGoValues = goValues.filter(Boolean);

	// Read the PRODUCTION form-handler.js and parse out its GLOBAL_RESET_FIELDS
	// array. This is the authoritative JS source — NOT the local test-file copy.
	const formHandlerSource = readFileSync(
		resolve(root, "infrastructure/configuration/template/js/ui/form-handler.js"),
		"utf8"
	);
	const jsBlockMatch = formHandlerSource.match(
		/var\s+GLOBAL_RESET_FIELDS\s*=\s*\[([^\]]+)\]/s
	);
	assert.ok(
		jsBlockMatch,
		"GLOBAL_RESET_FIELDS must be present in infrastructure/configuration/template/js/ui/form-handler.js"
	);
	const productionJsFields = (jsBlockMatch[1].match(/"([^"]+)"/g) || []).map((s) =>
		s.replace(/"/g, "")
	);
	assert.ok(
		productionJsFields.length > 0,
		"GLOBAL_RESET_FIELDS in form-handler.js must have entries"
	);

	assert.deepEqual(
		[...resolvedGoValues].sort(),
		[...productionJsFields].sort(),
		"GLOBAL_RESET_FIELDS in form-handler.js must match Go GlobalResettableSettings string values.\n" +
			"Go has: " + resolvedGoValues.sort().join(", ") + "\n" +
			"JS has: " + [...productionJsFields].sort().join(", ")
	);
});

// ---------------------------------------------------------------------------
// Item 7a: flag lifecycle — reset clicked then a fresh page has flag cleared
// ---------------------------------------------------------------------------

test("global reset flag starts cleared on a fresh window load", async () => {
	// Each buildDom() creates a fresh isolated window — the global reset flag
	// must not carry over between page loads.
	const win1 = await buildDom();
	win1.ConfigApp.formHandler.markGlobalForReset();
	assert.equal(win1.ConfigApp.formHandler.isGlobalMarkedForReset(), true, "flag set in first window");

	// A second isolated window (simulating re-open) must start with flag cleared.
	const win2 = await buildDom();
	assert.equal(
		win2.ConfigApp.formHandler.isGlobalMarkedForReset(),
		false,
		"flag must start cleared on a fresh window load"
	);
});

// ---------------------------------------------------------------------------
// Item 7 gap (3): validation-failure path — flag survives a blocked save
// ---------------------------------------------------------------------------

test("global reset flag persists through a blocked save and applies on the next successful save", async () => {
	// Behavior under test:
	//   1. Reset button clicked → markGlobalForReset() sets the flag, then
	//      getAndSaveIdeConfig() is called immediately.
	//   2. getAndSaveIdeConfig() checks validation first; when the form is
	//      invalid it returns early — BEFORE applyGlobalResets() is reached —
	//      so __saveIdeConfig__ is never called and the flag stays set.
	//   3. On the next call to getAndSaveIdeConfig() when the form is valid,
	//      applyGlobalResets() fires and the 14 nulls reach the IDE bridge.
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	var saveCalls = [];
	win.__saveIdeConfig__ = function (jsonString) {
		saveCalls.push(jsonString);
	};

	// Inject an invalid validation state so getAndSaveIdeConfig() returns early.
	// validation.getFormValidationInfo() iterates validationState; we patch
	// getFormValidationInfo directly to avoid manipulating internal state.
	var origGetFormValidationInfo = win.ConfigApp.validation.getFormValidationInfo;
	win.ConfigApp.validation.getFormValidationInfo = function () {
		return { isValid: false, validationState: { api_endpoint: false } };
	};

	// Simulate the reset-button click path: mark + immediate save attempt.
	fh.markGlobalForReset();
	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	// The save was blocked — __saveIdeConfig__ must not have been called.
	assert.equal(saveCalls.length, 0, "save must not fire when form is invalid");

	// The flag must still be set — the reset must not be silently dropped.
	assert.equal(
		fh.isGlobalMarkedForReset(),
		true,
		"global reset flag must still be set after a blocked (invalid) save"
	);

	// Restore valid validation so the next save goes through.
	win.ConfigApp.validation.getFormValidationInfo = origGetFormValidationInfo;

	// Trigger a normal (valid) save.
	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	// The save must have fired this time.
	assert.ok(saveCalls.length > 0, "save must fire once the form is valid");

	// The saved payload must contain all 14 global-reset nulls.
	var saved = JSON.parse(saveCalls[saveCalls.length - 1]);
	for (var i = 0; i < GLOBAL_RESET_FIELDS.length; i++) {
		var key = GLOBAL_RESET_FIELDS[i];
		assert.ok(
			Object.prototype.hasOwnProperty.call(saved, key),
			key + " must be present in saved payload after deferred reset"
		);
		assert.equal(saved[key], null, key + " must be null in saved payload after deferred reset");
	}

	// The flag must be cleared after the successful save.
	assert.equal(
		fh.isGlobalMarkedForReset(),
		false,
		"global reset flag must be cleared after the successful save"
	);
});

// ---------------------------------------------------------------------------
// Item 7b: coexistence — global reset and folder reset in same payload
// ---------------------------------------------------------------------------

test("global reset and folder reset coexist without interfering", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	// Mark global for reset.
	fh.markGlobalForReset();

	// Mark first folder for reset (index 0).
	fh.markFolderForReset(0);

	const data = {
		folderConfigs: [
			{ folderPath: "/test-folder", snyk_oss_enabled: true },
		],
	};

	fh.applyGlobalResets(data);
	fh.applyFolderResets(data);

	// Global reset writes nulls at top level.
	for (var i = 0; i < GLOBAL_RESET_FIELDS.length; i++) {
		var key = GLOBAL_RESET_FIELDS[i];
		assert.ok(
			Object.prototype.hasOwnProperty.call(data, key),
			key + " must be present at top level from global reset"
		);
		assert.equal(data[key], null, key + " must be null at top level from global reset");
	}

	// After global reset, the global flag is cleared.
	assert.equal(fh.isGlobalMarkedForReset(), false, "global reset flag must be cleared");

	// Folder reset also applied (snyk_oss_enabled set to null in folderConfigs[0]).
	assert.equal(
		data.folderConfigs[0].snyk_oss_enabled,
		null,
		"folder reset must set snyk_oss_enabled to null in folderConfigs[0]"
	);
});
