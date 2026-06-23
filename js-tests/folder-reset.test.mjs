// ABOUTME: Tests for the per-folder reset flag-leak bug fix (IDE-2149 per-folder analog).
// ABOUTME: Mirrors global-reset.test.mjs for per-folder behavior:
// ABOUTME:   - markFolderForReset / isFolderMarkedForReset toggles the per-folder flag
// ABOUTME:   - applyFolderResets(data) sets all org-scope fields to null for marked folders
// ABOUTME:   - validation-failure path clears folderResets so it cannot leak into a later save

import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// The org-scope per-folder fields cleared by a folder reset. Mirrors the list
// inside formHandler.applyFolderResets in form-handler.js.
var FOLDER_RESET_FIELDS = [
	"scan_automatic",
	"scan_net_new",
	"severity_filter_critical",
	"severity_filter_high",
	"severity_filter_medium",
	"severity_filter_low",
	"snyk_oss_enabled",
	"snyk_code_enabled",
	"snyk_iac_enabled",
	"snyk_secrets_enabled",
	"issue_view_open_issues",
	"issue_view_ignored_issues",
	"risk_score_threshold",
];

// ---------------------------------------------------------------------------
// markFolderForReset / isFolderMarkedForReset
// ---------------------------------------------------------------------------

test("markFolderForReset/isFolderMarkedForReset: toggles the per-folder reset flag", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	assert.equal(fh.isFolderMarkedForReset(0), false, "flag must start cleared");

	fh.markFolderForReset(0);
	assert.equal(fh.isFolderMarkedForReset(0), true, "flag must be set after markFolderForReset");

	// Other indexes must remain unaffected.
	assert.equal(fh.isFolderMarkedForReset(1), false, "flag for index 1 must remain cleared");
});

// ---------------------------------------------------------------------------
// applyFolderResets(data)
// ---------------------------------------------------------------------------

test("applyFolderResets: no-op when no folder is marked", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	var data = {
		folderConfigs: [
			{ folderPath: "/keep-me", snyk_oss_enabled: true, scan_automatic: "true" }
		]
	};
	fh.applyFolderResets(data);

	assert.equal(data.folderConfigs[0].snyk_oss_enabled, true, "unmarked reset must not touch data");
	assert.equal(data.folderConfigs[0].scan_automatic, "true", "unmarked reset must not touch data");
});

test("applyFolderResets: sets all org-scope fields to null (flag cleared by getAndSaveIdeConfig finally)", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	fh.markFolderForReset(0);
	var data = {
		folderConfigs: [
			{ folderPath: "/test", snyk_oss_enabled: true, scan_automatic: "true" }
		]
	};

	fh.applyFolderResets(data);

	for (var i = 0; i < FOLDER_RESET_FIELDS.length; i++) {
		var key = FOLDER_RESET_FIELDS[i];
		assert.equal(data.folderConfigs[0][key], null, key + " must be null after folder reset");
	}

	// Flag clearing is now centralized in getAndSaveIdeConfig's finally block, not in
	// applyFolderResets directly. When called standalone (as in this unit test),
	// the flag remains set until getAndSaveIdeConfig's finally clears it.
	assert.equal(fh.isFolderMarkedForReset(0), true, "flag still set — cleared by getAndSaveIdeConfig finally, not applyFolderResets directly");
});

test("applyFolderResets: only resets marked folder, not other folders", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	fh.markFolderForReset(0);
	var data = {
		folderConfigs: [
			{ folderPath: "/folder0", snyk_oss_enabled: true },
			{ folderPath: "/folder1", snyk_oss_enabled: true }
		]
	};

	fh.applyFolderResets(data);

	assert.equal(data.folderConfigs[0].snyk_oss_enabled, null, "marked folder must be reset");
	assert.equal(data.folderConfigs[1].snyk_oss_enabled, true, "unmarked folder must not be touched");
});

// ---------------------------------------------------------------------------
// Bug fix: validation-failure path must clear folderResets, not carry it forward.
// A folder-reset intent is tied to its own immediate save attempt only.
// If that save is blocked (validation error), the marks must NOT survive to
// leak into any later unrelated save.
// ---------------------------------------------------------------------------

test("folder reset marks are cleared when save is blocked by validation error (does not leak into later save)", async function() {
	// Correct behavior:
	//   1. Folder reset button clicked -> markFolderForReset(i) sets the mark.
	//   2. getAndSaveIdeConfig() detects invalid form and returns early.
	//      It must clear window.ConfigApp.folderResets before returning so the
	//      marks cannot silently propagate into a later, unrelated save.
	//   3. A subsequent valid save (of an unrelated field) must NOT inject
	//      org-scope nulls for the previously marked folder.
	//   4. The user must click "Reset overrides" again to re-trigger the reset.
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	var saveCalls = [];
	win.__saveIdeConfig__ = function(jsonString) {
		saveCalls.push(jsonString);
	};

	// Inject an invalid validation state so getAndSaveIdeConfig() returns early.
	var origGetFormValidationInfo = win.ConfigApp.validation.getFormValidationInfo;
	win.ConfigApp.validation.getFormValidationInfo = function() {
		return { isValid: false, validationState: { api_endpoint: false } };
	};

	// Mark folder 0 for reset and immediately attempt to save (as reset-handler does).
	fh.markFolderForReset(0);
	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	// The save was blocked -- __saveIdeConfig__ must not have been called.
	assert.equal(saveCalls.length, 0, "save must not fire when form is invalid");

	// CRITICAL: the folder reset marks must be cleared after the blocked save --
	// the reset intent must not survive to leak into the next unrelated save.
	assert.equal(
		fh.isFolderMarkedForReset(0),
		false,
		"folder reset flag must be cleared after a blocked (invalid) save to prevent leaking into a later save"
	);

	// Restore valid validation so the next save goes through.
	win.ConfigApp.validation.getFormValidationInfo = origGetFormValidationInfo;

	// Trigger an unrelated, valid save (e.g. user fixed the validation error
	// and saved something else -- not a reset).
	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	// The save must have fired.
	assert.ok(saveCalls.length > 0, "unrelated valid save must fire once the form is valid");

	// The unrelated save payload must NOT contain folder-reset nulls.
	var saved = JSON.parse(saveCalls[saveCalls.length - 1]);
	if (saved.folderConfigs) {
		for (var fi = 0; fi < saved.folderConfigs.length; fi++) {
			var fc = saved.folderConfigs[fi];
			for (var i = 0; i < FOLDER_RESET_FIELDS.length; i++) {
				var key = FOLDER_RESET_FIELDS[i];
				if (Object.prototype.hasOwnProperty.call(fc, key)) {
					assert.notEqual(
						fc[key],
						null,
						key + " must NOT be null in folder " + fi + " of an unrelated save -- folder reset must not leak into a later save"
					);
				}
			}
		}
	}
});

// ---------------------------------------------------------------------------
// Exception path (finally): marks cleared when save throws mid-way (unique to finally approach)
// ---------------------------------------------------------------------------

test("global and folder reset marks are cleared when saveConfig throws (exception path, finally guarantees)", async function() {
	// This test UNIQUELY validates the finally-based clear: arm both reset marks,
	// make ideBridge.saveConfig throw, and assert marks are cleared even on exception.
	// A point-clear approach (clears only at early-return sites) would FAIL this test
	// because the exception bypasses all early-return clear sites.
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	var saveCalls = [];
	win.__saveIdeConfig__ = function(jsonString) {
		saveCalls.push(jsonString);
		throw new Error("simulated saveConfig failure");
	};

	// Arm both global and folder reset marks.
	fh.markGlobalForReset();
	fh.markFolderForReset(0);

	// getAndSaveIdeConfig will call saveConfig which throws. With point-clears the
	// marks survive the exception. With finally-based clear they are always cleared.
	var threw = false;
	try {
		win.ConfigApp.autoSave.getAndSaveIdeConfig();
	} catch (e) {
		threw = true;
	}
	// The exception is internal (caught by the try/finally in getAndSaveIdeConfig itself);
	// it should not propagate to the caller.
	assert.equal(threw, false, "getAndSaveIdeConfig must not propagate internal exceptions to the caller");

	// saveConfig was called (form was valid, we got past all guards).
	assert.equal(saveCalls.length, 1, "saveConfig must have been called once");

	// CRITICAL: both marks must be cleared even though saveConfig threw.
	assert.equal(
		fh.isGlobalMarkedForReset(),
		false,
		"global reset flag must be cleared even when saveConfig throws (finally clears)"
	);
	assert.equal(
		fh.isFolderMarkedForReset(0),
		false,
		"folder reset flag must be cleared even when saveConfig throws (finally clears)"
	);

	// A subsequent valid save must not replay the nulls.
	var subsequentCalls = [];
	win.__saveIdeConfig__ = function(jsonString) {
		subsequentCalls.push(jsonString);
	};
	win.ConfigApp.autoSave.getAndSaveIdeConfig();
	assert.ok(subsequentCalls.length > 0, "subsequent save must fire");

	var saved = JSON.parse(subsequentCalls[0]);
	// Global reset fields must NOT be null in an unrelated subsequent save.
	var GLOBAL_RESET_FIELDS = [
		"snyk_oss_enabled", "snyk_code_enabled", "snyk_iac_enabled", "snyk_secrets_enabled",
		"scan_automatic", "scan_net_new", "severity_filter_critical", "severity_filter_high",
		"severity_filter_medium", "severity_filter_low", "issue_view_open_issues",
		"issue_view_ignored_issues", "risk_score_threshold", "organization"
	];
	for (var i = 0; i < GLOBAL_RESET_FIELDS.length; i++) {
		var key = GLOBAL_RESET_FIELDS[i];
		if (Object.prototype.hasOwnProperty.call(saved, key)) {
			assert.notEqual(saved[key], null, key + " must NOT be null in subsequent unrelated save");
		}
	}
	// Folder reset fields must NOT be null in an unrelated subsequent save.
	if (saved.folderConfigs) {
		for (var fi = 0; fi < saved.folderConfigs.length; fi++) {
			var fc = saved.folderConfigs[fi];
			for (var j = 0; j < FOLDER_RESET_FIELDS.length; j++) {
				var fkey = FOLDER_RESET_FIELDS[j];
				if (Object.prototype.hasOwnProperty.call(fc, fkey)) {
					assert.notEqual(fc[fkey], null, fkey + " must NOT be null in folder " + fi + " of subsequent unrelated save");
				}
			}
		}
	}
});

// ---------------------------------------------------------------------------
// collectData-guard path: folderResets must also be cleared when collectData fails
// ---------------------------------------------------------------------------

test("folder reset marks are cleared when save is blocked by missing collectData (does not leak into later save)", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	var saveCalls = [];
	win.__saveIdeConfig__ = function(jsonString) {
		saveCalls.push(jsonString);
	};

	// Remove collectChangedData to trigger the second early-return path.
	var origCollectChangedData = win.ConfigApp.formHandler.collectChangedData;
	win.ConfigApp.formHandler.collectChangedData = null;

	// Mark folder 0 for reset and attempt to save.
	fh.markFolderForReset(0);
	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	// Save must be blocked.
	assert.equal(saveCalls.length, 0, "save must not fire when collectChangedData is missing");

	// Folder marks must be cleared.
	assert.equal(
		fh.isFolderMarkedForReset(0),
		false,
		"folder reset flag must be cleared after a blocked (missing handler) save"
	);

	// Restore and do a normal save -- must not inject nulls.
	win.ConfigApp.formHandler.collectChangedData = origCollectChangedData;
	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	assert.ok(saveCalls.length > 0, "valid save must fire after handler is restored");

	var saved = JSON.parse(saveCalls[saveCalls.length - 1]);
	if (saved.folderConfigs) {
		for (var fi = 0; fi < saved.folderConfigs.length; fi++) {
			var fc = saved.folderConfigs[fi];
			for (var i = 0; i < FOLDER_RESET_FIELDS.length; i++) {
				var key = FOLDER_RESET_FIELDS[i];
				if (Object.prototype.hasOwnProperty.call(fc, key)) {
					assert.notEqual(
						fc[key],
						null,
						key + " must NOT be null in folder " + fi + " after handler restore -- folder reset must not leak"
					);
				}
			}
		}
	}
});
