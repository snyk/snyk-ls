// ABOUTME: Tests for the per-folder reset flag-leak bug fix (IDE-2149 per-folder analog).
// ABOUTME: Mirrors global-reset.test.mjs for per-folder behavior:
// ABOUTME:   - markFolderForReset / isFolderMarkedForReset toggles the per-folder flag
// ABOUTME:   - applyFolderResets(data) sets all org-scope fields to null for marked folders
// ABOUTME:   - validation-failure path clears folderResetPaths so it cannot leak into a later save
// ABOUTME: Also covers two correctness bugs fixed in IDE-2149:
// ABOUTME:   - WRONG-FOLDER reset: applyFolderResets matched by DOM index, not folderPath
// ABOUTME:   - RESET-ONLY folder dropped: collectChangedData omitted reset-only folders

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

	// isFolderMarkedForReset now takes a folderPath string (not an index).
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	var folder1Path = win.document.querySelector("[name='folder_1_folderPath']").value;

	assert.equal(fh.isFolderMarkedForReset(folder0Path), false, "flag must start cleared");

	fh.markFolderForReset(0);
	assert.equal(fh.isFolderMarkedForReset(folder0Path), true, "flag must be set after markFolderForReset");

	// Other paths must remain unaffected.
	assert.equal(fh.isFolderMarkedForReset(folder1Path), false, "flag for folder 1 must remain cleared");
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

	// markFolderForReset resolves the path from the DOM fixture.
	// Use the real fixture path in the data so applyFolderResets can match by path.
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;

	fh.markFolderForReset(0);
	var data = {
		folderConfigs: [
			{ folderPath: folder0Path, snyk_oss_enabled: true, scan_automatic: "true" }
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
	assert.equal(fh.isFolderMarkedForReset(folder0Path), true, "flag still set — cleared by getAndSaveIdeConfig finally, not applyFolderResets directly");
});

test("applyFolderResets: only resets marked folder, not other folders", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	// markFolderForReset(0) resolves the real DOM path for folder 0.
	// Use those real paths in the data so path-matching works correctly.
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	var folder1Path = win.document.querySelector("[name='folder_1_folderPath']").value;

	fh.markFolderForReset(0);
	var data = {
		folderConfigs: [
			{ folderPath: folder0Path, snyk_oss_enabled: true },
			{ folderPath: folder1Path, snyk_oss_enabled: true }
		]
	};

	fh.applyFolderResets(data);

	assert.equal(data.folderConfigs[0].snyk_oss_enabled, null, "marked folder must be reset");
	assert.equal(data.folderConfigs[1].snyk_oss_enabled, true, "unmarked folder must not be touched");
});

// ---------------------------------------------------------------------------
// Bug fix: validation-failure path must clear folderResetPaths, not carry it forward.
// A folder-reset intent is tied to its own immediate save attempt only.
// If that save is blocked (validation error), the marks must NOT survive to
// leak into any later unrelated save.
// ---------------------------------------------------------------------------

test("folder reset marks are cleared when save is blocked by validation error (does not leak into later save)", async function() {
	// Correct behavior:
	//   1. Folder reset button clicked -> markFolderForReset(i) sets the mark.
	//   2. getAndSaveIdeConfig() detects invalid form and returns early.
	//      It must clear window.ConfigApp.folderResetPaths before returning so the
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
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	assert.equal(
		fh.isFolderMarkedForReset(folder0Path),
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
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	assert.equal(
		fh.isFolderMarkedForReset(folder0Path),
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
// collectData-guard path: folderResetPaths must also be cleared when collectData fails
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
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	assert.equal(
		fh.isFolderMarkedForReset(folder0Path),
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

// ---------------------------------------------------------------------------
// Bug fix: WRONG-FOLDER reset (IDE-2149)
// collectChangedData compresses folderConfigs (only changed folders, re-indexed
// 0..n via push), but the old applyFolderResets matched by DOM index against the
// compressed array position. Resetting folder 1 when folder 0 had no other
// changes would silently no-op OR reset the wrong folder.
// The fix: mark by folderPath (a Set), match by fc.folderPath — never by position.
// ---------------------------------------------------------------------------

test("BUG: reset of folder 1 with folder 0 unchanged targets the correct folder by path (not DOM index)", async function() {
	// fixture: folder 0 = /Users/username/workspace/defaults-project
	//          folder 1 = /Users/username/workspace/org-set-project
	// folder 0 has no user edits; folder 1 is marked for reset.
	// collectChangedData will compress: only folder 1 appears, pushed to position [0].
	// Old bug: applyFolderResets(data) checks isFolderMarkedForReset(0) on the
	// compressed array — that checks DOM index 0 (folder 0), not folder 1 → wrong-folder reset.
	// Correct behavior: nulled fields appear on the entry whose folderPath == folder 1's path,
	// and folder 0's entry (if present at all) is NOT nulled.
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;
	var autoSave = win.ConfigApp.autoSave;

	// Read the real path from the DOM so this test can't pass vacuously.
	var folder1Path = win.document.querySelector("[name='folder_1_folderPath']").value;
	assert.ok(folder1Path, "fixture must have folder_1_folderPath hidden input");

	var saveCalls = [];
	win.__saveIdeConfig__ = function(jsonString) { saveCalls.push(jsonString); };

	// Mark folder 1 for reset (folder 0 has no edits, so only folder 1 appears in payload).
	fh.markFolderForReset(1);
	autoSave.getAndSaveIdeConfig();

	assert.ok(saveCalls.length > 0, "save must have fired");
	var saved = JSON.parse(saveCalls[0]);

	// The payload must contain a folderConfigs entry for folder 1's path with nulled fields.
	var folder1Entry = null;
	if (saved.folderConfigs) {
		for (var i = 0; i < saved.folderConfigs.length; i++) {
			if (saved.folderConfigs[i].folderPath === folder1Path) {
				folder1Entry = saved.folderConfigs[i];
				break;
			}
		}
	}
	assert.ok(folder1Entry, "payload must contain a folderConfigs entry with folderPath == folder 1's path");

	for (var j = 0; j < FOLDER_RESET_FIELDS.length; j++) {
		var key = FOLDER_RESET_FIELDS[j];
		assert.equal(folder1Entry[key], null, key + " must be null in folder 1's entry");
	}

	// folder 0's entry (if present) must NOT have any of the reset fields nulled.
	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	if (saved.folderConfigs) {
		for (var k = 0; k < saved.folderConfigs.length; k++) {
			if (saved.folderConfigs[k].folderPath === folder0Path) {
				for (var l = 0; l < FOLDER_RESET_FIELDS.length; l++) {
					var fkey = FOLDER_RESET_FIELDS[l];
					if (Object.prototype.hasOwnProperty.call(saved.folderConfigs[k], fkey)) {
						assert.notEqual(saved.folderConfigs[k][fkey], null,
							fkey + " must NOT be null in folder 0 — only folder 1 was reset");
					}
				}
				break;
			}
		}
	}
});

// ---------------------------------------------------------------------------
// Bug fix: RESET-ONLY folder dropped (IDE-2149)
// A folder marked for reset but with no other edited fields is omitted from
// folderConfigs entirely by collectChangedData, so its reset nulls are never sent.
// The fix: force-include a folder in the payload when it is in folderResetPaths,
// even if it has no other changed fields.
// ---------------------------------------------------------------------------

test("BUG: folder marked for reset with no other edits is included in the payload with nulled fields", async function() {
	// Start with a fresh DOM. No user edits to any folder.
	// Mark folder 0 for reset only — it has no other changes.
	// Old bug: collectChangedData finds no changed fields → changedFc is null →
	// folder 0 is not pushed → applyFolderResets sees an empty folderConfigs → no-op.
	// Correct behavior: folder 0 appears in folderConfigs with folderPath + nulled fields.
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;
	var autoSave = win.ConfigApp.autoSave;

	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;
	assert.ok(folder0Path, "fixture must have folder_0_folderPath hidden input");

	var saveCalls = [];
	win.__saveIdeConfig__ = function(jsonString) { saveCalls.push(jsonString); };

	// Mark folder 0 for reset with no other edits.
	fh.markFolderForReset(0);
	autoSave.getAndSaveIdeConfig();

	assert.ok(saveCalls.length > 0, "save must have fired");
	var saved = JSON.parse(saveCalls[0]);

	// The payload must contain folder 0's entry with nulled org-scope fields.
	var folder0Entry = null;
	if (saved.folderConfigs) {
		for (var i = 0; i < saved.folderConfigs.length; i++) {
			if (saved.folderConfigs[i].folderPath === folder0Path) {
				folder0Entry = saved.folderConfigs[i];
				break;
			}
		}
	}
	assert.ok(folder0Entry, "payload must contain a folderConfigs entry for folder 0 even when it has no other edits");

	for (var j = 0; j < FOLDER_RESET_FIELDS.length; j++) {
		var key = FOLDER_RESET_FIELDS[j];
		assert.equal(folder0Entry[key], null, key + " must be null in folder 0's reset entry");
	}
});

// ---------------------------------------------------------------------------
// Clearing: both finally and else-branch clear folderResetPaths (not folderResets)
// ---------------------------------------------------------------------------

test("folderResetPaths is cleared by finally (not leaked across saves)", async function() {
	var win = await buildDom();
	var fh = win.ConfigApp.formHandler;

	var folder0Path = win.document.querySelector("[name='folder_0_folderPath']").value;

	fh.markFolderForReset(0);
	// folderResetPaths must be a Set-like (has + size) containing the path after marking.
	// Note: instanceof Set cannot be used across JSDOM realms; duck-type instead.
	assert.ok(
		win.ConfigApp.folderResetPaths &&
		typeof win.ConfigApp.folderResetPaths.has === "function" &&
		win.ConfigApp.folderResetPaths.has(folder0Path),
		"folderResetPaths must be a Set holding folder 0's path after markFolderForReset"
	);

	var saveCalls = [];
	win.__saveIdeConfig__ = function(jsonString) { saveCalls.push(jsonString); };

	win.ConfigApp.autoSave.getAndSaveIdeConfig();

	// After save (finally block), folderResetPaths must be an empty Set (size === 0).
	// Note: instanceof Set cannot be used across JSDOM realms; check .size directly.
	assert.ok(
		win.ConfigApp.folderResetPaths &&
		typeof win.ConfigApp.folderResetPaths.size === "number" &&
		win.ConfigApp.folderResetPaths.size === 0,
		"folderResetPaths must be an empty Set after getAndSaveIdeConfig (finally)"
	);
});
