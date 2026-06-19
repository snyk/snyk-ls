// ABOUTME: Tests for the global ("Project Defaults") reset on the HTML settings page.
// ABOUTME: Covers markGlobalForReset/isGlobalMarkedForReset, applyGlobalResets(data)
// ABOUTME: writing 14 top-level nulls, and a DOM-driven click producing those nulls in the save payload.

import assert from "node:assert/strict";
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

test("clicking .reset-global-overrides-btn saves 14 top-level nulls", async () => {
	const win = await buildDom();

	// Auto-confirm the reset dialog (JSDOM's confirm is not implemented).
	win.confirm = function () {
		return true;
	};

	// Spy on the IDE save bridge.
	var calls = [];
	win.__saveIdeConfig__ = function (jsonString) {
		calls.push(jsonString);
	};

	const btn = win.document.querySelector(".reset-global-overrides-btn");
	assert.ok(btn, ".reset-global-overrides-btn must exist in the fixture");

	btn.click();

	// The click only marks the scope for reset; the IDE triggers the save (OK button path).
	win.getAndSaveIdeConfig();

	assert.ok(calls.length > 0, "save must have been called");
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
