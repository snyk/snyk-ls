// ABOUTME: Tests for the per-folder "Reset overrides" flow (form-handler + reset-handler).
// ABOUTME: Verifies resets are keyed by folderPath, emit 14 flat nulls, and survive compaction.

import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// The 14 org-scope folder fields a reset must clear (mirrors FOLDER_RESET_FIELDS in form-handler.js).
const RESET_FIELDS = [
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
	"preferred_org",
];

// Folder paths embedded in the dummy-data fixture (js-tests/fixtures/config-page.html).
const PATH_A = "/Users/username/workspace/defaults-project";
const PATH_B = "/Users/username/workspace/org-set-project";
const PATH_C = "/Users/username/workspace/org-locked-project";

function assertAllNull(entry, fields) {
	for (const f of fields) {
		assert.equal(entry[f], null, `${f} should be null`);
	}
}

// Enable auto-save and spy on the IDE save bridge; returns the list of JSON payloads sent.
function spySave(win) {
	win.__IS_IDE_AUTOSAVE_ENABLED__ = true;
	const calls = [];
	win.__saveIdeConfig__ = (jsonString) => calls.push(jsonString);
	return calls;
}

test("markFolderForReset / isFolderMarkedForReset are keyed by folderPath", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	assert.equal(fh.isFolderMarkedForReset(PATH_A), false, "not marked initially");
	fh.markFolderForReset(PATH_A);
	assert.equal(fh.isFolderMarkedForReset(PATH_A), true, "marked after mark");
	assert.equal(fh.isFolderMarkedForReset(PATH_B), false, "other path stays unmarked");
});

test("markFolderForReset ignores empty/missing folderPath", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	fh.markFolderForReset("");
	fh.markFolderForReset(undefined);
	assert.equal(fh.isFolderMarkedForReset(""), false, "empty path must not mark");
	assert.equal(fh.isFolderMarkedForReset(undefined), false, "undefined path must not mark");
});

test("applyFolderResets sets all 14 fields to null on an existing edited folder, preserving folderPath", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	const data = {
		folderConfigs: [
			{ folderPath: PATH_A, snyk_code_enabled: true, scan_automatic: "true" },
		],
	};
	fh.markFolderForReset(PATH_A);
	fh.applyFolderResets(data);

	const entry = data.folderConfigs.find((f) => f.folderPath === PATH_A);
	assert.ok(entry, "edited folder entry preserved");
	assert.equal(entry.folderPath, PATH_A, "folderPath preserved");
	assertAllNull(entry, RESET_FIELDS);
});

test("applyFolderResets emits a reset-only folder absent from data.folderConfigs (bug #2)", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	// Reset-only folder: collectChangedData dropped it because it had no other changed field.
	const data = { folderConfigs: [] };
	fh.markFolderForReset(PATH_A);
	fh.applyFolderResets(data);

	assert.equal(data.folderConfigs.length, 1, "a fresh entry was pushed for the reset-only folder");
	const entry = data.folderConfigs[0];
	assert.equal(entry.folderPath, PATH_A, "pushed entry carries folderPath");
	assertAllNull(entry, RESET_FIELDS);
});

test("applyFolderResets creates folderConfigs array when missing", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	const data = {};
	fh.markFolderForReset(PATH_A);
	fh.applyFolderResets(data);

	assert.ok(Array.isArray(data.folderConfigs), "folderConfigs initialized");
	assert.equal(data.folderConfigs.length, 1, "reset-only entry pushed");
	assert.equal(data.folderConfigs[0].folderPath, PATH_A);
});

test("applyFolderResets nulls only the marked folder; others untouched (bug #1 — compaction/index drift)", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	// Folders A, B, C present (as collectChangedData would emit them, compacted). Mark only B.
	const data = {
		folderConfigs: [
			{ folderPath: PATH_A, snyk_code_enabled: true },
			{ folderPath: PATH_B, snyk_code_enabled: false },
			{ folderPath: PATH_C, scan_automatic: "false" },
		],
	};
	fh.markFolderForReset(PATH_B);
	fh.applyFolderResets(data);

	const a = data.folderConfigs.find((f) => f.folderPath === PATH_A);
	const b = data.folderConfigs.find((f) => f.folderPath === PATH_B);
	const c = data.folderConfigs.find((f) => f.folderPath === PATH_C);

	// B is fully reset.
	assertAllNull(b, RESET_FIELDS);
	// A and C keep their original edits and are NOT nulled.
	assert.equal(a.snyk_code_enabled, true, "A.snyk_code_enabled untouched");
	assert.equal(a.scan_automatic, undefined, "A reset fields not added");
	assert.equal(c.scan_automatic, "false", "C.scan_automatic untouched");
	assert.equal(c.snyk_code_enabled, undefined, "C reset fields not added");
});

test("applyFolderResets clears window.ConfigApp.folderResets after applying", async () => {
	const win = await buildDom();
	const fh = win.ConfigApp.formHandler;

	fh.markFolderForReset(PATH_A);
	fh.applyFolderResets({ folderConfigs: [{ folderPath: PATH_A }] });

	// Prototype-agnostic: the reset map is created in the JSDOM realm, so compare by key count
	// rather than deepStrictEqual against this realm's {} (different Object.prototype).
	assert.equal(Object.keys(win.ConfigApp.folderResets).length, 0, "folderResets cleared");
	assert.equal(fh.isFolderMarkedForReset(PATH_A), false, "no longer marked");
});

test("DOM-driven: clicking .reset-overrides-btn produces 14 nulls for that folderPath in the save payload", async () => {
	const win = await buildDom();
	const doc = win.document;
	const calls = spySave(win);

	// Click the reset button for folder index 1 (PATH_B). The click both marks the folder and
	// saves; assert on the actual outbound payload the IDE receives.
	const btn = doc.querySelector('.reset-overrides-btn[data-folder-index="1"]');
	assert.ok(btn, "reset button for folder 1 exists in the rendered fixture");
	btn.click();

	assert.ok(calls.length > 0, "reset click must save");
	const saved = JSON.parse(calls[calls.length - 1]);
	const entry = (saved.folderConfigs || []).find((f) => f.folderPath === PATH_B);
	assert.ok(entry, "outbound payload contains an entry for the reset folderPath");
	assertAllNull(entry, RESET_FIELDS);
});

test("DOM-driven: reset button click does not require the folder to have other edits", async () => {
	const win = await buildDom();
	const doc = win.document;
	const calls = spySave(win);

	// Folder index 0 (PATH_A), no edits made — reset-only.
	const btn = doc.querySelector('.reset-overrides-btn[data-folder-index="0"]');
	assert.ok(btn, "reset button for folder 0 exists");
	btn.click();

	assert.ok(calls.length > 0, "reset-only click must still save");
	const saved = JSON.parse(calls[calls.length - 1]);
	const entry = (saved.folderConfigs || []).find((f) => f.folderPath === PATH_A);
	assert.ok(entry, "reset-only folder still emitted in payload");
	assertAllNull(entry, RESET_FIELDS);
});

test("clicking reset triggers a save even with no other edits", async () => {
	const win = await buildDom();
	const doc = win.document;
	const calls = spySave(win);

	// A folder reset changes no DOM input, so without an explicit save trigger it would never
	// persist (this was the VS Code bug). Regression guard: the click alone must reach
	// __saveIdeConfig__. The reset handler calls getAndSaveIdeConfig() directly, so this holds for
	// every IDE, not just auto-save ones.
	const btn = doc.querySelector('.reset-overrides-btn[data-folder-index="1"]');
	assert.ok(btn, "reset button for folder 1 exists");
	btn.click();

	assert.ok(calls.length > 0, "reset click must trigger a save");
	const saved = JSON.parse(calls[calls.length - 1]);
	const entry = (saved.folderConfigs || []).find((f) => f.folderPath === PATH_B);
	assert.ok(entry, "saved payload must contain the reset folder");
	assertAllNull(entry, RESET_FIELDS);
});
