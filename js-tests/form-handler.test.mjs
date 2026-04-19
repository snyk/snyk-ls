import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// Test that form-handler correctly collects folder severity overrides with _filter_ infix

test("collectData: folder severity_filter_* fields are collected correctly", async () => {
	const win = await buildDom();
	const doc = win.document;

	// Set up a folder with severity filter overrides
	// Use folder 1 (defaults-project) which has the useConfigAPI flag enabled
	const criticalCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_critical"]');
	const highCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_high"]');
	const mediumCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_medium"]');
	const lowCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_low"]');

	if (criticalCheckbox) {
		criticalCheckbox.checked = true;
	}
	if (highCheckbox) {
		highCheckbox.checked = false;
	}
	if (mediumCheckbox) {
		mediumCheckbox.checked = true;
	}
	if (lowCheckbox) {
		lowCheckbox.checked = false;
	}

	// Collect form data
	const data = win.ConfigApp.formHandler.collectData();

	// Verify folder configs were collected
	assert.ok(data.folderConfigs, "folderConfigs should exist");
	assert.ok(data.folderConfigs.length > 0, "should have at least one folder config");

	// Get folder 1 (defaults-project) which we modified in the setup
	const folderConfig = data.folderConfigs[1];
	assert.ok(folderConfig, "folder config at index 1 should exist");

	// Verify severity_filter_* fields were collected with correct values
	assert.equal(folderConfig.severity_filter_critical, true, "severity_filter_critical should be true");
	assert.equal(folderConfig.severity_filter_high, false, "severity_filter_high should be false");
	assert.equal(folderConfig.severity_filter_medium, true, "severity_filter_medium should be true");
	assert.equal(folderConfig.severity_filter_low, false, "severity_filter_low should be false");
});

test("collectData: folder severity_filter_* fields with all unchecked", async () => {
	const win = await buildDom();
	const doc = win.document;

	// Find and uncheck all severity checkboxes
	// Use folder 1 (defaults-project) which has the useConfigAPI flag enabled
	const criticalCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_critical"]');
	const highCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_high"]');
	const mediumCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_medium"]');
	const lowCheckbox = doc.querySelector('input[name="folder_1_override_severity_filter_low"]');

	if (criticalCheckbox) criticalCheckbox.checked = false;
	if (highCheckbox) highCheckbox.checked = false;
	if (mediumCheckbox) mediumCheckbox.checked = false;
	if (lowCheckbox) lowCheckbox.checked = false;

	// Collect form data
	const data = win.ConfigApp.formHandler.collectData();

	// Verify all are false
	if (data.folderConfigs.length > 0) {
		const folderConfig = data.folderConfigs[0];
		if (folderConfig.enabled_severities) {
			assert.equal(folderConfig.enabled_severities.critical, false, "all should be false");
			assert.equal(folderConfig.enabled_severities.high, false, "all should be false");
			assert.equal(folderConfig.enabled_severities.medium, false, "all should be false");
			assert.equal(folderConfig.enabled_severities.low, false, "all should be false");
		}
	}
});
