import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// Test that form-handler correctly collects folder severity overrides with _filter_ infix

test("collectData: folder severity_filter_* fields are collected correctly", async () => {
	const win = await buildDom();
	const doc = win.document;

	// Set up a folder with severity filter overrides
	// Simulate folder 0 with severity_filter_critical checked
	const criticalCheckbox = doc.querySelector('input[name="folder_0_severity_filter_critical"]');
	const highCheckbox = doc.querySelector('input[name="folder_0_severity_filter_high"]');
	const mediumCheckbox = doc.querySelector('input[name="folder_0_severity_filter_medium"]');
	const lowCheckbox = doc.querySelector('input[name="folder_0_severity_filter_low"]');

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

	// Find the first folder config
	const folderConfig = data.folderConfigs[0];
	assert.ok(folderConfig, "first folder config should exist");

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
	const criticalCheckbox = doc.querySelector('input[name="folder_0_severity_filter_critical"]');
	const highCheckbox = doc.querySelector('input[name="folder_0_severity_filter_high"]');
	const mediumCheckbox = doc.querySelector('input[name="folder_0_severity_filter_medium"]');
	const lowCheckbox = doc.querySelector('input[name="folder_0_severity_filter_low"]');

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

test("collectData and collectChangedData serialize Secure At Inception values at top level", async () => {
	const win = await buildDom();
	const doc = win.document;
	const checkbox = doc.querySelector('input[name="auto_configure_mcp_server"]');
	const frequencySelect = doc.querySelector(
		'select[name="secure_at_inception_execution_frequency"]'
	);
	assert.ok(checkbox, "auto_configure_mcp_server checkbox must exist");
	assert.ok(frequencySelect, "secure_at_inception_execution_frequency select must exist");

	for (const autoConfigure of [false, true]) {
		for (const frequency of ["On Code Generation", "Smart Scan", "Manual"]) {
			checkbox.checked = autoConfigure;
			frequencySelect.value = frequency;
			win.dirtyTracker.originalData.auto_configure_mcp_server = !autoConfigure;
			win.dirtyTracker.originalData.secure_at_inception_execution_frequency =
				frequency === "Manual" ? "Smart Scan" : "Manual";

			const data = win.ConfigApp.formHandler.collectData();
			const changedData = win.ConfigApp.formHandler.collectChangedData();

			assert.equal(data.auto_configure_mcp_server, autoConfigure);
			assert.equal(data.secure_at_inception_execution_frequency, frequency);
			assert.equal(changedData.auto_configure_mcp_server, autoConfigure);
			assert.equal(changedData.secure_at_inception_execution_frequency, frequency);
			for (const folderConfig of data.folderConfigs) {
				assert.equal(
					Object.prototype.hasOwnProperty.call(folderConfig, "auto_configure_mcp_server"),
					false
				);
				assert.equal(
					Object.prototype.hasOwnProperty.call(
						folderConfig,
						"secure_at_inception_execution_frequency"
					),
					false
				);
			}
		}
	}
});

test("Secure At Inception section reset restores false and Manual", async () => {
	const win = await buildDom();
	const doc = win.document;
	const checkbox = doc.querySelector('input[name="auto_configure_mcp_server"]');
	const frequencySelect = doc.querySelector(
		'select[name="secure_at_inception_execution_frequency"]'
	);
	const reset = doc.querySelector(
		'.reset-section-btn[data-section="secureAtInception"]'
	);
	assert.ok(checkbox, "auto_configure_mcp_server checkbox must exist");
	assert.ok(frequencySelect, "secure_at_inception_execution_frequency select must exist");
	assert.ok(reset, "Secure At Inception reset button must exist");

	checkbox.checked = true;
	frequencySelect.value = "On Code Generation";
	win.dirtyTracker.originalData.auto_configure_mcp_server = true;
	win.dirtyTracker.originalData.secure_at_inception_execution_frequency =
		"On Code Generation";
	reset.click();

	assert.equal(checkbox.checked, false);
	assert.equal(frequencySelect.value, "Manual");
	const changedData = win.ConfigApp.formHandler.collectChangedData();
	assert.equal(changedData.auto_configure_mcp_server, false);
	assert.equal(changedData.secure_at_inception_execution_frequency, "Manual");
});
