import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

// Helper functions
function hasClass(element, className) {
	return element.classList.contains(className);
}

function getOverrideIndicatorWrapper(input) {
	return input.closest(".override-indicator-wrapper");
}

function getSourceIndicator(wrapper) {
	return wrapper.querySelector(".source-indicator");
}

function triggerChangeEvent(element) {
	const event = new element.ownerDocument.defaultView.Event("change", { bubbles: true });
	element.dispatchEvent(event);
}

function triggerInputEvent(element) {
	const event = new element.ownerDocument.defaultView.Event("input", { bubbles: true });
	element.dispatchEvent(event);
}

function toggleCheckbox(win, id) {
	const checkbox = win.document.getElementById(id);
	checkbox.checked = !checkbox.checked;
	triggerChangeEvent(checkbox);
}

function setTextValue(win, id, value) {
	const input = win.document.getElementById(id);
	input.value = value;
	triggerInputEvent(input);
	triggerChangeEvent(input);
}

function selectOption(win, id, value) {
	const select = win.document.getElementById(id);
	select.value = value;
	triggerChangeEvent(select);
}

// ---------------------------------------------------------------------------
// Basic Indicator Addition Tests
// ---------------------------------------------------------------------------

test("indicator added on checkbox toggle", async () => {
	const win = await buildDom();
	const checkboxId = "folder_1_override_snyk_oss_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		// Skip if fixture doesn't have this field
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);
	assert.ok(wrapper, "checkbox should have override-indicator-wrapper parent");

	// Initially, indicator should not be present (or might be from initial state)
	const initialHasIndicator = hasClass(wrapper, "source-override");

	// Toggle checkbox
	toggleCheckbox(win, checkboxId);

	// After toggle, indicator should be added
	assert.ok(hasClass(wrapper, "source-override"), "source-override class should be added after checkbox toggle");
});

test("indicator added on text input change", async () => {
	const win = await buildDom();
	const inputId = "folder_0_preferred_org";
	const input = win.document.getElementById(inputId);

	if (!input) {
		// Skip if fixture doesn't have this field
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(input);
	assert.ok(wrapper, "text input should have override-indicator-wrapper parent");

	// Change the value
	setTextValue(win, inputId, "my-org-id");

	// After change, indicator should be added
	assert.ok(hasClass(wrapper, "source-override"), "source-override class should be added after text input change");
});

test("indicator added on select change", async () => {
	const win = await buildDom();
	const selectId = "folder_1_override_scan_automatic";
	const select = win.document.getElementById(selectId);

	if (!select) {
		// Skip if fixture doesn't have this field
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(select);
	assert.ok(wrapper, "select should have override-indicator-wrapper parent");

	// Change the select value
	selectOption(win, selectId, "manual");

	// After change, indicator should be added
	assert.ok(hasClass(wrapper, "source-override"), "source-override class should be added after select change");
});

test("indicator persists on multiple changes (idempotent)", async () => {
	const win = await buildDom();
	const checkboxId = "folder_1_override_snyk_code_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);

	// First toggle
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "source-override"), "indicator should be added on first toggle");

	// Second toggle (back to original)
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "source-override"), "indicator should persist after second toggle");

	// Third toggle
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "source-override"), "indicator should persist after third toggle");
});

// ---------------------------------------------------------------------------
// Source Indicator Removal Tests
// ---------------------------------------------------------------------------

test("source indicator (emoji) removed on change", async () => {
	const win = await buildDom();
	const checkboxId = "folder_1_override_snyk_iac_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);

	// Check if source indicator exists before change
	const sourceIndicatorBefore = getSourceIndicator(wrapper);
	if (!sourceIndicatorBefore) {
		// Skip test if no source indicator in fixture
		return;
	}

	// Change the field
	toggleCheckbox(win, checkboxId);

	// Source indicator should be removed
	const sourceIndicatorAfter = getSourceIndicator(wrapper);
	assert.equal(sourceIndicatorAfter, null, "source indicator should be removed after field change");
});

test("source indicator not removed if not present", async () => {
	const win = await buildDom();
	const checkboxId = "folder_1_override_snyk_secrets_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);

	// Verify no source indicator exists
	const sourceIndicator = getSourceIndicator(wrapper);
	if (sourceIndicator) {
		// Skip if there is a source indicator
		return;
	}

	// Change the field - should not error
	assert.doesNotThrow(() => {
		toggleCheckbox(win, checkboxId);
	}, "changing field without source indicator should not throw");

	assert.ok(hasClass(wrapper, "source-override"), "indicator should still be added");
});

// ---------------------------------------------------------------------------
// Auto-Org Checkbox Special Handling Tests
// ---------------------------------------------------------------------------

test("auto-org checkbox gets indicator when toggled", async () => {
	const win = await buildDom();
	const autoOrgId = "folder_0_auto_org";
	const autoOrgCheckbox = win.document.getElementById(autoOrgId);

	if (!autoOrgCheckbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(autoOrgCheckbox);
	assert.ok(wrapper, "auto-org checkbox should have override-indicator-wrapper parent");

	// Toggle auto-org
	toggleCheckbox(win, autoOrgId);

	// Indicator should be added to auto-org wrapper
	assert.ok(hasClass(wrapper, "source-override"), "source-override should be added to auto-org wrapper");
});

test("auto-org ON: preferred_org indicator removed", async () => {
	const win = await buildDom();
	const autoOrgId = "folder_0_auto_org";
	const preferredOrgId = "folder_0_preferred_org";
	const autoOrgCheckbox = win.document.getElementById(autoOrgId);
	const preferredOrgInput = win.document.getElementById(preferredOrgId);

	if (!autoOrgCheckbox || !preferredOrgInput) {
		return;
	}

	const preferredOrgWrapper = getOverrideIndicatorWrapper(preferredOrgInput);

	// First, ensure auto-org is OFF (checkbox unchecked)
	if (autoOrgCheckbox.checked) {
		toggleCheckbox(win, autoOrgId);
	}

	// Add indicator to preferred_org by changing it
	setTextValue(win, preferredOrgId, "my-org");
	assert.ok(hasClass(preferredOrgWrapper, "source-override"), "preferred_org should have indicator when auto-org is OFF");

	// Now toggle auto-org ON
	toggleCheckbox(win, autoOrgId);

	// Indicator should be removed from preferred_org
	assert.ok(!hasClass(preferredOrgWrapper, "source-override"), "source-override should be removed from preferred_org when auto-org is ON");
});

test("auto-org OFF: preferred_org indicator added", async () => {
	const win = await buildDom();
	const autoOrgId = "folder_0_auto_org";
	const preferredOrgId = "folder_0_preferred_org";
	const autoOrgCheckbox = win.document.getElementById(autoOrgId);
	const preferredOrgInput = win.document.getElementById(preferredOrgId);

	if (!autoOrgCheckbox || !preferredOrgInput) {
		return;
	}

	const preferredOrgWrapper = getOverrideIndicatorWrapper(preferredOrgInput);

	// First, ensure auto-org is ON (checkbox checked)
	if (!autoOrgCheckbox.checked) {
		toggleCheckbox(win, autoOrgId);
	}

	// Verify preferred_org has no indicator when auto-org is ON
	assert.ok(!hasClass(preferredOrgWrapper, "source-override"), "preferred_org should not have indicator when auto-org is ON");

	// Now toggle auto-org OFF
	toggleCheckbox(win, autoOrgId);

	// Indicator should be added to preferred_org
	assert.ok(hasClass(preferredOrgWrapper, "source-override"), "source-override should be added to preferred_org when auto-org is OFF");
});

test("auto-org OFF: preferred_org source indicator removed", async () => {
	const win = await buildDom();
	const autoOrgId = "folder_0_auto_org";
	const preferredOrgId = "folder_0_preferred_org";
	const autoOrgCheckbox = win.document.getElementById(autoOrgId);
	const preferredOrgInput = win.document.getElementById(preferredOrgId);

	if (!autoOrgCheckbox || !preferredOrgInput) {
		return;
	}

	const preferredOrgWrapper = getOverrideIndicatorWrapper(preferredOrgInput);

	// Ensure auto-org is ON first
	if (!autoOrgCheckbox.checked) {
		toggleCheckbox(win, autoOrgId);
	}

	// Check if source indicator exists
	const sourceIndicatorBefore = getSourceIndicator(preferredOrgWrapper);
	if (!sourceIndicatorBefore) {
		// Skip if no source indicator in fixture
		return;
	}

	// Toggle auto-org OFF
	toggleCheckbox(win, autoOrgId);

	// Source indicator should be removed
	const sourceIndicatorAfter = getSourceIndicator(preferredOrgWrapper);
	assert.equal(sourceIndicatorAfter, null, "source indicator should be removed from preferred_org when auto-org is toggled OFF");
});

test("auto-org ON: preferred_org source indicator stays", async () => {
	const win = await buildDom();
	const autoOrgId = "folder_0_auto_org";
	const preferredOrgId = "folder_0_preferred_org";
	const autoOrgCheckbox = win.document.getElementById(autoOrgId);
	const preferredOrgInput = win.document.getElementById(preferredOrgId);

	if (!autoOrgCheckbox || !preferredOrgInput) {
		return;
	}

	const preferredOrgWrapper = getOverrideIndicatorWrapper(preferredOrgInput);

	// Check if source indicator exists
	const sourceIndicatorBefore = getSourceIndicator(preferredOrgWrapper);
	if (!sourceIndicatorBefore) {
		// Skip if no source indicator in fixture
		return;
	}

	// Ensure auto-org is OFF first
	if (autoOrgCheckbox.checked) {
		toggleCheckbox(win, autoOrgId);
	}

	// Toggle auto-org ON
	toggleCheckbox(win, autoOrgId);

	// Source indicator should still be present (not removed when toggling ON)
	const sourceIndicatorAfter = getSourceIndicator(preferredOrgWrapper);
	assert.ok(sourceIndicatorAfter, "source indicator should remain when auto-org is toggled ON");
});

// ---------------------------------------------------------------------------
// Edge Cases
// ---------------------------------------------------------------------------

test("no wrapper found: no error", async () => {
	const win = await buildDom();

	// Create a temporary input without a wrapper
	const tempInput = win.document.createElement("input");
	tempInput.type = "checkbox";
	tempInput.id = "temp_test_input";
	win.document.body.appendChild(tempInput);

	// Trigger change - should not error
	assert.doesNotThrow(() => {
		triggerChangeEvent(tempInput);
	}, "changing input without wrapper should not throw");

	// Cleanup
	tempInput.remove();
});

test("multiple folders: indicators isolated", async () => {
	const win = await buildDom();
	const checkbox1Id = "folder_1_override_snyk_oss_enabled";
	const checkbox2Id = "folder_2_override_snyk_oss_enabled";
	const checkbox1 = win.document.getElementById(checkbox1Id);
	const checkbox2 = win.document.getElementById(checkbox2Id);

	if (!checkbox1 || !checkbox2) {
		// Skip if fixture doesn't have multiple folders
		return;
	}

	const wrapper1 = getOverrideIndicatorWrapper(checkbox1);
	const wrapper2 = getOverrideIndicatorWrapper(checkbox2);

	// Toggle folder 1 checkbox
	toggleCheckbox(win, checkbox1Id);

	// Folder 1 should have indicator
	assert.ok(hasClass(wrapper1, "source-override"), "folder 1 should have indicator");

	// Folder 2 should not have indicator
	assert.ok(!hasClass(wrapper2, "source-override"), "folder 2 should not have indicator");

	// Toggle folder 2 checkbox
	toggleCheckbox(win, checkbox2Id);

	// Both should now have indicators
	assert.ok(hasClass(wrapper1, "source-override"), "folder 1 should still have indicator");
	assert.ok(hasClass(wrapper2, "source-override"), "folder 2 should now have indicator");
});

// ---------------------------------------------------------------------------
// Project Default Indicator Tests
// ---------------------------------------------------------------------------

test("project default checkbox gets indicator when toggled", async () => {
	const win = await buildDom();
	const checkboxId = "snyk_oss_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		// Skip if fixture doesn't have project default field
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);
	assert.ok(wrapper, "project default checkbox should have override-indicator-wrapper parent");

	// Toggle checkbox
	toggleCheckbox(win, checkboxId);

	// After toggle, indicator should be added
	assert.ok(hasClass(wrapper, "source-override"), "source-override class should be added to project default checkbox");
});

test("project default select gets indicator when changed", async () => {
	const win = await buildDom();
	const selectId = "scan_automatic";
	const select = win.document.getElementById(selectId);

	if (!select) {
		// Skip if fixture doesn't have project default select
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(select);
	assert.ok(wrapper, "project default select should have override-indicator-wrapper parent");

	// Change the select value
	selectOption(win, selectId, "false");

	// After change, indicator should be added with source-global class
	assert.ok(hasClass(wrapper, "source-global"), "source-global class should be added to project default select");
});

test("project default text input gets indicator when changed", async () => {
	const win = await buildDom();
	const inputId = "organization";
	const input = win.document.getElementById(inputId);

	if (!input) {
		// Skip if fixture doesn't have project default text input
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(input);
	assert.ok(wrapper, "project default text input should have override-indicator-wrapper parent");

	// Change the value
	setTextValue(win, inputId, "my-org-id");

	// After change, indicator should be added with source-global class
	assert.ok(hasClass(wrapper, "source-global"), "source-global class should be added to project default text input");
});

test("project default severity filter checkbox gets indicator when toggled", async () => {
	const win = await buildDom();
	const checkboxId = "enabled_severities_critical";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		// Skip if fixture doesn't have severity filter checkbox
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);
	assert.ok(wrapper, "severity filter checkbox should have override-indicator-wrapper parent");

	// Toggle checkbox
	toggleCheckbox(win, checkboxId);

	// After toggle, indicator should be added
	assert.ok(hasClass(wrapper, "source-override"), "source-override class should be added to severity filter checkbox");
});

test("project default issue view option gets indicator when toggled", async () => {
	const win = await buildDom();
	const checkboxId = "issue_view_open_issues";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		// Skip if fixture doesn't have issue view option checkbox
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);
	assert.ok(wrapper, "issue view option checkbox should have override-indicator-wrapper parent");

	// Toggle checkbox
	toggleCheckbox(win, checkboxId);

	// After toggle, indicator should be added
	assert.ok(hasClass(wrapper, "source-override"), "source-override class should be added to issue view option checkbox");
});

test("project default source indicator removed on change", async () => {
	const win = await buildDom();
	const checkboxId = "snyk_code_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);

	// Check if source indicator exists before change
	const sourceIndicatorBefore = getSourceIndicator(wrapper);
	if (!sourceIndicatorBefore) {
		// Skip test if no source indicator in fixture
		return;
	}

	// Change the field
	toggleCheckbox(win, checkboxId);

	// Source indicator should be removed
	const sourceIndicatorAfter = getSourceIndicator(wrapper);
	assert.equal(sourceIndicatorAfter, null, "source indicator should be removed from project default after field change");
});

test("project default indicator persists on multiple changes", async () => {
	const win = await buildDom();
	const checkboxId = "snyk_iac_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);

	// First toggle
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "source-override"), "indicator should be added on first toggle");

	// Second toggle (back to original)
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "source-override"), "indicator should persist after second toggle");

	// Third toggle
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "source-override"), "indicator should persist after third toggle");
});

test("project default number input gets indicator when changed", async () => {
	const win = await buildDom();
	const inputId = "risk_score_threshold";
	const input = win.document.getElementById(inputId);

	if (!input) {
		// Skip if fixture doesn't have risk score threshold input
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(input);
	assert.ok(wrapper, "risk score threshold input should have override-indicator-wrapper parent");

	// Change the value
	setTextValue(win, inputId, "500");

	// After change, indicator should be added with source-global class
	assert.ok(hasClass(wrapper, "source-global"), "source-global class should be added to risk score threshold input");
});

test("project default delta findings select gets indicator when changed", async () => {
	const win = await buildDom();
	const selectId = "scan_net_new";
	const select = win.document.getElementById(selectId);

	if (!select) {
		// Skip if fixture doesn't have delta findings select
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(select);
	assert.ok(wrapper, "delta findings select should have override-indicator-wrapper parent");

	// Change the select value
	selectOption(win, selectId, "true");

	// After change, indicator should be added with source-global class
	assert.ok(hasClass(wrapper, "source-global"), "source-global class should be added to delta findings select");
});

// ---------------------------------------------------------------------------
// Project Default Propagation Tests
// ---------------------------------------------------------------------------

test("project default propagates to folder fields without overrides", async () => {
	const win = await buildDom();
	const projectCheckboxId = "snyk_oss_enabled";
	const folderCheckboxId = "folder_1_override_snyk_oss_enabled";
	const projectCheckbox = win.document.getElementById(projectCheckboxId);
	const folderCheckbox = win.document.getElementById(folderCheckboxId);

	if (!projectCheckbox || !folderCheckbox) {
		// Skip if fixture doesn't have these fields
		return;
	}

	// Get initial folder value
	const initialValue = folderCheckbox.checked;

	// Change project default
	toggleCheckbox(win, projectCheckboxId);

	// Folder field should be updated to match
	assert.equal(folderCheckbox.checked, !initialValue, "folder field should be updated when project default changes");
});

test("project default does not propagate to folder fields with user override", async () => {
	const win = await buildDom();
	const projectCheckboxId = "snyk_code_enabled";
	const folderCheckboxId = "folder_1_override_snyk_code_enabled";
	const projectCheckbox = win.document.getElementById(projectCheckboxId);
	const folderCheckbox = win.document.getElementById(folderCheckboxId);

	if (!projectCheckbox || !folderCheckbox) {
		// Skip if fixture doesn't have these fields
		return;
	}

	// First, add user override to folder field
	toggleCheckbox(win, folderCheckboxId);
	const folderValueAfterOverride = folderCheckbox.checked;

	// Now change project default
	toggleCheckbox(win, projectCheckboxId);

	// Folder field should NOT be updated (should keep user override)
	assert.equal(folderCheckbox.checked, folderValueAfterOverride, "folder field with user override should not be updated");
});

test("project default does not propagate to org-locked folder fields", async () => {
	const win = await buildDom();
	const projectInputId = "risk_score_threshold";
	const folderInputId = "folder_1_override_risk_score_threshold";
	const projectInput = win.document.getElementById(projectInputId);
	const folderInput = win.document.getElementById(folderInputId);

	if (!projectInput || !folderInput) {
		// Skip if fixture doesn't have these fields
		return;
	}

	// Add org-locked class to folder field
	const folderWrapper = getOverrideIndicatorWrapper(folderInput);
	if (folderWrapper) {
		folderWrapper.classList.add("source-org-locked");
	}

	const initialValue = folderInput.value;

	// Change project default
	setTextValue(win, projectInputId, "999");

	// Folder field should NOT be updated (org-locked)
	assert.equal(folderInput.value, initialValue, "org-locked folder field should not be updated");
});
