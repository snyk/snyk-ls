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
	const checkboxId = "folder_0_override_snyk_oss_enabled";
	const checkbox = win.document.getElementById(checkboxId);
	
	if (!checkbox) {
		// Skip if fixture doesn't have this field
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);
	assert.ok(wrapper, "checkbox should have override-indicator-wrapper parent");

	// Initially, indicator should not be present (or might be from initial state)
	const initialHasIndicator = hasClass(wrapper, "has-user-override");

	// Toggle checkbox
	toggleCheckbox(win, checkboxId);

	// After toggle, indicator should be added
	assert.ok(hasClass(wrapper, "has-user-override"), "has-user-override class should be added after checkbox toggle");
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
	assert.ok(hasClass(wrapper, "has-user-override"), "has-user-override class should be added after text input change");
});

test("indicator added on select change", async () => {
	const win = await buildDom();
	const selectId = "folder_0_override_scan_automatic";
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
	assert.ok(hasClass(wrapper, "has-user-override"), "has-user-override class should be added after select change");
});

test("indicator persists on multiple changes (idempotent)", async () => {
	const win = await buildDom();
	const checkboxId = "folder_0_override_snyk_code_enabled";
	const checkbox = win.document.getElementById(checkboxId);

	if (!checkbox) {
		return;
	}

	const wrapper = getOverrideIndicatorWrapper(checkbox);

	// First toggle
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "has-user-override"), "indicator should be added on first toggle");

	// Second toggle (back to original)
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "has-user-override"), "indicator should persist after second toggle");

	// Third toggle
	toggleCheckbox(win, checkboxId);
	assert.ok(hasClass(wrapper, "has-user-override"), "indicator should persist after third toggle");
});

// ---------------------------------------------------------------------------
// Source Indicator Removal Tests
// ---------------------------------------------------------------------------

test("source indicator (emoji) removed on change", async () => {
	const win = await buildDom();
	const checkboxId = "folder_0_override_snyk_iac_enabled";
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
	const checkboxId = "folder_0_override_snyk_secrets_enabled";
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

	assert.ok(hasClass(wrapper, "has-user-override"), "indicator should still be added");
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
	assert.ok(hasClass(wrapper, "has-user-override"), "has-user-override should be added to auto-org wrapper");
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
	assert.ok(hasClass(preferredOrgWrapper, "has-user-override"), "preferred_org should have indicator when auto-org is OFF");

	// Now toggle auto-org ON
	toggleCheckbox(win, autoOrgId);

	// Indicator should be removed from preferred_org
	assert.ok(!hasClass(preferredOrgWrapper, "has-user-override"), "has-user-override should be removed from preferred_org when auto-org is ON");
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
	assert.ok(!hasClass(preferredOrgWrapper, "has-user-override"), "preferred_org should not have indicator when auto-org is ON");

	// Now toggle auto-org OFF
	toggleCheckbox(win, autoOrgId);

	// Indicator should be added to preferred_org
	assert.ok(hasClass(preferredOrgWrapper, "has-user-override"), "has-user-override should be added to preferred_org when auto-org is OFF");
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
	const checkbox0Id = "folder_0_override_snyk_oss_enabled";
	const checkbox1Id = "folder_1_override_snyk_oss_enabled";
	const checkbox0 = win.document.getElementById(checkbox0Id);
	const checkbox1 = win.document.getElementById(checkbox1Id);

	if (!checkbox0 || !checkbox1) {
		// Skip if fixture doesn't have multiple folders
		return;
	}

	const wrapper0 = getOverrideIndicatorWrapper(checkbox0);
	const wrapper1 = getOverrideIndicatorWrapper(checkbox1);

	// Toggle folder 0 checkbox
	toggleCheckbox(win, checkbox0Id);

	// Folder 0 should have indicator
	assert.ok(hasClass(wrapper0, "has-user-override"), "folder 0 should have indicator");

	// Folder 1 should not have indicator
	assert.ok(!hasClass(wrapper1, "has-user-override"), "folder 1 should not have indicator");

	// Toggle folder 1 checkbox
	toggleCheckbox(win, checkbox1Id);

	// Both should now have indicators
	assert.ok(hasClass(wrapper0, "has-user-override"), "folder 0 should still have indicator");
	assert.ok(hasClass(wrapper1, "has-user-override"), "folder 1 should now have indicator");
});
