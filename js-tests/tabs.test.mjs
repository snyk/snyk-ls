import assert from "node:assert/strict";
import test from "node:test";
import { buildDom } from "./helpers.mjs";

function hasClass(el, className) {
	return el.className.includes(className);
}

// Tab Switching Tests

test("tab click activates tab and pane", async () => {
	const win = await buildDom();
	const tabLinks = win.document.querySelectorAll('.settings-tabs .nav-link[data-tab-target]');
	const panes = win.document.querySelectorAll('.tab-content > .tab-pane');

	if (tabLinks.length < 2) {
		// Skip if not enough tabs (single folder scenario)
		return;
	}

	// Click second tab
	const secondTab = tabLinks[1];
	secondTab.click();

	// Verify second tab is active
	assert.ok(hasClass(secondTab, 'active'), "clicked tab should have 'active' class");

	// Verify second pane is active (data-tab-target points to pane id)
	const targetId = secondTab.getAttribute('data-tab-target') || secondTab.getAttribute('href');
	if (targetId) {
		const targetPane = win.document.querySelector(targetId);
		assert.ok(targetPane && hasClass(targetPane, 'active'), "target pane should have 'active' class");
	}
});

test("tab click deactivates other tabs", async () => {
	const win = await buildDom();
	const tabLinks = win.document.querySelectorAll('.settings-tabs .nav-link[data-tab-target]');
	const panes = win.document.querySelectorAll('.tab-content > .tab-pane');

	if (tabLinks.length < 2) {
		return;
	}

	// Click second tab
	const secondTab = tabLinks[1];
	secondTab.click();

	// Verify first tab is NOT active
	const firstTab = tabLinks[0];
	assert.ok(!hasClass(firstTab, 'active'), "other tabs should not have 'active' class");

	// Verify first pane is NOT active
	if (panes.length > 0) {
		assert.ok(!hasClass(panes[0], 'active'), "other panes should not have 'active' class");
	}
});

test("non-folder tab click resets dropdown state", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');
	const dropdownLabel = win.document.getElementById('folderDropdownLabel');

	if (!dropdownBtn || !dropdownMenu) {
		// Skip if no dropdown (single folder scenario)
		return;
	}

	// Store default label
	const defaultLabel = dropdownLabel ? dropdownLabel.textContent : '';

	// Open dropdown
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should be open after click");

	// Click a non-folder tab (first tab)
	const tabLinks = win.document.querySelectorAll('.settings-tabs .nav-link[data-tab-target]');
	if (tabLinks.length > 0) {
		const firstTab = tabLinks[0];
		firstTab.click();

		// Verify dropdown button loses 'active' class
		assert.ok(!hasClass(dropdownBtn, 'active'), "dropdown button should not have 'active' class after non-folder tab click");

		// Verify dropdown label resets to default
		if (dropdownLabel) {
			assert.equal(dropdownLabel.textContent, defaultLabel, "dropdown label should reset to default");
		}

		// Verify all folder items lose 'selected' class
		const folderItems = win.document.querySelectorAll('.folder-dropdown-item');
		for (let i = 0; i < folderItems.length; i++) {
			assert.ok(!hasClass(folderItems[i], 'selected'), `folder item ${i} should not have 'selected' class`);
		}
	}
});

test("folder tab click preserves dropdown state", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');
	const folderItems = win.document.querySelectorAll('.folder-dropdown-item');

	if (!dropdownBtn || !dropdownMenu || folderItems.length === 0) {
		// Skip if no dropdown or folder items
		return;
	}

	// Open dropdown
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should be open");

	// Click first folder item (this is a folder selector, not a regular tab)
	const firstFolderItem = folderItems[0];
	firstFolderItem.click();

	// Verify dropdown button still has 'active' class
	assert.ok(hasClass(dropdownBtn, 'active'), "dropdown button should have 'active' class after folder selection");

	// Verify folder item has 'selected' class
	assert.ok(hasClass(firstFolderItem, 'selected'), "selected folder item should have 'selected' class");
});

// Dropdown Toggle Tests

test("dropdown button toggles show class", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');

	if (!dropdownBtn || !dropdownMenu) {
		return;
	}

	// Initial state: dropdown should be closed
	assert.ok(!hasClass(dropdownMenu, 'show'), "dropdown should be closed initially");

	// First click: open dropdown
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should have 'show' class after first click");

	// Second click: close dropdown
	dropdownBtn.click();
	assert.ok(!hasClass(dropdownMenu, 'show'), "dropdown should not have 'show' class after second click");

	// Third click: open again (verify toggle is idempotent)
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should have 'show' class after third click");
});

test("outside click closes dropdown", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');

	if (!dropdownBtn || !dropdownMenu) {
		return;
	}

	// Open dropdown
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should be open");

	// Click outside dropdown (on document body)
	const clickEvent = new win.MouseEvent('click', { bubbles: true });
	win.document.body.dispatchEvent(clickEvent);

	// Verify dropdown closes
	assert.ok(!hasClass(dropdownMenu, 'show'), "dropdown should close on outside click");
});

test("click inside dropdown keeps it open", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');

	if (!dropdownBtn || !dropdownMenu) {
		return;
	}

	// Open dropdown
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should be open");

	// Click inside dropdown menu
	const clickEvent = new win.MouseEvent('click', { bubbles: true });
	dropdownMenu.dispatchEvent(clickEvent);

	// Verify dropdown stays open (click inside doesn't close it)
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should stay open on inside click");
});

// Folder Selection Tests

test("folder selection activates pane and updates UI", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');
	const dropdownLabel = win.document.getElementById('folderDropdownLabel');
	const folderItems = win.document.querySelectorAll('.folder-dropdown-item');

	if (!dropdownBtn || !dropdownMenu || folderItems.length === 0) {
		return;
	}

	// Click first folder item
	const firstFolderItem = folderItems[0];
	const folderIndex = firstFolderItem.getAttribute('data-folder-index');
	firstFolderItem.click();

	// Verify correct pane is activated
	const paneId = 'folder-pane-' + folderIndex;
	const pane = win.document.getElementById(paneId);
	if (pane) {
		assert.ok(hasClass(pane, 'active'), "folder pane should have 'active' class");
	}

	// Verify folder item has 'selected' class
	assert.ok(hasClass(firstFolderItem, 'selected'), "selected folder item should have 'selected' class");

	// Verify dropdown button has 'active' class
	assert.ok(hasClass(dropdownBtn, 'active'), "dropdown button should have 'active' class");

	// Verify dropdown label is updated
	if (dropdownLabel) {
		const nameSpan = firstFolderItem.querySelector('.folder-item-name');
		const folderName = nameSpan ? nameSpan.textContent : '';
		const expectedLabel = folderName ? folderName + ' - Solution' : 'Solution';
		assert.equal(dropdownLabel.textContent, expectedLabel, "dropdown label should be 'FolderName - Solution'");
	}
});

test("folder selection deselects other items", async () => {
	const win = await buildDom();
	const folderItems = win.document.querySelectorAll('.folder-dropdown-item');

	if (folderItems.length < 2) {
		return;
	}

	// Click first folder item
	folderItems[0].click();

	// Verify first item is selected
	assert.ok(hasClass(folderItems[0], 'selected'), "first folder item should have 'selected' class");

	// Click second folder item
	folderItems[1].click();

	// Verify first item is no longer selected
	assert.ok(!hasClass(folderItems[0], 'selected'), "first folder item should not have 'selected' class after second item clicked");

	// Verify second item is selected
	assert.ok(hasClass(folderItems[1], 'selected'), "second folder item should have 'selected' class");
});

test("folder selection closes dropdown", async () => {
	const win = await buildDom();
	const dropdownBtn = win.document.getElementById('folder-dropdown-btn');
	const dropdownMenu = win.document.getElementById('folderDropdownMenu');
	const folderItems = win.document.querySelectorAll('.folder-dropdown-item');

	if (!dropdownBtn || !dropdownMenu || folderItems.length === 0) {
		return;
	}

	// Open dropdown
	dropdownBtn.click();
	assert.ok(hasClass(dropdownMenu, 'show'), "dropdown should be open");

	// Click folder item
	folderItems[0].click();

	// Verify dropdown closes
	assert.ok(!hasClass(dropdownMenu, 'show'), "dropdown should close after folder selection");
});

// Multi-Folder Tests

test("multiple folder switches work correctly", async () => {
	const win = await buildDom();
	const folderItems = win.document.querySelectorAll('.folder-dropdown-item');

	if (folderItems.length < 2) {
		return;
	}

	// Switch to first folder
	folderItems[0].click();
	const firstIndex = folderItems[0].getAttribute('data-folder-index');
	const firstPane = win.document.getElementById('folder-pane-' + firstIndex);
	assert.ok(firstPane && hasClass(firstPane, 'active'), "first folder pane should be active");
	assert.ok(hasClass(folderItems[0], 'selected'), "first folder item should be selected");

	// Switch to second folder
	folderItems[1].click();
	const secondIndex = folderItems[1].getAttribute('data-folder-index');
	const secondPane = win.document.getElementById('folder-pane-' + secondIndex);
	assert.ok(secondPane && hasClass(secondPane, 'active'), "second folder pane should be active");
	assert.ok(hasClass(folderItems[1], 'selected'), "second folder item should be selected");

	// Verify first folder is no longer active
	assert.ok(!hasClass(firstPane, 'active'), "first folder pane should not be active after switch");
	assert.ok(!hasClass(folderItems[0], 'selected'), "first folder item should not be selected after switch");

	// Switch back to first folder
	folderItems[0].click();
	assert.ok(hasClass(firstPane, 'active'), "first folder pane should be active again");
	assert.ok(hasClass(folderItems[0], 'selected'), "first folder item should be selected again");
	assert.ok(!hasClass(secondPane, 'active'), "second folder pane should not be active");
	assert.ok(!hasClass(folderItems[1], 'selected'), "second folder item should not be selected");
});
