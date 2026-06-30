// ABOUTME: Applies inbound per-folder filter values (severity + issue view) to the
// open settings form when they change elsewhere (e.g. the tree-view toolbar),
// without firing change events (so it can't trigger autosave / a feedback loop)
// and rebaselining only those fields in the dirty-tracker (so unrelated
// in-progress edits are preserved). Exposed as window.applyFilterSettings and
// invoked by the IDE host's message bridge on a $/snyk.configuration update.
(function (window) {
	"use strict";

	// Checkbox filter fields that live per folder and can change from outside the
	// settings window (the tree-view toolbar). Keyed by the setting name used both
	// in the form control name (folder_<index>_<field>) and the inbound settings map.
	var FILTER_FIELDS = [
		"severity_filter_critical",
		"severity_filter_high",
		"severity_filter_medium",
		"severity_filter_low",
		"issue_view_open_issues",
		"issue_view_ignored_issues",
	];

	// Numeric per-folder filter fields, rendered as <input type="number"> rather than
	// checkboxes (so they're applied via .value, not .checked). Risk score is the
	// only one; it changes from the tree-view filter popover.
	var NUMBER_FIELDS = ["risk_score_threshold"];

	// Maps each folder path to its form index via the hidden folder_<index>_folderPath inputs.
	function buildPathToIndex(doc) {
		var map = {};
		var inputs = doc.querySelectorAll('input[type="hidden"][name$="_folderPath"]');
		for (var i = 0; i < inputs.length; i++) {
			var match = /^folder_(\d+)_folderPath$/.exec(inputs[i].name);
			if (match) {
				map[inputs[i].value] = match[1];
			}
		}
		return map;
	}

	// Reads a boolean from an inbound ConfigSetting ({ value, changed }); returns
	// undefined when absent or not a boolean (so we only touch provided fields).
	function settingBool(settings, field) {
		var setting = settings && settings[field];
		if (!setting || typeof setting.value !== "boolean") {
			return undefined;
		}
		return setting.value;
	}

	// Reads a number from an inbound ConfigSetting; returns undefined when absent or
	// not a number (so we only touch provided fields). Risk score is always sent by
	// the LS (including its 0 default), so an inbound payload reliably carries it.
	function settingNumber(settings, field) {
		var setting = settings && settings[field];
		if (!setting || typeof setting.value !== "number") {
			return undefined;
		}
		return setting.value;
	}

	function rebaselineField(index, field, value) {
		var tracker = window.dirtyTracker;
		if (!tracker || !tracker.originalData || !tracker.originalData.folderConfigs) {
			return;
		}
		var baseline = tracker.originalData.folderConfigs[index];
		if (baseline) {
			baseline[field] = value;
		}
	}

	// applyFilterSettings updates the per-folder filter checkboxes from an inbound
	// $/snyk.configuration payload. folderConfigs is the LspConfigurationParam
	// FolderConfigs array: [{ folderPath, settings: { <name>: { value } } }].
	window.applyFilterSettings = function (folderConfigs) {
		if (!folderConfigs || !folderConfigs.length) {
			return;
		}
		var doc = window.document;
		var pathToIndex = buildPathToIndex(doc);
		var touched = false;

		for (var f = 0; f < folderConfigs.length; f++) {
			var fc = folderConfigs[f];
			if (!fc || !fc.folderPath) {
				continue;
			}
			var index = pathToIndex[fc.folderPath];
			if (index === undefined) {
				continue;
			}
			for (var k = 0; k < FILTER_FIELDS.length; k++) {
				var field = FILTER_FIELDS[k];
				var value = settingBool(fc.settings, field);
				if (value === undefined) {
					continue;
				}
				var el = doc.querySelector('input[name="folder_' + index + "_" + field + '"]');
				if (!el || el.checked === value) {
					// Still rebaseline if the control matches, so a prior divergent
					// baseline doesn't leave the field falsely dirty.
					if (el) rebaselineField(index, field, value);
					continue;
				}
				// Set without dispatching a change event: no autosave, no echo, no loop.
				el.checked = value;
				rebaselineField(index, field, value);
				touched = true;
			}

			for (var n = 0; n < NUMBER_FIELDS.length; n++) {
				var numField = NUMBER_FIELDS[n];
				var numValue = settingNumber(fc.settings, numField);
				if (numValue === undefined) {
					continue;
				}
				var numEl = doc.querySelector('input[name="folder_' + index + "_" + numField + '"]');
				if (!numEl) {
					continue;
				}
				// Compare as strings since input.value is a string; rebaseline either
				// way so a matching control isn't left falsely dirty.
				if (String(numEl.value) === String(numValue)) {
					rebaselineField(index, numField, numValue);
					continue;
				}
				// Set without dispatching a change event: no autosave, no echo, no loop.
				numEl.value = String(numValue);
				rebaselineField(index, numField, numValue);
				touched = true;
			}
		}

		// Re-evaluate dirty state so the save/dirty UI reflects that these fields
		// are now in sync with the baseline (unrelated edits stay dirty).
		if (touched && window.dirtyTracker && typeof window.dirtyTracker.checkDirty === "function") {
			window.dirtyTracker.checkDirty();
		}
	};
})(window);
