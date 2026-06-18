// ABOUTME: Project Default Propagation — after a successful save, walks all
// ABOUTME: folder panes and overwrites inputs that were inheriting from
// ABOUTME: Project Defaults (PD) with the new PD value.
//
// Exposed as: window.ConfigApp.projectDefaultPropagator.propagate(changedData, originalPdValues)
//
// Algorithm:
//   For each key in changedData (skipping folderConfigs / trusted_folders):
//     1. Find the PD input in #fallbacks-pane by name=<key>.
//        If absent, skip — not a PD-scope field.
//     2. Read the post-save PD value from the DOM (authoritative after save).
//     3. For each folder input matched via data-setting=<key>:
//        a. Skip if wrapper carries source-org or source-org-locked.
//        b. Skip if folder's current value != old PD value (user override).
//        c. Otherwise write the new PD value and dispatch a change event.

(function () {
	'use strict';

	window.ConfigApp = window.ConfigApp || {};

	// ---------------------------------------------------------------------------
	// Module-private helpers
	// ---------------------------------------------------------------------------

	/**
	 * Read the effective value from a form element.
	 * Returns a boolean for checkboxes, a string for everything else.
	 * @param {HTMLInputElement|HTMLSelectElement} el
	 * @returns {boolean|string}
	 */
	function readValue(el) {
		if (el.type === 'checkbox') {
			return el.checked;
		}
		return el.value;
	}

	/**
	 * Write a value to a form element.
	 * @param {HTMLInputElement|HTMLSelectElement} el
	 * @param {boolean|string} value
	 */
	function writeValue(el, value) {
		if (el.type === 'checkbox') {
			el.checked = !!value;
		} else {
			el.value = String(value);
		}
	}

	/**
	 * Compare two values for equality, normalising types consistently.
	 * Checkboxes produce booleans; text/number/select produce strings.
	 * We compare with String() on both sides when neither is a pure boolean.
	 * @param {boolean|string} a
	 * @param {boolean|string} b
	 * @returns {boolean}
	 */
	function valuesEqual(a, b) {
		if (typeof a === 'boolean' || typeof b === 'boolean') {
			return !!a === !!b;
		}
		return String(a) === String(b);
	}

	// ---------------------------------------------------------------------------
	// Public API
	// ---------------------------------------------------------------------------

	var projectDefaultPropagator = {};

	/**
	 * Propagate changed Project Default values into folder panes.
	 *
	 * Called inside the saveSuccess branch of auto-save.js, BEFORE
	 * dirtyTracker.reset(), so that propagated folder values become the
	 * new baseline (not dirty).
	 *
	 * @param {Object} changedData      - The collectChangedData() result (post-save).
	 * @param {Object} originalPdValues - dirtyTracker.originalData (pre-save baseline).
	 */
	projectDefaultPropagator.propagate = function (changedData, originalPdValues) {
		if (!changedData || !originalPdValues) {
			return;
		}

		var keys = Object.keys(changedData);

		for (var i = 0; i < keys.length; i++) {
			var key = keys[i];

			// Skip structural keys that are not PD settings (UNIT-006b)
			if (key === 'folderConfigs' || key === 'trusted_folders') {
				continue;
			}

			// Look up the PD input by name inside #fallbacks-pane
			var pdInput = document.querySelector('#fallbacks-pane [name="' + key + '"]');
			if (!pdInput) {
				// Not a PD-scope field — skip silently (UNIT-006)
				continue;
			}

			// Post-save DOM value is authoritative
			var newValue = readValue(pdInput);

			// Pre-save baseline value for this key
			var oldValue = originalPdValues[key];

			// Find all folder inputs for this setting via data-setting attribute (UNIT-002)
			var folderInputs = document.querySelectorAll('.folder-pane [data-setting="' + key + '"]');

			for (var j = 0; j < folderInputs.length; j++) {
				var folderInput = folderInputs[j];

				// Skip org-managed inputs (UNIT-005)
				var wrapper = folderInput.closest('.override-indicator-wrapper');
				if (wrapper) {
					if (wrapper.classList.contains('source-org') ||
						wrapper.classList.contains('source-org-locked')) {
						continue;
					}
				}

				// Skip user-overridden inputs: their current value differs from old PD (UNIT-004)
				var currentFolderValue = readValue(folderInput);
				if (!valuesEqual(currentFolderValue, oldValue)) {
					continue;
				}

				// Write the new PD value
				writeValue(folderInput, newValue);

				// Notify other listeners that this input changed
				var event = new Event('change', { bubbles: true });
				folderInput.dispatchEvent(event);
			}
		}
	};

	window.ConfigApp.projectDefaultPropagator = projectDefaultPropagator;
})();
