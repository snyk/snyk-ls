// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var helpers = window.ConfigApp.helpers;

	var saveTimeout = null;
	var SAVE_DELAY = 500; // milliseconds delay for debouncing
	var originalEndpoint = "";

	// Check if auto-save is enabled (default false)
	if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === "undefined") {
		window.__IS_IDE_AUTOSAVE_ENABLED__ = false;
	}

	// Get current form data, validate, and call __saveIdeConfig__
	autoSave.getAndSaveIdeConfig = function() {
		var endpointInput = helpers.get("endpoint");
		var endpointError = helpers.get("endpoint-error");
		var currentEndpoint = endpointInput.value;

		// Validate endpoint
		if (currentEndpoint && !window.ConfigApp.validation.validateEndpoint(currentEndpoint)) {
			helpers.removeClass(endpointError, "hidden");
			return;
		} else {
			helpers.addClass(endpointError, "hidden");
		}

		// Validate risk score
		var riskScoreInput = helpers.get("riskScoreThreshold");
		var riskScoreError = helpers.get("riskScore-error");
		if (riskScoreInput && riskScoreError) {
			if (!window.ConfigApp.validation.validateRiskScore(riskScoreInput.value)) {
				helpers.removeClass(riskScoreError, "hidden");
				return;
			} else {
				helpers.addClass(riskScoreError, "hidden");
			}
		}

		// Validate additional env
		var additionalEnvInput = helpers.get("additionalEnv");
		var additionalEnvError = helpers.get("additionalEnv-error");
		if (additionalEnvInput && additionalEnvError) {
			if (!window.ConfigApp.validation.validateAdditionalEnv(additionalEnvInput.value)) {
				helpers.removeClass(additionalEnvError, "hidden");
				return;
			} else {
				helpers.addClass(additionalEnvError, "hidden");
			}
		}

		var data = window.ConfigApp.formData.collectData();
		var jsonString = JSON.stringify(data);

		try {
			window.__saveIdeConfig__(jsonString);

			// Reset dirty state after successful save
			if (window.dirtyTracker) {
				window.dirtyTracker.reset(data);
			}

			// If endpoint changed, trigger logout
			if (originalEndpoint && currentEndpoint !== originalEndpoint) {
				if (typeof window.__ideLogout__ !== "undefined") {
					window.__ideLogout__();
				}
			}
		} catch (e) {
			// Keep dirty state on save failure
			alert("Error saving configuration: " + e.message);
		}
	};

	// Debounced save - delays save until user stops changing inputs
	autoSave.debouncedSave = function() {
		if (saveTimeout) {
			clearTimeout(saveTimeout);
		}
		saveTimeout = setTimeout(function () {
			autoSave.getAndSaveIdeConfig();
		}, SAVE_DELAY);
	};

	// Attach auto-save listeners to all form inputs
	autoSave.attachAutoSaveListeners = function() {
		if (!window.__IS_IDE_AUTOSAVE_ENABLED__) return; // Don't attach listeners if auto-save not enabled

		var form = helpers.get("configForm");
		if (!form) return;

		var inputs = form.getElementsByTagName("input");
		var selects = form.getElementsByTagName("select");
		var textareas = form.getElementsByTagName("textarea");

		// Add blur event listeners to all inputs
		for (var i = 0; i < inputs.length; i++) {
			helpers.addEvent(inputs[i], "blur", autoSave.debouncedSave);
			// Also save on change for checkboxes and radios
			if (inputs[i].type === "checkbox" || inputs[i].type === "radio") {
				helpers.addEvent(inputs[i], "change", autoSave.debouncedSave);
			}
		}

		for (var j = 0; j < selects.length; j++) {
			helpers.addEvent(selects[j], "change", autoSave.debouncedSave);
		}

		for (var k = 0; k < textareas.length; k++) {
			helpers.addEvent(textareas[k], "blur", autoSave.debouncedSave);
		}
	};

	autoSave.setOriginalEndpoint = function(endpoint) {
		originalEndpoint = endpoint;
	};

	// Expose getAndSaveIdeConfig to window for IDEs to call
	window.getAndSaveIdeConfig = autoSave.getAndSaveIdeConfig;

	window.ConfigApp.autoSave = autoSave;
})();
