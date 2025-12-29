// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var dom = window.ConfigApp.dom || window.ConfigApp.helpers;
	var ideBridge = window.ConfigApp.ideBridge;

	var saveTimeout = null;
	var SAVE_DELAY = 500; // milliseconds delay for debouncing
	var originalEndpoint = "";

	// Get current form data, validate, and call __saveIdeConfig__
	autoSave.getAndSaveIdeConfig = function() {
		var domHelper = dom || window.ConfigApp.helpers;
		var endpointInput = domHelper ? domHelper.get("endpoint") : document.getElementById("endpoint");
		var currentEndpoint = endpointInput ? endpointInput.value : "";

		// Check validation state
		var validationInfo = window.ConfigApp.validation.getFormValidationInfo();
		if (!validationInfo.isValid) {
			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.VALIDATION_ERROR);
			}
			return;
		}

		// Collect form data using formHandler if available, otherwise use legacy formData
		var formDataCollector = window.ConfigApp.formHandler || window.ConfigApp.formData;
		if (!formDataCollector || !formDataCollector.collectData) {
			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.ERROR);
			}
			return;
		}

		var data = formDataCollector.collectData();
		var jsonString = JSON.stringify(data);

		// Try to save using IDE bridge
		var saveSuccess = false;
		if (ideBridge) {
			saveSuccess = ideBridge.saveConfig(jsonString);
		}

		// Fallback to direct window call if bridge is not available
		if (!saveSuccess) {
			if (typeof window.__saveIdeConfig__ === "function") {
				try {
					window.__saveIdeConfig__(jsonString);
					saveSuccess = true;
				} catch (e) {
					alert("Error saving configuration: " + e.message);
					if (ideBridge) {
						ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.ERROR);
					}
					return;
				}
			} else {
				if (ideBridge) {
					ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.BRIDGE_MISSING);
				}
				return;
			}
		}

		// If save was successful
		if (saveSuccess) {
			// Reset dirty state after successful save
			if (window.dirtyTracker) {
				window.dirtyTracker.reset(data);
			}

			// If endpoint changed, trigger logout
			if (originalEndpoint && currentEndpoint !== originalEndpoint) {
				if (ideBridge) {
					ideBridge.logout();
				} else if (typeof window.__ideLogout__ === "function") {
					window.__ideLogout__();
				}
			}

			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.SUCCESS);
			}
		}
	};

	// Debounced save - delays save until user stops changing inputs
	autoSave.debouncedSave = function() {
		// Check if auto-save is enabled using IDE bridge
		var isEnabled = ideBridge ? ideBridge.isAutoSaveEnabled() : window.__IS_IDE_AUTOSAVE_ENABLED__;
		if (!isEnabled) return;

		if (saveTimeout) {
			clearTimeout(saveTimeout);
		}
		saveTimeout = setTimeout(function () {
			autoSave.getAndSaveIdeConfig();
		}, SAVE_DELAY);
	};

	autoSave.setOriginalEndpoint = function(endpoint) {
		originalEndpoint = endpoint;
	};

	window.ConfigApp.autoSave = autoSave;
})();
