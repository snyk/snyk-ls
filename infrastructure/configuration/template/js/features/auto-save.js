// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var dom = window.ConfigApp.dom;
	var ideBridge = window.ConfigApp.ideBridge;

	var originalEndpoint = "";

	// Get current form data, validate, and call __saveIdeConfig__
	autoSave.getAndSaveIdeConfig = function() {
		var endpointInput = dom.get("endpoint");
		var currentEndpoint = endpointInput ? endpointInput.value : "";

		// Check validation state
		var validationInfo = window.ConfigApp.validation.getFormValidationInfo();
		if (!validationInfo.isValid) {
			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.VALIDATION_ERROR);
			}
			return;
		}

		// Collect form data
		if (!window.ConfigApp.formHandler || !window.ConfigApp.formHandler.collectData) {
			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.ERROR);
			}
			return;
		}

		var data = window.ConfigApp.formHandler.collectData();
		var jsonString = JSON.stringify(data);

		// Save using IDE bridge
		var saveSuccess = ideBridge.saveConfig(jsonString);

		// If save was successful
		if (saveSuccess) {
			// Reset dirty state after successful save
			if (window.dirtyTracker) {
				window.dirtyTracker.reset(data);
			}

			// If endpoint changed, trigger logout
			if (originalEndpoint && currentEndpoint !== originalEndpoint) {
				ideBridge.logout();
			}

			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.SUCCESS);
			}
		}
	};

	autoSave.setOriginalEndpoint = function(endpoint) {
		originalEndpoint = endpoint;
	};

	window.ConfigApp.autoSave = autoSave;
})();
