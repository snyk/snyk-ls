// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var ideBridge = window.ConfigApp.ideBridge;

	// Get current form data, validate, and call __saveIdeConfig__
	autoSave.getAndSaveIdeConfig = function() {
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

			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.SUCCESS);
			}
		}
	};

	window.ConfigApp.autoSave = autoSave;
})();
