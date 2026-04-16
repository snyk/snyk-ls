// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var dom = window.ConfigApp.dom;
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

		var data = window.ConfigApp.formHandler.collectChangedData();

		// Apply folder resets (sets all org-scope fields to null for reset-marked folders)
		if (window.ConfigApp.formHandler.applyFolderResets) {
			window.ConfigApp.formHandler.applyFolderResets(data);
		}

		var jsonString = JSON.stringify(data);

		// Save using IDE bridge
		var saveSuccess = ideBridge.saveConfig(jsonString);

		// If save was successful
		if (saveSuccess) {
			// Discard any saved token state before resetting the dirty tracker baseline.
			// If the user changed auth-sensitive fields (e.g. auth method), the monitor
			// holds the pre-change token in savedToken so it can be restored if the user
			// reverts. But once the save goes through, that token must not be restored —
			// the save is the commit point.
			if (window.ConfigApp.authFieldMonitor && window.ConfigApp.authFieldMonitor.resetSavedState) {
				window.ConfigApp.authFieldMonitor.resetSavedState();
			}
			// Reset dirty state after successful save (baseline must be the full form state)
			if (window.dirtyTracker) {
				window.dirtyTracker.reset();
			}

			if (ideBridge) {
				ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.SUCCESS);
			}
		}
	};

	window.ConfigApp.autoSave = autoSave;
})();
