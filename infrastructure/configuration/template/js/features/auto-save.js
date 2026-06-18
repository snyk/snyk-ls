// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var dom = window.ConfigApp.dom;
	var ideBridge = window.ConfigApp.ideBridge;

	// Guard against re-entrance when triggerChangeHandlers() calls getAndSaveIdeConfig recursively
	var _isSaving = false;

	// Get current form data, validate, and call __saveIdeConfig__
	autoSave.getAndSaveIdeConfig = function() {
		if (_isSaving) return;
		_isSaving = true;

		try {
			// Run dirty-tracker change listeners (authFieldMonitor etc.) before collecting,
			// so token/endpoint/authMethod changes are reflected before collectChangedData() reads them.
			// Closing the panel without blurring would otherwise silently discard the pending change.
			// triggerChangeHandlers() runs the listeners synchronously; the auto-save re-entrance it can
			// trigger is blocked by the _isSaving guard. No DOM focus change needed.
			// SELECT values are always read live from the DOM by collectChangedData(), so no blur
			// is required to capture a pending SELECT change either.
			if (window.ConfigApp.formState && typeof window.ConfigApp.formState.triggerChangeHandlers === 'function') {
				window.ConfigApp.formState.triggerChangeHandlers();
			}

			// Check validation state
			var validationInfo = window.ConfigApp.validation.getFormValidationInfo();
			if (!validationInfo.isValid) {
				if (ideBridge) {
					ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.VALIDATION_ERROR);
				}
				return;
			}

			// Collect form data
			if (!window.ConfigApp.formHandler || !window.ConfigApp.formHandler.collectChangedData || !window.ConfigApp.formHandler.collectData) {
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
				// Propagate changed Project Default values into folder panes that were
				// inheriting from PD (i.e. not user-overridden). Must run BEFORE reset()
				// so the propagated folder values become the new baseline (not dirty).
				if (window.ConfigApp.projectDefaultPropagator && window.dirtyTracker) {
					window.ConfigApp.projectDefaultPropagator.propagate(data, window.dirtyTracker.originalData);
				}
				// Reset dirty state after successful save (baseline must be the full form state)
				if (window.dirtyTracker) {
					window.dirtyTracker.reset();
				}

				if (ideBridge) {
					ideBridge.notifySaveAttempt(ideBridge.SAVE_STATUS.SUCCESS);
				}
			}
		} finally {
			_isSaving = false;
		}
	};

	window.ConfigApp.autoSave = autoSave;
})();
