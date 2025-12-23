// ABOUTME: Auto-save functionality with debouncing and validation
// ABOUTME: Handles automatic form saving with delay and error checking

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var autoSave = {};
	var helpers = window.ConfigApp.helpers;

	var saveTimeout = null;
	var SAVE_DELAY = 500; // milliseconds delay for debouncing
	var originalEndpoint = "";

	// Status codes for save attempt notifications
	var SAVE_STATUS = {
		SUCCESS: "success",
		ENDPOINT_INVALID: "endpoint_invalid",
		RISK_SCORE_INVALID: "risk_score_invalid",
		ADDITIONAL_ENV_INVALID: "additional_env_invalid",
		BRIDGE_MISSING: "bridge_missing",
		ERROR: "error"
	};

	// Check if auto-save is enabled (default false)
	if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === "undefined") {
		window.__IS_IDE_AUTOSAVE_ENABLED__ = false;
	}

	/**
	 * Notify IDE that a save attempt has finished
	 * @param {string} status - One of SAVE_STATUS values
	 * Status values:
	 *   - "success": Save completed successfully
	 *   - "endpoint_invalid": Endpoint validation failed
	 *   - "risk_score_invalid": Risk score validation failed
	 *   - "additional_env_invalid": Additional environment validation failed
	 *   - "bridge_missing": __saveIdeConfig__ function not available
	 *   - "error": Exception occurred during save
	 */
	function notifySaveAttemptFinished(status) {
		if (typeof window.__ideSaveAttemptFinished__ === "function") {
			try {
				window.__ideSaveAttemptFinished__(status);
			} catch (e) {
				// Silently ignore notification errors to avoid disrupting save flow
				if (window.console && console.error) {
					console.error("Error notifying IDE of save attempt:", e);
				}
			}
		}
	}

	// Get current form data, validate, and call __saveIdeConfig__
	autoSave.getAndSaveIdeConfig = function() {
		var endpointInput = helpers.get("endpoint");
		var currentEndpoint = endpointInput ? endpointInput.value : "";

		// Validate all fields
		var validationResult = window.ConfigApp.validation.validateAllBeforeSave();
		if (!validationResult.valid) {
			var statusMap = {
				"endpoint": SAVE_STATUS.ENDPOINT_INVALID,
				"risk_score": SAVE_STATUS.RISK_SCORE_INVALID,
				"additional_env": SAVE_STATUS.ADDITIONAL_ENV_INVALID
			};
			notifySaveAttemptFinished(statusMap[validationResult.failedField] || SAVE_STATUS.ERROR);
			return;
		}

		var data = window.ConfigApp.formData.collectData();
		var jsonString = JSON.stringify(data);

		// Check if IDE save bridge is available
		if (typeof window.__saveIdeConfig__ !== "function") {
			notifySaveAttemptFinished(SAVE_STATUS.BRIDGE_MISSING);
			return;
		}

		try {
			window.__saveIdeConfig__(jsonString);

			// Reset dirty state after successful save
			if (window.dirtyTracker) {
				window.dirtyTracker.reset(data);
			}

			// If endpoint changed, trigger logout
			if (originalEndpoint && currentEndpoint !== originalEndpoint) {
				if (typeof window.__ideLogout__ === "function") {
					window.__ideLogout__();
				}
			}

			notifySaveAttemptFinished(SAVE_STATUS.SUCCESS);
		} catch (e) {
			// Keep dirty state on save failure
			alert("Error saving configuration: " + e.message);
			notifySaveAttemptFinished(SAVE_STATUS.ERROR);
		}
	};

	// Debounced save - delays save until user stops changing inputs
	autoSave.debouncedSave = function() {
		if (!window.__IS_IDE_AUTOSAVE_ENABLED__) return;

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

	// Expose getAndSaveIdeConfig to window for IDEs to call
	window.getAndSaveIdeConfig = autoSave.getAndSaveIdeConfig;

	window.ConfigApp.autoSave = autoSave;
})();
