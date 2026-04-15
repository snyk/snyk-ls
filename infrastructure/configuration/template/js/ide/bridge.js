// ABOUTME: Centralized IDE integration bridge for all IDE communication
// ABOUTME: Provides clean interface for IDE function calls and exposes window-level functions for IDE consumption

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var ideBridge = {};

	function executeCommand(cmd, args, callback) {
		if (typeof window.__ideExecuteCommand__ === "function") {
			window.__ideExecuteCommand__(cmd, args, callback);
		}
	}

	// Status codes for save attempt notifications
	var SAVE_STATUS = {
		SUCCESS: "success",
		VALIDATION_ERROR: "validation_error",
		BRIDGE_MISSING: "bridge_missing",
		ERROR: "error",
	};

	// Check if auto-save is enabled (default false)
	if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === "undefined") {
		window.__IS_IDE_AUTOSAVE_ENABLED__ = false;
	}

	/**
	 * Check if auto-save is enabled in the IDE
	 * @returns {boolean} True if auto-save is enabled
	 */
	ideBridge.isAutoSaveEnabled = function () {
		return window.__IS_IDE_AUTOSAVE_ENABLED__ === true;
	};

	/**
	 * Save configuration to IDE
	 * @param {string} jsonString - Serialized configuration data
	 * @returns {boolean} True if save was successful
	 */
	ideBridge.saveConfig = function (jsonString) {
		if (typeof window.__saveIdeConfig__ !== "function") {
			return false;
		}
		try {
			window.__saveIdeConfig__(jsonString);
			return true;
		} catch (e) {
			if (window.console && console.error) {
				console.error("Error saving config to IDE:", e);
			}
			return false;
		}
	};

	/**
	 * Notify IDE that a save attempt has finished
	 * @param {string} status - One of SAVE_STATUS values (success, validation_error, bridge_missing, error)
	 */
	ideBridge.notifySaveAttempt = function (status) {
		if (typeof window.__ideSaveAttemptFinished__ === "function") {
			try {
				window.__ideSaveAttemptFinished__(status);
			} catch (e) {
				if (window.console && console.error) {
					console.error("Error notifying IDE of save attempt:", e);
				}
			}
		}
	};

	/**
	 * Trigger IDE login flow with optional auth parameters
	 * @param {string} authMethod - Authentication method (e.g. "oauth", "token", "pat")
	 * @param {string} endpoint - API endpoint URL
	 * @param {boolean} insecure - Whether to allow insecure connections
	 */
	ideBridge.login = function (authMethod, endpoint, insecure) {
		executeCommand("snyk.login", [authMethod, endpoint, insecure]);
	};

	/**
	 * Trigger IDE logout
	 */
	ideBridge.logout = function () {
		executeCommand("snyk.logout", []);
	};

	/**
	 * Notify IDE of dirty state change
	 * @param {boolean} isDirty - Whether the form is dirty
	 */
	ideBridge.notifyDirtyState = function (isDirty) {
		if (typeof window.__onFormDirtyChange__ === "function") {
			try {
				window.__onFormDirtyChange__(isDirty);
			} catch (e) {
				if (window.console && console.error) {
					console.error("Error notifying IDE of dirty state:", e);
				}
			}
		}
	};

	// Expose window-level functions for IDE to call

	/**
	 * Get current dirty state of form (called by IDE)
	 * @returns {boolean} True if form is dirty
	 */
	window.__isFormDirty__ = function () {
		return window.dirtyTracker.getDirtyState();
	};

	/**
	 * Set authentication token (called by IDE after successful authentication)
	 * @param {string} token - Authentication token to set
	 * @param {string} [apiUrl] - Optional API URL to update the endpoint field
	 */
	window.setAuthToken = function (token, apiUrl) {
		var dom = window.ConfigApp.dom;

		if (apiUrl) {
			dom.get("api_endpoint").value = apiUrl;
		}

		dom.get("token").value = token;
		// Trigger input event to re-validate the token field with its new value.
		dom.triggerEvent(dom.get("token"), "input");

		// Sync auth-sensitive fields and token into the dirty-tracker baseline.
		// Both the LS and IDEs persist these immediately on successful auth, so they
		// must not be treated as unsaved user changes.
		window.dirtyTracker.syncBaselineFields(window.ConfigApp.authFieldMonitor.sensitiveFields.concat(["token"]));

		if (window.ConfigApp.authFieldMonitor && window.ConfigApp.authFieldMonitor.syncAuthControls) {
			window.ConfigApp.authFieldMonitor.syncAuthControls();
		}

		// Reset any stale saved-token state so triggerChangeHandlers does not
		// restore the old pre-auth token over the newly received one.
		window.ConfigApp.authFieldMonitor.resetSavedState();

		// Trigger dirty state tracking and auto-save (now with correct validation state)
		window.ConfigApp.formState.triggerChangeHandlers();
	};

	/**
	 * Get and save IDE config (called by IDE)
	 */
	window.getAndSaveIdeConfig = function () {
		window.ConfigApp.autoSave.getAndSaveIdeConfig();
	};

	// Export status constants for use by other modules
	ideBridge.SAVE_STATUS = SAVE_STATUS;

	window.ConfigApp.ideBridge = ideBridge;
})();
