// ABOUTME: Centralized IDE integration bridge for all IDE communication
// ABOUTME: Provides clean interface for IDE function calls and exposes window-level functions for IDE consumption

(function() {
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
		ERROR: "error"
	};

	// Check if auto-save is enabled (default false)
	if (typeof window.__IS_IDE_AUTOSAVE_ENABLED__ === "undefined") {
		window.__IS_IDE_AUTOSAVE_ENABLED__ = false;
	}

	/**
	 * Check if auto-save is enabled in the IDE
	 * @returns {boolean} True if auto-save is enabled
	 */
	ideBridge.isAutoSaveEnabled = function() {
		return window.__IS_IDE_AUTOSAVE_ENABLED__ === true;
	};

	/**
	 * Save configuration to IDE
	 * @param {string} jsonString - Serialized configuration data
	 * @returns {boolean} True if save was successful
	 */
	ideBridge.saveConfig = function(jsonString) {
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
	ideBridge.notifySaveAttempt = function(status) {
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
	ideBridge.login = function(authMethod, endpoint, insecure) {
		executeCommand("snyk.login", [authMethod, endpoint, insecure]);
	};

	/**
	 * Trigger IDE logout
	 */
	ideBridge.logout = function() {
		executeCommand("snyk.logout", []);
	};

	/**
	 * Notify IDE of dirty state change
	 * @param {boolean} isDirty - Whether the form is dirty
	 */
	ideBridge.notifyDirtyState = function(isDirty) {
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
	window.__isFormDirty__ = function() {
		if (window.dirtyTracker && window.dirtyTracker.getDirtyState) {
			return window.dirtyTracker.getDirtyState();
		}
		return false;
	};


	/**
	 * Set authentication token (called by IDE after successful authentication)
	 * @param {string} token - Authentication token to set
	 * @param {string} [apiUrl] - Optional API URL to update the endpoint field
	 */
	window.setAuthToken = function(token, apiUrl) {
		var dom = window.ConfigApp.dom;
		var tokenInput = dom ? dom.get("token") : document.getElementById("token");

		if (apiUrl) {
			var endpointInput = dom ? dom.get("endpoint") : document.getElementById("endpoint");
			if (endpointInput) {
				endpointInput.value = apiUrl;
			}
		}

		if (tokenInput) {
			tokenInput.value = token;

			// Sync auth-sensitive fields into the dirty-tracker baseline so the auth-field-monitor
			// does not treat the just-received endpoint/token as a user-driven change requiring re-auth.
			if (window.dirtyTracker && window.dirtyTracker.syncBaselineFields && window.ConfigApp.authFieldMonitor) {
				window.dirtyTracker.syncBaselineFields(window.ConfigApp.authFieldMonitor.sensitiveFields);
			}

			// Update Authenticate/Logout button states
			var authBtn = dom ? dom.get("authenticate-btn") : document.getElementById("authenticate-btn");
			var logoutBtn = dom ? dom.get("logout-btn") : document.getElementById("logout-btn");
			if (authBtn) { authBtn.disabled = true; }
			if (logoutBtn) { logoutBtn.disabled = false; }

			// Validate first so validationState is correct before auto-save reads it.
			// If validationState["token"] is still false from a pre-auth error, auto-save
			// would fire notifySaveAttempt("validation_error"), causing the IDE to re-show the error.
			if (window.ConfigApp.validation && window.ConfigApp.validation.validateTokenOnInput) {
				window.ConfigApp.validation.validateTokenOnInput();
			}

			// Reset any stale saved-token state so triggerChangeHandlers does not
			// restore the old pre-auth token over the newly received one.
			if (window.ConfigApp.authFieldMonitor && window.ConfigApp.authFieldMonitor.resetSavedState) {
				window.ConfigApp.authFieldMonitor.resetSavedState();
			}

			// Trigger dirty state tracking and auto-save (now with correct validation state)
			if (window.ConfigApp.formState && window.ConfigApp.formState.triggerChangeHandlers) {
				window.ConfigApp.formState.triggerChangeHandlers();
			}
		}
	};

	/**
	 * Get and save IDE config (called by IDE)
	 */
	window.getAndSaveIdeConfig = function() {
		if (window.ConfigApp.autoSave && window.ConfigApp.autoSave.getAndSaveIdeConfig) {
			window.ConfigApp.autoSave.getAndSaveIdeConfig();
		}
	};

	// Export status constants for use by other modules
	ideBridge.SAVE_STATUS = SAVE_STATUS;

	window.ConfigApp.ideBridge = ideBridge;
})();
