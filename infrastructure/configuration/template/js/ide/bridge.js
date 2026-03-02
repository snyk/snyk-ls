(function() {
	window.ConfigApp = window.ConfigApp || {};
	var ideBridge = {};

	/**
	 * Route a command to the IDE via the unified executeCommand bridge.
	 * Requires the IDE to inject window.__ideExecuteCommand__(cmd, args, callback).
	 * @param {string} cmd - The command ID (e.g. 'snyk.login')
	 * @param {Array} args - Command arguments array
	 * @param {Function} [callback] - Optional callback for command result
	 */
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
	 * Trigger IDE login flow with authentication parameters.
	 * Routes through the unified executeCommand bridge.
	 * @param {string} authMethod - Authentication method ('oauth', 'pat', 'token')
	 * @param {string} endpoint - API endpoint URL
	 * @param {boolean} insecure - Whether to skip SSL verification
	 */
	ideBridge.login = function(authMethod, endpoint, insecure) {
		executeCommand("snyk.login", [authMethod, endpoint, insecure]);
	};

	/**
	 * Trigger IDE logout.
	 * Routes through the unified executeCommand bridge.
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
	 * Set authentication token (called by IDE)
	 * @param {string} token - Authentication token to set
	 */
	window.setAuthToken = function(token) {
		var dom = window.ConfigApp.dom;
		var tokenInput = dom.get("token");

		if (tokenInput) {
			tokenInput.value = token;

			// Trigger dirty state tracking
			if (window.ConfigApp.formState && window.ConfigApp.formState.triggerChangeHandlers) {
				window.ConfigApp.formState.triggerChangeHandlers();
			}

			// Trigger token validation
			if (window.ConfigApp.validation && window.ConfigApp.validation.validateTokenOnInput) {
				window.ConfigApp.validation.validateTokenOnInput();
			}
		}

		// Update auth status indicator
		var statusEl = dom.get("auth-status");
		if (statusEl) {
			if (token) {
				statusEl.textContent = "Authenticated";
				dom.removeClass(statusEl, "hidden");
			} else {
				statusEl.textContent = "";
				dom.addClass(statusEl, "hidden");
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
