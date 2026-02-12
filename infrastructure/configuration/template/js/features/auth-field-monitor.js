// ABOUTME: Monitors authentication-related fields for changes that require re-authentication
// ABOUTME: Extensible infrastructure using dirty tracker data to detect auth field changes

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var authFieldMonitor = {};

	// Extensible configuration: fields that require logout when changed
	var AUTH_SENSITIVE_FIELDS = ["endpoint", "authenticationMethod"];

	/**
	 * Check if any auth-sensitive fields changed by comparing dirty tracker data
	 * @param {Object} originalData - Original form data from dirty tracker
	 * @param {Object} currentData - Current form data
	 * @returns {Object} Object with changed flag and array of changed field names
	 */
	authFieldMonitor.checkForAuthChanges = function(originalData, currentData) {
		if (!originalData || !currentData) {
			return { changed: false, changedFields: [] };
		}

		var changedFields = [];

		for (var i = 0; i < AUTH_SENSITIVE_FIELDS.length; i++) {
			var fieldName = AUTH_SENSITIVE_FIELDS[i];
			var originalValue = originalData[fieldName];
			var currentValue = currentData[fieldName];

			// Normalize for comparison (handle undefined, null, empty string)
			var normOriginal = originalValue || "";
			var normCurrent = currentValue || "";

			if (normOriginal !== normCurrent) {
				changedFields.push(fieldName);
			}
		}

		return {
			changed: changedFields.length > 0,
			changedFields: changedFields
		};
	};

	/**
	 * Change listener callback for dirty tracker
	 * Checks for auth field changes and triggers logout if needed
	 * @param {Object} originalData - Original form data
	 * @param {Object} currentData - Current form data
	 */
	authFieldMonitor.onDataChange = function(originalData, currentData) {
		var changeInfo = authFieldMonitor.checkForAuthChanges(originalData, currentData);

		if (changeInfo.changed) {
			// Trigger logout when auth-sensitive fields change
			if (window.ConfigApp.authentication && window.ConfigApp.authentication.logout) {
				window.ConfigApp.authentication.logout();
			}
		}
	};

	window.ConfigApp.authFieldMonitor = authFieldMonitor;
})();
