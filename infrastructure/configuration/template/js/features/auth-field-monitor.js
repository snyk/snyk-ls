// ABOUTME: Monitors auth-sensitive fields (endpoint, authenticationMethod) for changes
// ABOUTME: Clears token and enables Authenticate button when these fields change from saved values

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authFieldMonitor = {};
	var dom = window.ConfigApp.dom;

	// Tracks whether the token has already been cleared for the current set of changes.
	// Prevents repeated dirty-check notifications from wiping a token the user has manually entered.
	var hasCleared = false;

	// Holds the token value saved when a sensitive field change clears it.
	// Restored if the user reverts those fields back to their baseline values.
	var savedToken = null;

	// Fields that require re-authentication when changed
	var SENSITIVE_FIELDS = ["authenticationMethod", "endpoint"];

	/**
	 * Called by the dirty tracker on every checkDirty/reset cycle.
	 * When auth-sensitive fields differ from the baseline, clears the token
	 * and updates button states to require re-authentication.
	 * @param {Object} originalData - Baseline (saved) form data
	 * @param {Object} currentData - Current form data
	 */
	authFieldMonitor.onDataChange = function (originalData, currentData) {
		if (!originalData || !currentData) {
			return;
		}

		var needsReauth = false;
		for (var i = 0; i < SENSITIVE_FIELDS.length; i++) {
			var field = SENSITIVE_FIELDS[i];
			var original = originalData[field] || "";
			var current = currentData[field] || "";
			if (original !== current) {
				needsReauth = true;
				break;
			}
		}

		var authBtn = dom ? dom.get("authenticate-btn") : document.getElementById("authenticate-btn");
		if (!authBtn) {
			return;
		}

		var tokenInput = dom ? dom.get("token") : document.getElementById("token");
		var logoutBtn = dom ? dom.get("logout-btn") : document.getElementById("logout-btn");

		if (needsReauth) {
			if (!hasCleared && tokenInput) {
				savedToken = tokenInput.value;
				tokenInput.value = "";
				hasCleared = true;
				// Hide any token validation error: empty token is always valid.
				// Also updates validationState so saves are not blocked.
				if (window.ConfigApp.validation && window.ConfigApp.validation.validateTokenOnInput) {
					window.ConfigApp.validation.validateTokenOnInput();
				}
			}
			if (logoutBtn) {
				logoutBtn.disabled = true;
			}
			authBtn.disabled = false;
		} else {
			hasCleared = false;
			if (savedToken !== null && tokenInput) {
				tokenInput.value = savedToken;
				savedToken = null;
			}
			var hasToken = !!(tokenInput && tokenInput.value);
			authBtn.disabled = hasToken;
			if (logoutBtn) {
				logoutBtn.disabled = !hasToken;
			}
		}
	};

	// Called by setAuthToken to prevent restoring a stale pre-auth token
	// after successful authentication has set a new token.
	authFieldMonitor.resetSavedState = function() {
		savedToken = null;
		hasCleared = false;
	};

	// Exposed so setAuthToken can sync exactly these fields into the baseline
	authFieldMonitor.sensitiveFields = SENSITIVE_FIELDS;

	window.ConfigApp.authFieldMonitor = authFieldMonitor;
})();
