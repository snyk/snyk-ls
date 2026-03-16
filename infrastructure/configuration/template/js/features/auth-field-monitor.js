// ABOUTME: Monitors auth-sensitive fields (endpoint, authenticationMethod) for changes
// ABOUTME: Clears token and enables Authenticate button when these fields change from saved values

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authFieldMonitor = {};
	var dom = window.ConfigApp.dom;

	// Tracks whether the token has already been cleared for the current set of changes.
	// Prevents repeated blur events from wiping a token the user has manually entered.
	var hasCleared = false;

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
				tokenInput.value = "";
				hasCleared = true;
			}
			if (logoutBtn) {
				logoutBtn.disabled = true;
			}
			authBtn.disabled = false;
		} else {
			hasCleared = false;
			var hasToken = !!(tokenInput && tokenInput.value);
			authBtn.disabled = hasToken;
		}
	};

	// Exposed so setAuthToken can sync exactly these fields into the baseline
	authFieldMonitor.sensitiveFields = SENSITIVE_FIELDS;

	window.ConfigApp.authFieldMonitor = authFieldMonitor;
})();
