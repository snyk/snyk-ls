// ABOUTME: Monitors auth-sensitive fields (api_endpoint, authentication_method) for changes
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
	var SENSITIVE_FIELDS = ["authentication_method", "api_endpoint"];

	function getAuthElements() {
		return {
			authBtn: dom.get("authenticate-btn"),
			tokenInput: dom.get("token"),
			logoutBtn: dom.get("logout-btn"),
			tokenFieldGroup: dom.get("token-field-group"),
			authMethodSelect: dom.get("authentication_method"),
			getTokenLink: dom.get("get-token-link"),
		};
	}

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

		var elements = getAuthElements();
		var tokenInput = elements.tokenInput;
		var authBtn = elements.authBtn;

		if (needsReauth) {
			if (!hasCleared && tokenInput) {
				savedToken = tokenInput.value;
				tokenInput.value = "";
				hasCleared = true;
				// Trigger input event to re-validate the now-empty token field.
				// Clears any stale error and updates validationState so saves are not blocked.
				dom.triggerEvent(tokenInput, "input");
			}
		} else {
			hasCleared = false;
			if (savedToken !== null && tokenInput) {
				tokenInput.value = savedToken;
				savedToken = null;
			}
		}

		applyAuthControlsState(elements);
	};

	function applyAuthControlsState(elements) {
		var authMethodSelect = elements.authMethodSelect;
		var tokenInput = elements.tokenInput;
		var authBtn = elements.authBtn;
		var logoutBtn = elements.logoutBtn;
		var getTokenLink = elements.getTokenLink;
		var tokenFieldGroup = elements.tokenFieldGroup;

		if (!authMethodSelect || !tokenInput) {
			return;
		}

		var isOAuth = authMethodSelect.value === "oauth";
		var hasToken = !!(tokenInput.value);

		// Token field: hidden for OAuth, visible for PAT/Legacy
		if (tokenFieldGroup) {
			if (isOAuth) {
				dom.addClass(tokenFieldGroup, "hidden");
			} else {
				dom.removeClass(tokenFieldGroup, "hidden");
			}
		}

		// Get Token link: hidden for OAuth, visible for PAT/Legacy
		if (getTokenLink) {
			if (isOAuth) {
				dom.addClass(getTokenLink, "hidden");
			} else {
				dom.removeClass(getTokenLink, "hidden");
			}
		}

		// Authenticate button: visible for OAuth, hidden for PAT/Legacy
		if (authBtn) {
			if (isOAuth) {
				dom.removeClass(authBtn, "hidden");
			} else {
				dom.addClass(authBtn, "hidden");
			}
		}

		// Log out button: hidden if no token, visible if token exists
		if (logoutBtn) {
			if (hasToken) {
				dom.removeClass(logoutBtn, "hidden");
			} else {
				dom.addClass(logoutBtn, "hidden");
			}
			logoutBtn.disabled = !hasToken;
		}

		if (authBtn) {
			authBtn.disabled = hasToken;
		}
	}

	authFieldMonitor.syncAuthControls = function () {
		applyAuthControlsState(getAuthElements());
	};

	// Called by setAuthToken to prevent restoring a stale pre-auth token
	// after successful authentication has set a new token.
	authFieldMonitor.resetSavedState = function () {
		savedToken = null;
		hasCleared = false;
	};

	// Exposed so setAuthToken can sync exactly these fields into the baseline
	authFieldMonitor.sensitiveFields = SENSITIVE_FIELDS;

	window.ConfigApp.authFieldMonitor = authFieldMonitor;
})();
