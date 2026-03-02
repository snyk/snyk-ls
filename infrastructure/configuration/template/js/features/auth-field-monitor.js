(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authFieldMonitor = {};
	var dom = window.ConfigApp.dom;

	var AUTH_SENSITIVE_FIELDS = ["authenticationMethod", "endpoint"];

	/**
	 * Change listener registered with DirtyTracker.addChangeListener.
	 * Called on every checkDirty() and after reset() with (originalData, currentData).
	 * Enables or disables the Authenticate button based on whether auth-sensitive fields differ from saved values.
	 * @param {Object} originalData - Last-saved form data
	 * @param {Object} currentData - Current form data
	 */
	authFieldMonitor.onDataChange = function (originalData, currentData) {
		if (!originalData || !currentData) {
			return;
		}

		var needsReauth = false;
		for (var i = 0; i < AUTH_SENSITIVE_FIELDS.length; i++) {
			var field = AUTH_SENSITIVE_FIELDS[i];
			if ((originalData[field] || "") !== (currentData[field] || "")) {
				needsReauth = true;
				break;
			}
		}

		var authBtn = dom.get("authenticate-btn");
		if (!authBtn) {
			return;
		}

		if (needsReauth) {
			authBtn.disabled = false;
		} else {
			var tokenInput = dom.get("token");
			authBtn.disabled = !!(tokenInput && tokenInput.value);
		}
	};

	window.ConfigApp.authFieldMonitor = authFieldMonitor;
})();
