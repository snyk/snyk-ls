(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authFieldMonitor = {};
	var dom = window.ConfigApp.dom;

	var AUTH_SENSITIVE_FIELDS = ["authenticationMethod", "endpoint"];

	/**
	 * Change listener registered with DirtyTracker.addChangeListener.
	 * Called on every checkDirty() and after reset() with (originalData, currentData).
	 * Shows or hides the re-authentication advisory indicator.
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

		var indicator = dom.get("auth-reauth-advisory");
		if (!indicator) {
			return;
		}

		if (needsReauth) {
			dom.removeClass(indicator, "hidden");
		} else {
			dom.addClass(indicator, "hidden");
		}
	};

	window.ConfigApp.authFieldMonitor = authFieldMonitor;
})();
