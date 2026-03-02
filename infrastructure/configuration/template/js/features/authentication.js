(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authentication = {};
	var dom = window.ConfigApp.dom;
	var ideBridge = window.ConfigApp.ideBridge;

	authentication.authenticate = function () {
		var data = window.ConfigApp.formHandler.collectData();
		ideBridge.login(data.authenticationMethod, data.endpoint, data.insecure);
	};

	authentication.logout = function () {
		// Clear the token field
		var tokenInput = dom.get("token");
		if (tokenInput) {
			tokenInput.value = "";
		}

		// Hide auth status indicator
		var statusEl = dom.get("auth-status");
		if (statusEl) {
			statusEl.innerHTML = "";
			dom.addClass(statusEl, "hidden");
		}

		ideBridge.logout();
	};

	window.ConfigApp.authentication = authentication;
})();
