// ABOUTME: Authentication management functions for login and logout operations
// ABOUTME: Handles authentication and logout actions via IDE integration functions

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authentication = {};
	var dom = window.ConfigApp.dom;
	var ideBridge = window.ConfigApp.ideBridge;

	authentication.authenticate = function () {
		// Collect current form values and pass them directly to the login command.
		// The LS applies them to config before invoking the auth flow.
		var data = window.ConfigApp.formHandler ? window.ConfigApp.formHandler.collectData() : {};
		ideBridge.login(data.authenticationMethod, data.endpoint, data.insecure);
	};

	authentication.logout = function () {
		// Clear the token field
		var tokenInput = dom.get("token");
		if (tokenInput) {
			tokenInput.value = "";
		}

		if (window.ConfigApp.authFieldMonitor && window.ConfigApp.authFieldMonitor.syncAuthControls) {
			window.ConfigApp.authFieldMonitor.syncAuthControls();
		}

		ideBridge.logout();
	};

	window.ConfigApp.authentication = authentication;
})();
