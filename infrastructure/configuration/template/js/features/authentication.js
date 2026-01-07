// ABOUTME: Authentication management functions for login and logout operations
// ABOUTME: Handles authentication and logout actions via IDE integration functions

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authentication = {};
	var dom = window.ConfigApp.dom;
	var ideBridge = window.ConfigApp.ideBridge;

	authentication.authenticate = function () {
		// Save config before authenticating, because of possible endpoint/token type changes
		if (window.ConfigApp.autoSave && window.ConfigApp.autoSave.getAndSaveIdeConfig) {
			window.ConfigApp.autoSave.getAndSaveIdeConfig();
		}

		ideBridge.login();
	};

	authentication.logout = function () {
		// Clear the token field
		var tokenInput = dom.get("token");
		if (tokenInput) {
			tokenInput.value = "";
		}

		ideBridge.logout();
	};

	window.ConfigApp.authentication = authentication;
})();
