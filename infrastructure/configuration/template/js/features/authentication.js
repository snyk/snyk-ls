// ABOUTME: Authentication management functions for login and logout operations
// ABOUTME: Handles authentication and logout actions via IDE integration functions

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authentication = {};
	var dom = window.ConfigApp.dom || window.ConfigApp.helpers;
	var ideBridge = window.ConfigApp.ideBridge;

	authentication.authenticate = function () {
		// Save config before authenticating, because of possible endpoint/token type changes
		if (window.ConfigApp.autoSave && window.ConfigApp.autoSave.getAndSaveIdeConfig) {
			window.ConfigApp.autoSave.getAndSaveIdeConfig();
		}

		// Use IDE bridge if available, otherwise fall back to direct window call
		if (ideBridge) {
			ideBridge.login();
		} else if (typeof window.__ideLogin__ === "function") {
			window.__ideLogin__();
		}
	};

	authentication.logout = function () {
		// Clear the token field
		var domHelper = dom || window.ConfigApp.helpers;
		var tokenInput = domHelper ? domHelper.get("token") : document.getElementById("token");
		if (tokenInput) {
			tokenInput.value = "";
		}

		// Use IDE bridge if available, otherwise fall back to direct window call
		if (ideBridge) {
			ideBridge.logout();
		} else if (typeof window.__ideLogout__ === "function") {
			window.__ideLogout__();
		}
	};

	window.ConfigApp.authentication = authentication;
})();
