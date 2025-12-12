// ABOUTME: Authentication management functions for login and logout operations
// ABOUTME: Handles authentication and logout actions via IDE integration functions

(function () {
	window.ConfigApp = window.ConfigApp || {};
	var authentication = {};

	authentication.authenticate = function () {
		// Save config before authenticating, because of possible endpoint/token type changes
		window.ConfigApp.autoSave.getAndSaveIdeConfig();
		window.__ideLogin__();
	};

	authentication.logout = function () {
		// Clear the token field
		var tokenInput = window.ConfigApp.helpers.get("token");
		if (tokenInput) {
			tokenInput.value = "";
		}

		// Disable the logout button
		var logoutBtn = window.ConfigApp.helpers.get("logout-btn");
		if (logoutBtn) {
			logoutBtn.disabled = true;
		}

		// Call IDE logout function
		window.__ideLogout__();
	};

	window.ConfigApp.authentication = authentication;
})();
