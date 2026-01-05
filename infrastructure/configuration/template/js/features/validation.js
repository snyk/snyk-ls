// ABOUTME: Form validation functions for endpoint and risk score fields
// ABOUTME: Provides validation logic used throughout the configuration dialog

(function() {
	window.ConfigApp = window.ConfigApp || {};
	var validation = {};

	// Global validation state - tracks validation status by fieldId
	var validationState = {};

	// Validate Endpoint
	validation.validateEndpoint = function(url) {
		if (!url) return true; // Empty URL allows default
		// Regex for api.*.snyk.io or api.*.snykgov.io
		var snykRegex = /^https:\/\/api\..*\.snyk\.io/;
		var snykgovRegex = /^https:\/\/api\..*\.snykgov\.io/;

		return (
			snykRegex.test(url) ||
			snykgovRegex.test(url) ||
			url === "https://api.snyk.io"
		);
	};

	// Validate risk score
	validation.validateRiskScore = function(value) {
		if (value === "" || value === null || value === undefined) {
			return true; // Empty is valid (will use default)
		}

		var num = parseInt(value);
		return !isNaN(num) && num >= 0 && num <= 1000;
	};

	// Validate UUID format (for Legacy API Token)
	validation.isUUID = function(str) {
		var uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
		return uuidRegex.test(str);
	};

	// Validate Personal Access Token format
	validation.isPAT = function(token) {
		var patRegex = /^snyk_(?:uat|sat)\.[a-z0-9]{8}\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$/;
		return patRegex.test(token);
	};

	// Validate OAuth2 token format
	validation.isOAuth2Token = function(token) {
		try {
			var oauthToken = JSON.parse(token);
			return (
				oauthToken.access_token &&
				oauthToken.access_token.length > 0 &&
				oauthToken.expiry &&
				Date.parse(oauthToken.expiry) > Date.now() &&
				oauthToken.refresh_token &&
				oauthToken.refresh_token.length > 0
			);
		} catch (e) {
			return false;
		}
	};

	// Validate token based on selected authentication method
	// Returns: { valid: boolean, errorMessage: string|null }
	validation.validateToken = function(token, authMethod) {
		if (!token || token.trim() === "") {
			return { valid: true, errorMessage: null }; // Empty token is valid
		}

		// If no auth method specified, try to get it from the form
		if (!authMethod) {
			var dom = window.ConfigApp.dom;
			var authMethodSelect = dom.get("authenticationMethod");
			authMethod = authMethodSelect ? authMethodSelect.value : "oauth";
		}

		var isValid = false;
		var errorMessage = null;

		switch (authMethod) {
			case "oauth":
				isValid = validation.isOAuth2Token(token);
				if (!isValid) {
					errorMessage = "Invalid OAuth2 token format. Expected JSON with access_token, expiry (future date), and refresh_token.";
				}
				break;
			case "pat":
				isValid = validation.isPAT(token);
				if (!isValid) {
					errorMessage = "Invalid Personal Access Token format. Expected format: snyk_uat.xxxxxxxx.xxxx.xxxx or snyk_sat.xxxxxxxx.xxxx.xxxx";
				}
				break;
			case "token":
				isValid = validation.isUUID(token);
				if (!isValid) {
					errorMessage = "Invalid API Token format. Expected UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
				}
				break;
			default:
				// If auth method is unknown, accept any of the three formats
				isValid = validation.isUUID(token) || validation.isPAT(token) || validation.isOAuth2Token(token);
				if (!isValid) {
					errorMessage = "Invalid token format. Please check your authentication method and token.";
				}
		}

		return { valid: isValid, errorMessage: errorMessage };
	};

	// Validate token on input
	validation.validateTokenOnInput = function() {
		validation.validateAndShowError("token", "token-error", validation.validateToken);
	};

	// Validate endpoint on input
	validation.validateEndpointOnInput = function() {
		validation.validateAndShowError("endpoint", "endpoint-error", validation.validateEndpoint);
	};

	// Validate risk score on input
	validation.validateRiskScoreOnInput = function() {
		validation.validateAndShowError("riskScoreThreshold", "riskScore-error", validation.validateRiskScore);
	};

	// Validate additional environment variables format
	validation.validateAdditionalEnv = function(value) {
		if (!value || value.trim() === "") {
			return true; // Empty is valid
		}

		// Pattern: KEY=VALUE where KEY is valid env var name [A-Za-z_][A-Za-z0-9_]*
		// VALUE cannot contain ; or = characters (exactly one = per segment)
		var envVarPattern = /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;=]*\s*$/;

		return value.split(";")
			.filter(function(segment) { return segment.trim() !== ""; })
			.every(function(segment) { return envVarPattern.test(segment); });
	};

	// Helper function to validate a field and show/hide error message
	// validatorFn should return either:
	//   - boolean (true = valid, false = invalid)
	//   - {valid: boolean, errorMessage: string}
	// Returns true if valid, false if invalid
	// Updates the global validation state using fieldId as the key
	validation.validateAndShowError = function(fieldId, errorId, validatorFn) {
		var dom = window.ConfigApp.dom;
		var input = dom.get(fieldId);
		var error = dom.get(errorId);

		if (!input || !error) return true;

		var value = input.value;
		var result = validatorFn(value);
		var isValid = false;

		// Handle object result {valid, errorMessage}
		if (result && typeof result === 'object' && 'valid' in result) {
			isValid = result.valid;
			if (!isValid) {
				if (result.errorMessage) {
					error.textContent = result.errorMessage;
				}
				dom.removeClass(error, "hidden");
			} else {
				dom.addClass(error, "hidden");
			}
		} else {
			// Handle boolean result
			isValid = !!result;
			if (!isValid) {
				dom.removeClass(error, "hidden");
			} else {
				dom.addClass(error, "hidden");
			}
		}

		// Update validation state using fieldId as key
		validationState[fieldId] = isValid;

		return isValid;
	};

	// Validate per-folder additional env on input
	validation.validateFolderAdditionalEnvOnInput = function(folderIndex) {
		var fieldId = "folder_" + folderIndex + "_additionalEnv";
		var errorId = "folder_" + folderIndex + "_additionalEnv-error";
		validation.validateAndShowError(fieldId, errorId, validation.validateAdditionalEnv);
	};

	// Validate all folder additional env fields
	validation.validateAllFolderAdditionalEnv = function() {
		var allValid = true;

		// Find all folder additional env inputs
		var inputs = document.querySelectorAll('[id^="folder_"][id$="_additionalEnv"]');

		for (var i = 0; i < inputs.length; i++) {
			var input = inputs[i];
			var folderIndex = (input.id.match(/folder_(\d+)_additionalEnv/) || [])[1];
			var fieldId = "folder_" + folderIndex + "_additionalEnv";
			var errorId = "folder_" + folderIndex + "_additionalEnv-error";

			if (!validation.validateAndShowError(fieldId, errorId, validation.validateAdditionalEnv)) {
				allValid = false;
			}
		}

		return allValid;
	};

	// Get current form validation info by querying the validation state
	// Returns: { isValid: boolean, validationState: object }
	validation.getFormValidationInfo = function() {
		var allValid = true;

		// Check all fields in validation state
		for (var fieldId in validationState) {
			if (validationState.hasOwnProperty(fieldId) && validationState[fieldId] === false) {
				allValid = false;
				break;
			}
		}

		return {
			isValid: allValid,
			validationState: validationState
		};
	};

	// Initialize validation event listeners for all per-folder additional env fields
	validation.initializeFolderAdditionalEnvValidation = function() {
		var dom = window.ConfigApp.dom;
		var folderAdditionalEnvInputs = document.querySelectorAll('[id^="folder_"][id$="_additionalEnv"]');

		for (var i = 0; i < folderAdditionalEnvInputs.length; i++) {
			(function(input) {
                var folderIndex = (input.id.match(/folder_(\d+)_additionalEnv/) || [])[1];
				dom.addEvent(input, "input", function() {
					validation.validateFolderAdditionalEnvOnInput(folderIndex);
				});
			})(folderAdditionalEnvInputs[i]);
		}
	};

	// Initialize all validation event listeners
	validation.initializeAllValidation = function() {
		var dom = window.ConfigApp.dom;

		// Token validation
		var tokenInput = dom.get("token");
		if (tokenInput) {
			dom.addEvent(tokenInput, "input", validation.validateTokenOnInput);
		}

		// Re-validate token when authentication method changes
		var authMethodSelect = dom.get("authenticationMethod");
		if (authMethodSelect) {
			dom.addEvent(authMethodSelect, "change", validation.validateTokenOnInput);
		}

		// Endpoint validation
		var endpointInput = dom.get("endpoint");
		if (endpointInput) {
			dom.addEvent(endpointInput, "input", validation.validateEndpointOnInput);
		}

		// Risk score validation
		var riskScoreInput = dom.get("riskScoreThreshold");
		if (riskScoreInput) {
			dom.addEvent(riskScoreInput, "input", validation.validateRiskScoreOnInput);
		}

		// Per-folder additional env validation
		validation.initializeFolderAdditionalEnvValidation();
	};

	window.ConfigApp.validation = validation;
})();
